from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from lab_broker.domain.planner import build_overview
from lab_broker.domain.types import InputError, Snapshot
from lab_broker.fixtures import load_snapshot, write_atomic_json
from lab_broker.live_export import (
    LiveBindings,
    LiveEvidence,
    ProxmoxHTTPSReader,
    _unwrap_pve_envelope,
    build_live_snapshot,
)
from lab_broker.web import ApplicationUnavailable, SnapshotFileApplication
from tests.support import catalog, raw_snapshot


class FakePVEReader:
    def __init__(self, responses):
        self.responses = responses
        self.paths = []

    def get(self, api_path):
        self.paths.append(api_path)
        try:
            return copy.deepcopy(self.responses[api_path])
        except KeyError as exc:
            raise AssertionError(f"unexpected PVE path: {api_path}") from exc


def live_inputs(catalog_mutator=None):
    policies = catalog(catalog_mutator)
    fixture = raw_snapshot()
    source_nodes = {"node-cobalt": "hypervisor-a", "node-amber": "hypervisor-b"}
    node_bindings = [
        {
            "alias": node["id"],
            "source_node": source_nodes[node["id"]],
            "host_reserve_bytes": node["host_reserve_bytes"],
        }
        for node in fixture["nodes"]
    ]
    cohort_owners = {}
    for policy in policies.environments.values():
        for member in policy.cohort:
            cohort_owners.setdefault(member, []).append(policy.id)
    guest_bindings = []
    guest_rows = []
    for index, guest in enumerate(fixture["guests"], start=1001):
        owners = sorted(cohort_owners.get(guest["id"], [guest["owner_environment"]]))
        kind = "lxc" if guest["id"] == "archive-worker" else "qemu"
        guest_bindings.append(
            {
                "alias": guest["id"],
                "node_alias": guest["node"],
                "source_kind": kind,
                "source_id": index,
                "owner_environments": owners,
                "core_protected": guest["core_protected"],
                "gpu_affine": guest["gpu_affine"],
            }
        )
        guest_rows.append(
            {
                "type": kind,
                "vmid": index,
                "node": source_nodes[guest["node"]],
                "status": guest["state"],
                "maxmem": guest["configured_memory_bytes"],
                "mem": guest["observed_memory_bytes"],
                "template": 0,
            }
        )
    binding_value = {
        "schema_version": 1,
        "canonical_profile": "broker-cjson-v1",
        "nodes": node_bindings,
        "guests": guest_bindings,
    }
    evidence_value = {
        "schema_version": 1,
        "catalog_digest": policies.digest,
        "source_observed_at": {
            "telemetry": "2035-06-15T11:59:50Z",
            "controllers": "2035-06-15T11:59:49Z",
            "backups": "2035-06-15T11:59:48Z",
        },
        "node_swap_in_bytes_per_second": {"node-cobalt": 0, "node-amber": 0},
        "networks": copy.deepcopy(fixture["networks"]),
        "controllers": copy.deepcopy(fixture["controllers"]),
        "backups": copy.deepcopy(fixture["backups"]),
        "active_owners": {},
        "exam_lease": None,
    }
    responses = {
        "/nodes": [
            {"node": "hypervisor-a", "status": "online"},
            {"node": "hypervisor-b", "status": "online"},
        ],
        "/cluster/resources?type=vm": guest_rows,
        "/nodes/hypervisor-a/status": {
            "memory": {"total": 80 * 1024**3, "available": 31 * 1024**3},
            "rootfs": {"avail": 29 * 1024**3},
            "ksm": {"shared": 5 * 1024**3},
        },
        "/nodes/hypervisor-b/status": {
            "memory": {"total": 72 * 1024**3, "available": 27 * 1024**3},
            "rootfs": {"avail": 25 * 1024**3},
            "ksm": {"shared": 2 * 1024**3},
        },
    }
    return policies, binding_value, evidence_value, responses


def fixed_clock():
    values = iter(
        (
            datetime(2035, 6, 15, 11, 59, 56, tzinfo=UTC),
            datetime(2035, 6, 15, 11, 59, 57, tzinfo=UTC),
            datetime(2035, 6, 15, 11, 59, 58, tzinfo=UTC),
        )
    )
    return lambda: next(values)


class LiveExportContractTests(unittest.TestCase):
    def build(
        self,
        mutate_catalog=None,
        mutate_bindings=None,
        mutate_evidence=None,
        mutate_responses=None,
    ):
        policies, binding_value, evidence_value, responses = live_inputs(mutate_catalog)
        if mutate_bindings:
            mutate_bindings(binding_value)
        bindings = LiveBindings.from_dict(binding_value, policies)
        if mutate_evidence:
            mutate_evidence(evidence_value)
        evidence = LiveEvidence.from_dict(evidence_value, policies, bindings)
        if mutate_responses:
            mutate_responses(responses)
        reader = FakePVEReader(responses)
        result = build_live_snapshot(
            reader,
            bindings,
            evidence,
            policies,
            clock=fixed_clock(),
        )
        return policies, bindings, reader, result

    def test_export_is_sanitized_valid_and_preserves_the_acceptance_matrix(self):
        policies, bindings, reader, result = self.build()
        snapshot = Snapshot.from_dict(result)
        self.assertEqual(result["generated_at"], "2035-06-15T11:59:58Z")
        self.assertEqual(result["collected_at"], "2035-06-15T11:59:57Z")
        self.assertTrue(result["revision"].startswith("live-"))
        self.assertEqual(result["catalog_digest"], policies.digest)
        self.assertEqual(result["binding_digest"], bindings.binding_digest)
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("hypervisor-a", serialized)
        self.assertNotIn("hypervisor-b", serialized)
        self.assertNotIn("source_id", serialized)
        self.assertEqual(
            reader.paths,
            [
                "/nodes",
                "/cluster/resources?type=vm",
                "/nodes/hypervisor-b/status",
                "/nodes/hypervisor-a/status",
            ],
        )
        overview = build_overview(
            snapshot,
            policies,
            evaluated_at=datetime(2035, 6, 15, 12, 0, tzinfo=UTC),
            mode="live-read-only",
        )
        outcomes = {row["id"]: row["outcome"] for row in overview["environments"]}
        self.assertEqual(outcomes["cluster-blue"], "safe_now")
        self.assertEqual(outcomes["security-range"], "safe_with_donors")
        self.assertEqual(outcomes["desktop-range"], "safe_with_donors")

    def test_unbound_or_moved_guest_refuses_the_entire_export(self):
        def add_unknown(responses):
            responses["/cluster/resources?type=vm"].append(
                {
                    "type": "qemu",
                    "vmid": 9999,
                    "node": "hypervisor-a",
                    "status": "running",
                    "maxmem": 1024**3,
                    "mem": 1024,
                    "template": 0,
                }
            )

        with self.assertRaises(InputError):
            self.build(mutate_responses=add_unknown)

        def move_guest(responses):
            responses["/cluster/resources?type=vm"][0]["node"] = "hypervisor-b"

        with self.assertRaises(InputError):
            self.build(mutate_responses=move_guest)

    def test_qemu_observation_above_maxmem_is_conservatively_capped(self):
        def add_qemu_accounting_overhead(responses):
            row = next(
                item
                for item in responses["/cluster/resources?type=vm"]
                if item["type"] == "qemu" and item["status"] == "running"
            )
            row["mem"] = row["maxmem"] + 34_140_160

        _policies, bindings, _reader, result = self.build(
            mutate_responses=add_qemu_accounting_overhead
        )
        first_running_qemu = next(
            binding.alias
            for binding in bindings.guests
            if binding.source_kind == "qemu"
            and next(row for row in result["guests"] if row["id"] == binding.alias)["state"]
            == "running"
        )
        sanitized = next(row for row in result["guests"] if row["id"] == first_running_qemu)
        self.assertEqual(
            sanitized["observed_memory_bytes"],
            sanitized["configured_memory_bytes"],
        )
        Snapshot.from_dict(result)

    def test_cross_node_cohort_is_bound_and_sanitized_per_explicit_placement(self):
        policies, _bindings, _reader, result = self.build()
        guest_nodes = {row["id"]: row["node"] for row in result["guests"]}
        self.assertEqual(guest_nodes["security-target-one"], "node-cobalt")
        self.assertEqual(
            {guest_nodes[alias] for alias in {"security-target-two", "security-analyst"}},
            {"node-amber"},
        )
        plan = build_overview(
            Snapshot.from_dict(result),
            policies,
            evaluated_at=datetime(2035, 6, 15, 12, 0, tzinfo=UTC),
            mode="live-read-only",
        )
        security_range = next(row for row in plan["environments"] if row["id"] == "security-range")
        self.assertEqual(security_range["outcome"], "safe_with_donors")

    def test_shared_running_cohort_without_owner_evidence_fails_planning_closed(self):
        def run_shared(responses):
            for row in responses["/cluster/resources?type=vm"]:
                if row["vmid"] in {1022, 1023, 1024}:
                    row["status"] = "running"
                    row["mem"] = 2 * 1024**3

        policies, _bindings, _reader, result = self.build(mutate_responses=run_shared)
        overview = build_overview(
            Snapshot.from_dict(result),
            policies,
            evaluated_at=datetime(2035, 6, 15, 12, 0, tzinfo=UTC),
            mode="live-read-only",
        )
        outcomes = {row["id"]: row["outcome"] for row in overview["environments"]}
        self.assertEqual(outcomes["cluster-blue"], "unknown")
        self.assertEqual(outcomes["cluster-green"], "unknown")

    def test_binding_and_external_evidence_contracts_reject_unsafe_defaults(self):
        policies, binding_value, evidence_value, _responses = live_inputs()
        binding_value["nodes"][0]["host_reserve_bytes"] = True
        with self.assertRaises(InputError):
            LiveBindings.from_dict(binding_value, policies)

        policies, binding_value, _evidence_value, _responses = live_inputs()
        binding_value["schema_version"] = True
        with self.assertRaises(InputError):
            LiveBindings.from_dict(binding_value, policies)

        policies, binding_value, evidence_value, _responses = live_inputs()
        bindings = LiveBindings.from_dict(binding_value, policies)
        del evidence_value["controllers"]["security-range-controller"]
        with self.assertRaises(InputError):
            LiveEvidence.from_dict(evidence_value, policies, bindings)

        policies, binding_value, evidence_value, _responses = live_inputs()
        bindings = LiveBindings.from_dict(binding_value, policies)
        evidence_value["schema_version"] = True
        with self.assertRaises(InputError):
            LiveEvidence.from_dict(evidence_value, policies, bindings)

        policies, binding_value, evidence_value, _responses = live_inputs()
        bindings = LiveBindings.from_dict(binding_value, policies)
        evidence_value["catalog_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(InputError, "catalog digest"):
            LiveEvidence.from_dict(evidence_value, policies, bindings)

    def test_nullable_swap_rate_survives_sanitization(self):
        policies, _bindings, _reader, result = self.build(
            mutate_evidence=lambda value: value["node_swap_in_bytes_per_second"].__setitem__(
                "node-amber", None
            )
        )
        current = Snapshot.from_dict(result)
        self.assertIsNone(current.nodes["node-amber"].swap_in_bytes_per_second)
        overview = build_overview(
            current,
            policies,
            evaluated_at=datetime(2035, 6, 15, 12, 0, tzinfo=UTC),
        )
        affected = next(row for row in overview["environments"] if row["id"] == "cluster-blue")
        self.assertEqual(affected["outcome"], "unknown")
        self.assertIn("swap_evidence_unknown", affected["reason_codes"])

    def test_https_reader_rejects_urls_and_non_get_path_shapes_before_network(self):
        with self.assertRaises(InputError):
            ProxmoxHTTPSReader(
                "https://hypervisor-a", 8006, "token-id", "secret", insecure_tls=True
            )
        reader = ProxmoxHTTPSReader(
            "hypervisor-a",
            8006,
            "token-id",
            "secret",
            insecure_tls=True,
        )
        with self.assertRaises(InputError):
            reader.get("/nodes/../access")

    def test_task_history_accepts_only_the_exact_paginated_api_shape(self):
        path = "/nodes/hypervisor-a/tasks?limit=16&typefilter=vzdump"
        rows = [{"type": "vzdump"}, {"type": "vzdump"}]
        self.assertEqual(
            _unwrap_pve_envelope(path, {"data": rows, "total": 27}),
            rows,
        )
        for invalid in (
            {"data": rows},
            {"data": rows, "total": True},
            {"data": rows, "total": 1},
            {"data": rows, "total": 27, "extra": None},
            {"data": rows, "total": 1_000_001},
        ):
            with self.subTest(envelope=invalid), self.assertRaisesRegex(InputError, "task-history"):
                _unwrap_pve_envelope(path, invalid)
        with self.assertRaisesRegex(InputError, "response envelope"):
            _unwrap_pve_envelope("/nodes", {"data": [], "total": 0})

    def test_task_log_accepts_only_its_exact_bounded_paginated_shape(self):
        path = (
            "/nodes/hypervisor-a/tasks/"
            "UPID%3Ahypervisor-a%3A00000001%3A00000002%3A00000003%3A"
            "vzdump%3A101%3Aroot%40pam%3A/log?limit=5000"
        )
        rows = [
            {"n": 1, "t": "synthetic log row"},
            {"n": 2, "t": "synthetic log row"},
        ]
        self.assertEqual(
            _unwrap_pve_envelope(path, {"data": rows, "total": 8_000}),
            rows,
        )
        for invalid in (
            {"data": rows},
            {"data": rows, "total": True},
            {"data": rows, "total": 1},
            {"data": rows, "total": 8_000, "extra": None},
            {"data": rows, "total": 1_000_001},
        ):
            with self.subTest(envelope=invalid), self.assertRaisesRegex(InputError, "task-log"):
                _unwrap_pve_envelope(path, invalid)
        with self.assertRaisesRegex(InputError, "task-log"):
            _unwrap_pve_envelope(
                path.replace("limit=5000", "limit=5001"),
                {"data": rows, "total": len(rows)},
            )
        with self.assertRaisesRegex(InputError, "response envelope"):
            _unwrap_pve_envelope(
                "/nodes/hypervisor-a/tasks/not%2Fencoded/log?limit=5000",
                {"data": rows, "total": len(rows)},
            )


class AtomicSnapshotTests(unittest.TestCase):
    def test_atomic_writer_replaces_a_regular_file_and_loader_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            target = directory / "snapshot.json"
            value = raw_snapshot()
            write_atomic_json(target, value)
            self.assertEqual(load_snapshot(target).revision, "fictional-snapshot-1")
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
            value["revision"] = "fictional-snapshot-2"
            write_atomic_json(target, value)
            self.assertEqual(load_snapshot(target).revision, "fictional-snapshot-2")

            link = directory / "snapshot-link.json"
            link.symlink_to(target)
            with self.assertRaises(InputError):
                load_snapshot(link)
            with self.assertRaises(InputError):
                write_atomic_json(link, value)

    def test_live_file_application_recomputes_freshness_from_request_time(self):
        _policies, _bindings, _reader, result = LiveExportContractTests().build()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog_path = directory / "catalog.json"
            snapshot_path = directory / "snapshot.json"
            # The test writes only temporary synthetic inputs; production uses
            # the bounded atomic writer and a root-owned deployment directory.
            catalog_path.write_text(
                json.dumps(
                    json.loads(
                        (Path(__file__).parents[1] / "policies/examples/catalog.json").read_text()
                    )
                ),
                encoding="utf-8",
            )
            write_atomic_json(snapshot_path, result)
            current = SnapshotFileApplication(
                catalog_path,
                snapshot_path,
                clock=lambda: datetime(2035, 6, 15, 12, 0, tzinfo=UTC),
            )
            self.assertEqual(current.overview()["snapshot_status"], "current")
            self.assertEqual(current.overview()["mode"], "live-read-only")

            stale = SnapshotFileApplication(
                catalog_path,
                snapshot_path,
                clock=lambda: datetime(2035, 6, 15, 12, 5, tzinfo=UTC),
            )
            overview = stale.overview()
            self.assertEqual(overview["snapshot_status"], "unknown")
            self.assertIn("telemetry_stale", overview["snapshot_reason_codes"])

    def test_live_application_rejects_snapshot_from_a_different_catalog(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog_path = Path(__file__).parents[1] / "policies/examples/catalog.json"
            snapshot_path = directory / "snapshot.json"
            value = raw_snapshot()
            value["catalog_digest"] = "sha256:" + "0" * 64
            write_atomic_json(snapshot_path, value)
            application = SnapshotFileApplication(
                catalog_path,
                snapshot_path,
                clock=lambda: datetime(2035, 6, 15, 12, 0, tzinfo=UTC),
            )
            with self.assertRaises(ApplicationUnavailable):
                application.overview()


if __name__ == "__main__":
    unittest.main()
