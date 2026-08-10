from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch
from urllib.parse import quote

from lab_broker.domain.types import InputError
from lab_broker.evidence_probe import (
    EvidenceProbeConfig,
    SwapRateEvidence,
    SwapRateUnavailable,
    export_probe_evidence,
    probe_live_evidence,
)
from lab_broker.live_export import LiveBindings, LiveEvidence, ProxmoxHTTPSReader
from tests.support import raw_catalog
from tests.test_live_export import FakePVEReader, live_inputs

NOW = datetime(2035, 6, 15, 12, 0, tzinfo=UTC)


class FakeBrokerStatusReader:
    def __init__(self, response):
        self.response = response
        self.calls = 0

    def read(self):
        self.calls += 1
        return copy.deepcopy(self.response)


class FakeSwapRateReader:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def read(self):
        self.calls += 1
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


def broker_status(phase="idle", lab=None, *, lease_remaining=None):
    active = phase != "idle"
    ready = phase == "ready"
    response = {
        "ok": True,
        "status": {
            "phase": phase,
            "job_id": "job-aaaaaaaaaaaaaaaa" if active else None,
            "lab": lab,
            "exam": 1 if active else None,
            "requested_at": 2_065_521_500 if active else None,
            "ready_at": 2_065_521_600 if ready else None,
            "duration_seconds": 7_200 if ready else None,
            "elapsed_seconds": 100 if ready else None,
            "remaining_seconds": 7_100 if ready else None,
            "lease_remaining_seconds": lease_remaining if ready else None,
            "grade_grace_seconds": 900,
            "message": f"phase {phase}",
        },
    }
    if phase == "error":
        response["status"]["error_code"] = "operation_failed"
    return response


def probe_config_value():
    return {
        "schema_version": 1,
        "task_history_limit": 16,
        "broker_status_socket": "/run/lab-broker/example-status.sock",
        "networks": [
            {"alias": "assessment-fabric", "source_vnet": "segment-assessment"},
            {"alias": "practice-fabric", "source_vnet": "segment-practice"},
            {"alias": "range-fabric", "source_vnet": "segment-range"},
            {"alias": "platform-fabric", "source_vnet": "segment-platform"},
        ],
        "controllers": [
            {
                "alias": "workspace-controller",
                "pve_guest_aliases": ["batch-runner"],
                "require_exam_broker": False,
                "implemented": True,
            },
            {
                "alias": "automation-exam-controller",
                "pve_guest_aliases": [],
                "require_exam_broker": True,
                "implemented": True,
            },
            {
                "alias": "foundation-observer",
                "pve_guest_aliases": ["foundation-metrics"],
                "require_exam_broker": False,
                "implemented": True,
            },
            {
                "alias": "cluster-exam-controller",
                "pve_guest_aliases": [],
                "require_exam_broker": True,
                "implemented": True,
            },
            {
                "alias": "linux-exam-controller",
                "pve_guest_aliases": [],
                "require_exam_broker": True,
                "implemented": True,
            },
            {
                "alias": "security-range-controller",
                "pve_guest_aliases": ["security-gateway"],
                "require_exam_broker": False,
                "implemented": True,
            },
            {
                "alias": "desktop-range-controller",
                "pve_guest_aliases": [],
                "require_exam_broker": False,
                "implemented": False,
            },
        ],
        "backup_maximum_age_seconds": {
            "batch-orchestrator": 86_400,
            "vision-workbench": 86_400,
            "archive-indexer": 86_400,
        },
        "broker_lab_owners": {
            "cluster-blue": "cluster-blue",
            "cluster-green": "cluster-green",
            "linux-blue": "linux-blue",
            "automation-blue": "automation-blue",
        },
    }


def probe_inputs():
    policies, binding_value, _evidence, responses = live_inputs()
    bindings = LiveBindings.from_dict(binding_value, policies)
    for source_node in ("hypervisor-a", "hypervisor-b"):
        responses[f"/nodes/{source_node}/status"]["swap"] = {"total": 0}
    responses["/cluster/sdn/vnets"] = [
        {"type": "vnet", "vnet": row["source_vnet"], "pending": None}
        for row in probe_config_value()["networks"]
    ]

    completed_at = int(NOW.timestamp()) - 1_800
    upid = "UPID:hypervisor-a:backup-history"
    responses["/nodes/hypervisor-a/tasks?limit=16&typefilter=vzdump"] = [
        {
            "type": "vzdump",
            "node": "hypervisor-a",
            "endtime": completed_at,
            "upid": upid,
        }
    ]
    responses["/nodes/hypervisor-b/tasks?limit=16&typefilter=vzdump"] = []
    responses[f"/nodes/hypervisor-a/tasks/{quote(upid, safe='')}/log?limit=5000"] = [
        {"n": 1, "t": "INFO: Starting Backup of VM 1003 (qemu)"},
        {"n": 2, "t": "INFO: Finished Backup of VM 1003 (00:00:05)"},
        {"n": 3, "t": "INFO: Starting Backup of VM 1004 (lxc)"},
        {"n": 4, "t": "INFO: Finished Backup of VM 1004 (00:00:06)"},
        {"n": 5, "t": "INFO: Starting Backup of VM 1005 (qemu)"},
        {"n": 6, "t": "INFO: Finished Backup of VM 1005 (00:00:04)"},
    ]
    config = EvidenceProbeConfig.from_dict(
        probe_config_value(),
        policies,
        bindings,
    )
    return policies, binding_value, bindings, config, responses


class EvidenceProbeTests(unittest.TestCase):
    def test_probe_emits_only_semantic_strict_evidence(self):
        policies, _binding_value, bindings, config, responses = probe_inputs()
        reader = FakePVEReader(responses)
        broker = FakeBrokerStatusReader(broker_status())
        result = probe_live_evidence(
            reader,
            broker,
            bindings,
            policies,
            config,
            clock=lambda: NOW,
        )

        LiveEvidence.from_dict(result, policies, bindings)
        self.assertEqual(result["catalog_digest"], policies.digest)
        self.assertEqual(
            result["node_swap_in_bytes_per_second"], {"node-cobalt": 0, "node-amber": 0}
        )
        self.assertTrue(all(result["networks"].values()))
        self.assertTrue(result["controllers"]["workspace-controller"])
        self.assertTrue(result["controllers"]["cluster-exam-controller"])
        self.assertFalse(result["controllers"]["security-range-controller"])
        self.assertFalse(result["controllers"]["desktop-range-controller"])
        self.assertEqual(result["exam_lease"], None)
        self.assertEqual(
            {row["environment_id"]: row["state"] for row in result["backups"]},
            {
                "batch-orchestrator": "fresh",
                "vision-workbench": "fresh",
                "archive-indexer": "fresh",
            },
        )
        self.assertEqual(broker.calls, 1)
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("hypervisor-", serialized)
        self.assertNotIn("vnet-", serialized)
        self.assertNotIn("UPID", serialized)

    def test_ready_broker_status_binds_shared_owners_and_global_exam_lease(self):
        policies, _binding_value, bindings, config, responses = probe_inputs()
        result = probe_live_evidence(
            FakePVEReader(responses),
            FakeBrokerStatusReader(broker_status("ready", "cluster-blue", lease_remaining=3_600)),
            bindings,
            policies,
            config,
            clock=lambda: NOW,
        )
        self.assertEqual(
            result["exam_lease"],
            {
                "environment_id": "cluster-blue",
                "state": "active",
                "expires_at": "2035-06-15T13:00:00Z",
            },
        )
        self.assertEqual(
            result["active_owners"],
            {
                "cluster-control": "cluster-blue",
                "cluster-worker-one": "cluster-blue",
                "cluster-worker-two": "cluster-blue",
            },
        )

    def test_configured_swap_emits_unknown_without_fabricating_a_zero_rate(self):
        policies, _binding_value, bindings, config, responses = probe_inputs()
        responses["/nodes/hypervisor-b/status"]["swap"]["total"] = 8 * 1024**3
        result = probe_live_evidence(
            FakePVEReader(responses),
            FakeBrokerStatusReader(broker_status()),
            bindings,
            policies,
            config,
            clock=lambda: NOW,
        )
        self.assertEqual(
            result["node_swap_in_bytes_per_second"],
            {"node-amber": None, "node-cobalt": 0},
        )
        LiveEvidence.from_dict(result, policies, bindings)

    def test_fresh_injected_swap_rates_survive_and_use_the_oldest_observation(self):
        policies, _binding_value, bindings, config, responses = probe_inputs()
        for source_node in ("hypervisor-a", "hypervisor-b"):
            responses[f"/nodes/{source_node}/status"]["swap"]["total"] = 8 * 1024**3
        swap_reader = FakeSwapRateReader(
            SwapRateEvidence(
                observed_at=NOW - timedelta(seconds=30),
                node_swap_in_bytes_per_second=MappingProxyType(
                    {"node-amber": None, "node-cobalt": 65_537}
                ),
            )
        )
        result = probe_live_evidence(
            FakePVEReader(responses),
            FakeBrokerStatusReader(broker_status()),
            bindings,
            policies,
            config,
            swap_rate_reader=swap_reader,
            clock=lambda: NOW,
        )
        self.assertEqual(
            result["node_swap_in_bytes_per_second"],
            {"node-amber": None, "node-cobalt": 65_537},
        )
        self.assertEqual(result["source_observed_at"]["telemetry"], "2035-06-15T11:59:30Z")
        self.assertEqual(swap_reader.calls, 1)
        LiveEvidence.from_dict(result, policies, bindings)

    def test_injected_swap_rates_require_exact_semantic_alias_coverage(self):
        cases = (
            ({"node-cobalt": 0}, "exactly cover"),
            (
                {"node-amber": 0, "node-cobalt": 0, "node-silver": 0},
                "exactly cover",
            ),
            ({"node-amber": 0, "Node-Cobalt": 0}, "lowercase semantic alias"),
        )
        for rates, message in cases:
            with self.subTest(rates=rates):
                policies, _binding_value, bindings, config, responses = probe_inputs()
                with self.assertRaisesRegex(InputError, message):
                    probe_live_evidence(
                        FakePVEReader(responses),
                        FakeBrokerStatusReader(broker_status()),
                        bindings,
                        policies,
                        config,
                        swap_rate_reader=FakeSwapRateReader(SwapRateEvidence(NOW, rates)),
                        clock=lambda: NOW,
                    )

    def test_injected_swap_rates_reject_boolean_negative_and_overflow_values(self):
        cases = (True, -1, 2**63)
        for bad_rate in cases:
            with self.subTest(rate=bad_rate):
                policies, _binding_value, bindings, config, responses = probe_inputs()
                with self.assertRaisesRegex(InputError, "outside its integer range"):
                    probe_live_evidence(
                        FakePVEReader(responses),
                        FakeBrokerStatusReader(broker_status()),
                        bindings,
                        policies,
                        config,
                        swap_rate_reader=FakeSwapRateReader(
                            SwapRateEvidence(
                                NOW,
                                {"node-amber": 0, "node-cobalt": bad_rate},
                            )
                        ),
                        clock=lambda: NOW,
                    )

    def test_injected_swap_rates_reject_naive_and_future_observations(self):
        cases = (
            (NOW.replace(tzinfo=None), "timezone-aware"),
            (NOW + timedelta(microseconds=1), "future-dated"),
        )
        for observed_at, message in cases:
            with self.subTest(observed_at=observed_at):
                policies, _binding_value, bindings, config, responses = probe_inputs()
                with self.assertRaisesRegex(InputError, message):
                    probe_live_evidence(
                        FakePVEReader(responses),
                        FakeBrokerStatusReader(broker_status()),
                        bindings,
                        policies,
                        config,
                        swap_rate_reader=FakeSwapRateReader(
                            SwapRateEvidence(
                                observed_at,
                                {"node-amber": 0, "node-cobalt": 0},
                            )
                        ),
                        clock=lambda: NOW,
                    )

    def test_injected_swap_rate_cannot_conflict_with_configured_zero(self):
        policies, _binding_value, bindings, config, responses = probe_inputs()
        with self.assertRaisesRegex(InputError, "configured-zero"):
            probe_live_evidence(
                FakePVEReader(responses),
                FakeBrokerStatusReader(broker_status()),
                bindings,
                policies,
                config,
                swap_rate_reader=FakeSwapRateReader(
                    SwapRateEvidence(
                        NOW,
                        {"node-amber": 0, "node-cobalt": 1},
                    )
                ),
                clock=lambda: NOW,
            )

    def test_stale_or_declared_unavailable_swap_evidence_uses_pve_defaults(self):
        for result in (
            SwapRateEvidence(
                NOW - timedelta(seconds=91),
                {"node-amber": 8_192, "node-cobalt": 0},
            ),
            SwapRateUnavailable("bounded reader timed out"),
        ):
            with self.subTest(result=type(result).__name__):
                policies, _binding_value, bindings, config, responses = probe_inputs()
                responses["/nodes/hypervisor-b/status"]["swap"]["total"] = 8 * 1024**3
                swap_reader = FakeSwapRateReader(result)
                evidence = probe_live_evidence(
                    FakePVEReader(responses),
                    FakeBrokerStatusReader(broker_status()),
                    bindings,
                    policies,
                    config,
                    swap_rate_reader=swap_reader,
                    clock=lambda: NOW,
                )
                self.assertEqual(
                    evidence["node_swap_in_bytes_per_second"],
                    {"node-amber": None, "node-cobalt": 0},
                )
                self.assertEqual(
                    evidence["source_observed_at"]["telemetry"],
                    "2035-06-15T12:00:00Z",
                )
                self.assertEqual(swap_reader.calls, 1)

    def test_swap_evidence_at_freshness_boundary_is_accepted(self):
        policies, _binding_value, bindings, config, responses = probe_inputs()
        responses["/nodes/hypervisor-b/status"]["swap"]["total"] = 8 * 1024**3
        result = probe_live_evidence(
            FakePVEReader(responses),
            FakeBrokerStatusReader(broker_status()),
            bindings,
            policies,
            config,
            swap_rate_reader=FakeSwapRateReader(
                SwapRateEvidence(
                    NOW - timedelta(seconds=policies.max_snapshot_age_seconds),
                    {"node-amber": 4_096, "node-cobalt": None},
                )
            ),
            clock=lambda: NOW,
        )
        self.assertEqual(
            result["node_swap_in_bytes_per_second"],
            {"node-amber": 4_096, "node-cobalt": None},
        )
        self.assertEqual(result["source_observed_at"]["telemetry"], "2035-06-15T11:58:30Z")

    def test_only_declared_swap_unavailability_is_a_fallback(self):
        policies, _binding_value, bindings, config, responses = probe_inputs()
        with self.assertRaisesRegex(RuntimeError, "unexpected failure"):
            probe_live_evidence(
                FakePVEReader(responses),
                FakeBrokerStatusReader(broker_status()),
                bindings,
                policies,
                config,
                swap_rate_reader=FakeSwapRateReader(RuntimeError("unexpected failure")),
                clock=lambda: NOW,
            )

    def test_swap_reader_must_return_the_public_evidence_type(self):
        policies, _binding_value, bindings, config, responses = probe_inputs()
        with self.assertRaisesRegex(InputError, "invalid evidence type"):
            probe_live_evidence(
                FakePVEReader(responses),
                FakeBrokerStatusReader(broker_status()),
                bindings,
                policies,
                config,
                swap_rate_reader=FakeSwapRateReader(None),
                clock=lambda: NOW,
            )

    def test_newest_unfinished_backup_attempt_wins_over_older_success(self):
        policies, _binding_value, bindings, config, responses = probe_inputs()
        newer_upid = "UPID:hypervisor-a:newer-attempt"
        responses["/nodes/hypervisor-a/tasks?limit=16&typefilter=vzdump"].insert(
            0,
            {
                "type": "vzdump",
                "node": "hypervisor-a",
                "endtime": int(NOW.timestamp()) - 600,
                "upid": newer_upid,
            },
        )
        responses[f"/nodes/hypervisor-a/tasks/{quote(newer_upid, safe='')}/log?limit=5000"] = [
            {"n": 1, "t": "INFO: Starting Backup of VM 1005 (qemu)"}
        ]
        result = probe_live_evidence(
            FakePVEReader(responses),
            FakeBrokerStatusReader(broker_status()),
            bindings,
            policies,
            config,
            clock=lambda: NOW,
        )
        backups = {row["environment_id"]: row for row in result["backups"]}
        self.assertEqual(
            backups["vision-workbench"],
            {
                "environment_id": "vision-workbench",
                "state": "unknown",
                "age_seconds": None,
            },
        )
        self.assertEqual(backups["batch-orchestrator"]["state"], "fresh")
        self.assertEqual(backups["archive-indexer"]["state"], "fresh")

    def test_probe_config_requires_exact_coverage_and_honest_unimplemented_state(self):
        policies, _binding_value, bindings, _config, _responses = probe_inputs()
        missing = probe_config_value()
        missing["controllers"].pop()
        with self.assertRaisesRegex(InputError, "exactly cover"):
            EvidenceProbeConfig.from_dict(missing, policies, bindings)

        dishonest = probe_config_value()
        windows = next(
            row for row in dishonest["controllers"] if row["alias"] == "desktop-range-controller"
        )
        windows["pve_guest_aliases"] = ["desktop-management"]
        with self.assertRaisesRegex(InputError, "cannot claim"):
            EvidenceProbeConfig.from_dict(dishonest, policies, bindings)

    def test_export_is_atomic_mode_0600_and_reloads_as_strict_evidence(self):
        policies, binding_value, bindings, _config, responses = probe_inputs()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog_path = directory / "catalog.json"
            bindings_path = directory / "bindings.json"
            config_path = directory / "probe.json"
            output_path = directory / "evidence.json"
            for path, value in (
                (catalog_path, raw_catalog()),
                (bindings_path, binding_value),
                (config_path, probe_config_value()),
            ):
                path.write_text(json.dumps(value), encoding="utf-8")
            result = export_probe_evidence(
                catalog_path=catalog_path,
                bindings_path=bindings_path,
                probe_config_path=config_path,
                output_path=output_path,
                reader=FakePVEReader(responses),
                broker=FakeBrokerStatusReader(broker_status()),
                clock=lambda: NOW,
            )
            self.assertEqual(json.loads(output_path.read_text(encoding="utf-8")), result)
            self.assertEqual(os.stat(output_path).st_mode & 0o777, 0o600)
            LiveEvidence.from_dict(result, policies, bindings)

    def test_export_threads_the_optional_swap_rate_reader(self):
        policies, binding_value, bindings, _config, responses = probe_inputs()
        for source_node in ("hypervisor-a", "hypervisor-b"):
            responses[f"/nodes/{source_node}/status"]["swap"]["total"] = 8 * 1024**3
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            catalog_path = directory / "catalog.json"
            bindings_path = directory / "bindings.json"
            config_path = directory / "probe.json"
            output_path = directory / "evidence.json"
            for path, value in (
                (catalog_path, raw_catalog()),
                (bindings_path, binding_value),
                (config_path, probe_config_value()),
            ):
                path.write_text(json.dumps(value), encoding="utf-8")
            swap_reader = FakeSwapRateReader(
                SwapRateEvidence(
                    NOW - timedelta(seconds=10),
                    {"node-amber": 2_048, "node-cobalt": 1_024},
                )
            )
            result = export_probe_evidence(
                catalog_path=catalog_path,
                bindings_path=bindings_path,
                probe_config_path=config_path,
                output_path=output_path,
                reader=FakePVEReader(responses),
                broker=FakeBrokerStatusReader(broker_status()),
                swap_rate_reader=swap_reader,
                clock=lambda: NOW,
            )
            self.assertEqual(
                result["node_swap_in_bytes_per_second"],
                {"node-amber": 2_048, "node-cobalt": 1_024},
            )
            self.assertEqual(result["source_observed_at"]["telemetry"], "2035-06-15T11:59:50Z")
            self.assertEqual(swap_reader.calls, 1)
            LiveEvidence.from_dict(result, policies, bindings)


class ReadOnlyCredentialSelectionTests(unittest.TestCase):
    def test_complete_read_only_pair_is_required_and_generic_tokens_are_ignored(self):
        read_only_id = "PVE_RO_TOKEN_" + "ID"
        read_only_secret = "PVE_RO_TOKEN_" + "SECRET"
        generic_id = "PVE_TOKEN_" + "ID"
        generic_secret = "PVE_TOKEN_" + "SECRET"
        environment = {
            "PVE_HOST": "example-hypervisor",
            read_only_id: "audit-" + "token",
            read_only_secret: "audit-" + "secret",
            generic_id: "generic-" + "token",
            generic_secret: "generic-" + "secret",
        }
        with patch.dict(os.environ, environment, clear=True):
            reader = ProxmoxHTTPSReader.from_environment(insecure_tls=True)
        self.assertEqual(reader.token_id, "audit-token")
        self.assertEqual(reader.token_secret, "audit-secret")

        environment[read_only_secret] = ""
        with (
            patch.dict(os.environ, environment, clear=True),
            self.assertRaisesRegex(InputError, "PVE_RO_TOKEN"),
        ):
            ProxmoxHTTPSReader.from_environment(insecure_tls=True)

        environment.pop(read_only_id)
        environment.pop(read_only_secret)
        with (
            patch.dict(os.environ, environment, clear=True),
            self.assertRaisesRegex(InputError, "PVE_RO_TOKEN"),
        ):
            ProxmoxHTTPSReader.from_environment(insecure_tls=True)


if __name__ == "__main__":
    unittest.main()
