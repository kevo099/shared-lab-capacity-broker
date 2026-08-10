from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from lab_broker.domain.canonical import digest
from lab_broker.domain.planner import (
    EvidenceUnknown,
    build_overview,
    node_envelope,
    plan_start,
)
from lab_broker.domain.types import Catalog, InputError, PlanRequest, Snapshot
from tests.support import (
    GIB,
    catalog,
    environment,
    guest,
    node,
    raw_catalog,
    raw_snapshot,
    snapshot,
)


def cross_node_security_range_catalog(value):
    # The fictional catalog intentionally exercises a multi-node cohort.
    environment(value, "security-range")


def cross_node_security_range_snapshot(value):
    # The fictional snapshot already matches the catalog's explicit split.
    guest(value, "security-target-two")


class InputContractTests(unittest.TestCase):
    def test_validated_policy_and_snapshot_mappings_are_immutable(self):
        policies = catalog()
        current = snapshot()
        with self.assertRaises(TypeError):
            policies.environments["new-environment"] = policies.environments["cluster-blue"]
        with self.assertRaises(TypeError):
            current.nodes["node-cobalt"] = current.nodes["node-amber"]

    def test_bool_is_never_accepted_as_an_integer(self):
        value = raw_catalog()
        value["max_snapshot_age_seconds"] = True
        with self.assertRaises(InputError):
            Catalog.from_dict(value)

        value = raw_snapshot()
        value["nodes"][0]["memory_total_bytes"] = False
        with self.assertRaises(InputError):
            Snapshot.from_dict(value)

        value = raw_snapshot()
        value["nodes"][0]["swap_in_bytes_per_second"] = None
        self.assertIsNone(Snapshot.from_dict(value).nodes["node-cobalt"].swap_in_bytes_per_second)

    def test_semantic_identifiers_are_ascii_and_reject_unicode_confusables(self):
        value = raw_catalog()
        environment(value, "foundation")["controller"] = "c\u043ere-observer"
        with self.assertRaises(InputError):
            Catalog.from_dict(value)

        value = raw_snapshot()
        value["guests"][0]["id"] = "c\u043ere-gateway"
        with self.assertRaises(InputError):
            Snapshot.from_dict(value)

    def test_unknown_fields_duplicate_aliases_and_out_of_range_values_fail(self):
        value = raw_catalog()
        value["unexpected"] = "unsafe-default"
        with self.assertRaises(InputError):
            Catalog.from_dict(value)

        value = raw_snapshot()
        value["guests"].append(copy.deepcopy(value["guests"][0]))
        with self.assertRaises(InputError):
            Snapshot.from_dict(value)

        value = raw_snapshot()
        value["nodes"][0]["memory_total_bytes"] = 2**63
        with self.assertRaises(InputError):
            Snapshot.from_dict(value)

    def test_request_rejects_unknown_environment_and_duration_over_policy(self):
        policies = catalog()
        current = snapshot()
        with self.assertRaises(InputError):
            plan_start(
                PlanRequest.create("not-reviewed", current.demo_evaluation_time),
                current,
                policies,
            )
        with self.assertRaises(InputError):
            plan_start(
                PlanRequest.create("cluster-blue", current.demo_evaluation_time, 99999),
                current,
                policies,
            )

    def test_planner_rejects_snapshot_from_a_different_catalog(self):
        policies = catalog()
        current = replace(snapshot(), catalog_digest="sha256:" + "0" * 64)
        with self.assertRaisesRegex(InputError, "catalog digest"):
            plan_start(
                PlanRequest.create("cluster-blue", current.demo_evaluation_time),
                current,
                policies,
            )

    def test_explicit_placements_must_partition_the_cohort_and_match_aggregates(self):
        value = raw_catalog()
        cross_node_security_range_catalog(value)
        policies = Catalog.from_dict(value)
        security_range = policies.environments["security-range"]
        self.assertEqual(
            [placement.node for placement in security_range.placements],
            ["node-amber", "node-cobalt"],
        )

        for mutate in (
            lambda target: target["placements"][1]["cohort"].pop(),
            lambda target: target["placements"][1].__setitem__("node", "node-cobalt"),
            lambda target: target["placements"][1].__setitem__("reserved_memory_bytes", 3 * GIB),
        ):
            invalid = raw_catalog()
            cross_node_security_range_catalog(invalid)
            mutate(environment(invalid, "security-range"))
            with self.subTest(mutation=mutate), self.assertRaises(InputError):
                Catalog.from_dict(invalid)


class CapacityEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = snapshot()

    def test_conservative_and_observed_envelopes_are_distinct(self):
        result = node_envelope(self.snapshot, "node-cobalt")
        self.assertEqual(result["guaranteed_headroom_bytes"], 32 * GIB)
        self.assertEqual(result["observed_headroom_bytes"], 20 * GIB)
        self.assertEqual(result["running_configured_bytes"], 37 * GIB)

    def test_ksm_never_increases_guaranteed_headroom(self):
        baseline = node_envelope(self.snapshot, "node-cobalt")
        changed = replace(
            self.snapshot,
            nodes={
                **self.snapshot.nodes,
                "node-cobalt": replace(
                    self.snapshot.nodes["node-cobalt"], ksm_shared_bytes=40 * GIB
                ),
            },
        )
        after = node_envelope(changed, "node-cobalt")
        self.assertEqual(after["guaranteed_headroom_bytes"], baseline["guaranteed_headroom_bytes"])
        self.assertEqual(after["ksm_shared_diagnostic_bytes"], 40 * GIB)

    def test_reservation_realization_does_not_double_count_running_maxima(self):
        def add_reservation(value):
            value["reservations"] = [
                {
                    "environment_id": "cluster-blue",
                    "node": "node-amber",
                    "reserved_bytes": 21 * GIB,
                    "member_ids": [
                        "cluster-control",
                        "cluster-worker-one",
                        "cluster-worker-two",
                    ],
                    "state": "active",
                }
            ]

        stopped = snapshot(add_reservation)
        stopped_envelope = node_envelope(stopped, "node-amber")
        self.assertEqual(stopped_envelope["unrealized_reservations_bytes"], 21 * GIB)

        def run_members(value):
            add_reservation(value)
            for member in (
                "cluster-control",
                "cluster-worker-one",
                "cluster-worker-two",
            ):
                row = guest(value, member)
                row["state"] = "running"
                row["observed_memory_bytes"] = 2 * GIB
                row["owner_environment"] = "cluster-blue"

        running = snapshot(run_members)
        running_envelope = node_envelope(running, "node-amber")
        self.assertEqual(running_envelope["unrealized_reservations_bytes"], 0)
        self.assertEqual(
            running_envelope["guaranteed_headroom_bytes"],
            stopped_envelope["guaranteed_headroom_bytes"],
        )

    def test_ambiguous_reservation_membership_fails_closed(self):
        def ambiguous(value):
            record = {
                "environment_id": "cluster-blue",
                "node": "node-amber",
                "reserved_bytes": 21 * GIB,
                "member_ids": [
                    "cluster-control",
                    "cluster-worker-one",
                    "cluster-worker-two",
                ],
                "state": "active",
            }
            value["reservations"] = [
                record,
                {**record, "environment_id": "cluster-green"},
            ]

        with self.assertRaises(EvidenceUnknown):
            node_envelope(snapshot(ambiguous), "node-amber")


class PlannerAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.catalog = catalog()
        self.snapshot = snapshot()
        self.when = self.snapshot.demo_evaluation_time

    def plan(
        self,
        environment_id: str,
        current: Snapshot | None = None,
        policies: Catalog | None = None,
    ):
        selected_catalog = policies or self.catalog
        selected_snapshot = current or self.snapshot
        if selected_snapshot.catalog_digest != selected_catalog.digest:
            selected_snapshot = replace(selected_snapshot, catalog_digest=selected_catalog.digest)
        return plan_start(
            PlanRequest.create(environment_id, self.when),
            selected_snapshot,
            selected_catalog,
        )

    def test_fixture_matrix_answers_the_central_question(self):
        overview = build_overview(self.snapshot, self.catalog, evaluated_at=self.when)
        outcomes = {item["id"]: item["outcome"] for item in overview["environments"]}
        self.assertEqual(
            outcomes,
            {
                "cluster-blue": "safe_now",
                "cluster-green": "safe_now",
                "vision-workbench": "already_active",
                "security-range": "safe_with_donors",
                "automation-blue": "safe_now",
                "linux-blue": "safe_now",
                "desktop-range": "safe_with_donors",
            },
        )
        security_range = self.plan("security-range")
        self.assertEqual(security_range["required_donors"], ["vision-workbench"])
        self.assertEqual(security_range["donor_set_id"], "security-vision-release")
        windows = self.plan("desktop-range")
        self.assertEqual(windows["required_donors"], ["batch-orchestrator", "archive-indexer"])

    def test_overview_supports_a_catalog_with_no_user_visible_rows(self):
        def hide(value):
            for policy in value["environments"]:
                policy["user_visible"] = False

        overview = build_overview(self.snapshot, catalog(hide), evaluated_at=self.when)
        self.assertEqual(overview["environments"], [])
        self.assertEqual(overview["summary"]["managed_environments"], 0)

    def test_plan_is_byte_stable_and_any_evidence_change_changes_digest(self):
        first = self.plan("security-range")
        second = self.plan("security-range")
        self.assertEqual(first, second)
        self.assertIsNone(first["lease_id"])
        self.assertEqual(
            first["digest"],
            digest({key: value for key, value in first.items() if key != "digest"}),
        )

        changed = replace(
            self.snapshot,
            nodes={
                **self.snapshot.nodes,
                "node-cobalt": replace(
                    self.snapshot.nodes["node-cobalt"],
                    memory_available_bytes=self.snapshot.nodes["node-cobalt"].memory_available_bytes
                    - 1,
                ),
            },
        )
        self.assertNotEqual(first["digest"], self.plan("security-range", changed)["digest"])

    def test_observed_only_capacity_is_blocked_in_the_mvp(self):
        def high_observed(value):
            node(value, "node-amber")["memory_available_bytes"] = 72 * GIB

        def oversized_request(value):
            environment(value, "cluster-blue")["reserved_memory_bytes"] = 60 * GIB

        current = snapshot(high_observed)
        policies = catalog(oversized_request)
        result = self.plan("cluster-blue", current, policies)
        self.assertEqual(result["outcome"], "blocked")
        self.assertIn("capacity_observed_only", result["reason_codes"])
        self.assertEqual(result["actions"], [])

    def test_security_range_uses_only_the_guarded_reviewed_adapter(self):
        result = self.plan("security-range")
        donor_actions = [action for action in result["actions"] if "donor" in action["operation"]]
        self.assertEqual(len(donor_actions), 1)
        self.assertEqual(donor_actions[0]["adapter"], "reviewed-range-capacity")
        serialized = str(result).lower()
        self.assertNotIn("migration", serialized)
        self.assertNotIn("shell", serialized)

    def test_stale_or_failed_donor_backup_blocks_without_inventing_a_subset(self):
        def stale(value):
            for backup in value["backups"]:
                if backup["environment_id"] == "vision-workbench":
                    backup["state"] = "stale"

        result = self.plan("security-range", snapshot(stale))
        self.assertEqual(result["outcome"], "blocked")
        self.assertIn("backup_stale", result["reason_codes"])
        self.assertEqual(result["actions"], [])

    def test_core_gpu_affine_and_unreviewed_workloads_are_never_donors(self):
        def corrected(value):
            target = environment(value, "security-range")
            target["donor_sets"] = [
                {
                    "id": "unsafe-core",
                    "donors": ["foundation"],
                    "adapter": "reviewed-range-capacity",
                    "requires_fresh_backup": False,
                    "service_impact": 1,
                    "restore_seconds": 1,
                    "dependencies": 0,
                }
            ]

        result = self.plan("security-range", policies=catalog(corrected))
        self.assertEqual(result["outcome"], "blocked")
        self.assertEqual(result["required_donors"], [])
        self.assertEqual(result["actions"], [])

    def test_locked_guest_network_storage_swap_and_controller_are_hard_gates(self):
        mutations = {
            "guest_locked": lambda value: guest(value, "cluster-control").__setitem__(
                "locked", True
            ),
            "network_prerequisite_missing": lambda value: value["networks"].__setitem__(
                "assessment-fabric", False
            ),
            "storage_floor_breached": lambda value: node(value, "node-amber").__setitem__(
                "root_free_bytes", 1
            ),
            "swap_pressure": lambda value: node(value, "node-amber").__setitem__(
                "swap_in_bytes_per_second", 1048577
            ),
            "controller_unhealthy": lambda value: value["controllers"].__setitem__(
                "cluster-exam-controller", False
            ),
        }
        for expected, mutate in mutations.items():
            with self.subTest(reason=expected):
                result = self.plan("cluster-blue", snapshot(mutate))
                self.assertEqual(result["outcome"], "blocked")
                self.assertIn(expected, result["reason_codes"])
                self.assertEqual(result["actions"], [])

    def test_missing_swap_rate_is_unknown_only_for_affected_placements(self):
        def amber_unknown(value):
            node(value, "node-amber")["swap_in_bytes_per_second"] = None

        affected = self.plan("cluster-blue", snapshot(amber_unknown))
        self.assertEqual(affected["outcome"], "unknown")
        self.assertIn("swap_evidence_unknown", affected["reason_codes"])
        self.assertEqual(affected["actions"], [])

        def cobalt_unknown(value):
            node(value, "node-cobalt")["swap_in_bytes_per_second"] = None

        unaffected = self.plan("cluster-blue", snapshot(cobalt_unknown))
        self.assertEqual(unaffected["outcome"], "safe_now")

    def test_cross_node_security_range_has_per_node_capacity_and_deterministic_donor_plan(
        self,
    ):
        policies = catalog(cross_node_security_range_catalog)
        current = snapshot(cross_node_security_range_snapshot)
        first = self.plan("security-range", current, policies)
        second = self.plan("security-range", current, policies)
        self.assertEqual(first, second)
        self.assertEqual(first["outcome"], "safe_with_donors")
        self.assertEqual(first["required_donors"], ["vision-workbench"])
        self.assertIsNone(first["capacity"]["node"])
        self.assertEqual(
            [row["node"] for row in first["capacity"]["nodes"]],
            ["node-amber", "node-cobalt"],
        )
        reserve_actions = [
            action for action in first["actions"] if action["operation"] == "reserve-capacity"
        ]
        self.assertEqual(
            [action["target"] for action in reserve_actions],
            ["node-amber", "node-cobalt"],
        )
        self.assertEqual(
            [action["arguments"]["memory_bytes"] for action in reserve_actions],
            [8 * GIB, 35 * GIB],
        )

    def test_cross_node_security_range_wrong_placement_and_secondary_node_pressure_fail_closed(
        self,
    ):
        policies = catalog(cross_node_security_range_catalog)

        def wrong_node(value):
            cross_node_security_range_snapshot(value)
            guest(value, "security-analyst")["node"] = "node-cobalt"

        result = self.plan("security-range", snapshot(wrong_node), policies)
        self.assertEqual(result["outcome"], "unknown")
        self.assertIn("inventory_binding_unknown", result["reason_codes"])
        self.assertEqual(result["actions"], [])

        def pressure(value):
            cross_node_security_range_snapshot(value)
            node(value, "node-amber")["swap_in_bytes_per_second"] = 1048577

        result = self.plan("security-range", snapshot(pressure), policies)
        self.assertEqual(result["outcome"], "blocked")
        self.assertIn("swap_pressure", result["reason_codes"])
        self.assertEqual(result["actions"], [])

    def test_cross_node_holding_reservation_requires_every_exact_placement(self):
        policies = catalog(cross_node_security_range_catalog)

        def partial_reservation(value):
            cross_node_security_range_snapshot(value)
            value["reservations"] = [
                {
                    "environment_id": "security-range",
                    "node": "node-cobalt",
                    "reserved_bytes": 35 * GIB,
                    "member_ids": [
                        "security-gateway",
                        "security-directory",
                        "security-client-one",
                        "security-client-two",
                        "security-target-one",
                    ],
                    "state": "reserved",
                }
            ]

        result = self.plan("security-range", snapshot(partial_reservation), policies)
        self.assertEqual(result["outcome"], "unknown")
        self.assertIn("inventory_binding_unknown", result["reason_codes"])


class FreshnessAndExclusivityTests(unittest.TestCase):
    def setUp(self):
        self.catalog = catalog()
        self.base = snapshot()
        self.when = self.base.demo_evaluation_time

    def plan(self, environment_id: str, current: Snapshot):
        return plan_start(PlanRequest.create(environment_id, self.when), current, self.catalog)

    def test_missing_stale_future_and_skewed_sources_are_unknown(self):
        def missing(value):
            del value["source_observed_at"]["backups"]

        def stale(value):
            value["source_observed_at"]["telemetry"] = "2035-06-15T11:50:00Z"

        def future(value):
            value["source_observed_at"]["telemetry"] = "2035-06-15T12:00:01Z"

        def skew(value):
            value["source_observed_at"]["backups"] = "2035-06-15T11:59:20Z"

        cases = (
            (missing, "telemetry_incomplete"),
            (stale, "telemetry_stale"),
            (future, "telemetry_future_dated"),
            (skew, "telemetry_source_skew"),
        )
        for mutate, reason in cases:
            with self.subTest(reason=reason):
                result = self.plan("cluster-blue", snapshot(mutate))
                self.assertEqual(result["outcome"], "unknown")
                self.assertIn(reason, result["reason_codes"])
                self.assertEqual(result["actions"], [])

    def test_contradictory_collection_order_is_unknown(self):
        def contradictory(value):
            value["collected_at"] = "2035-06-15T11:59:45Z"

        result = self.plan("cluster-blue", snapshot(contradictory))
        self.assertEqual(result["outcome"], "unknown")
        self.assertIn("telemetry_source_skew", result["reason_codes"])
        self.assertEqual(result["actions"], [])

    def test_plan_validity_never_outlives_oldest_required_source(self):
        def almost_stale(value):
            value["observed_at"] = "2035-06-15T11:58:35Z"
            value["collected_at"] = "2035-06-15T11:58:36Z"
            value["source_observed_at"] = {
                source: "2035-06-15T11:58:35Z" for source in value["source_observed_at"]
            }

        result = self.plan("cluster-blue", snapshot(almost_stale))
        self.assertEqual(result["outcome"], "safe_now")
        self.assertEqual(result["valid_until"], "2035-06-15T12:00:05Z")

    def test_conflicting_live_exam_leases_fail_closed(self):
        def conflicting(value):
            value["leases"] = [
                {
                    "id": "lease-alpha",
                    "environment_id": "cluster-blue",
                    "class": "exam",
                    "state": "active",
                    "expires_at": "2035-06-15T14:00:00Z",
                },
                {
                    "id": "lease-bravo",
                    "environment_id": "linux-blue",
                    "class": "exam",
                    "state": "cleanup_failed",
                    "expires_at": "2035-06-15T14:00:00Z",
                },
            ]

        result = self.plan("security-range", snapshot(conflicting))
        self.assertEqual(result["outcome"], "unknown")
        self.assertIn("inventory_binding_unknown", result["reason_codes"])
        self.assertEqual(result["actions"], [])

    def test_missing_managed_binding_fails_every_plan_closed(self):
        def missing_binding(value):
            value["guests"] = [
                guest for guest in value["guests"] if guest["id"] != "desktop-client-two"
            ]

        result = self.plan("cluster-blue", snapshot(missing_binding))
        self.assertEqual(result["outcome"], "unknown")
        self.assertIn("inventory_binding_unknown", result["reason_codes"])
        self.assertEqual(result["actions"], [])

    def test_one_exam_lease_blocks_every_other_exam_even_when_ram_fits(self):
        for state in (
            "reserved",
            "active",
            "cleanup_due",
            "releasing",
            "cleanup_failed",
        ):

            def leased(value, lease_state=state):
                value["leases"] = [
                    {
                        "id": "lease-alpha",
                        "environment_id": "cluster-blue",
                        "class": "exam",
                        "state": lease_state,
                        "expires_at": "2035-06-15T14:00:00Z",
                    }
                ]

            with self.subTest(state=state):
                result = self.plan("linux-blue", snapshot(leased))
                self.assertEqual(result["outcome"], "queued_exclusivity")
                self.assertIn("exam_slot_occupied", result["reason_codes"])
                self.assertEqual(result["actions"], [])

    def test_terminal_exam_lease_does_not_hold_the_slot(self):
        def released(value):
            value["leases"] = [
                {
                    "id": "lease-alpha",
                    "environment_id": "cluster-blue",
                    "class": "exam",
                    "state": "released",
                    "expires_at": "2035-06-15T11:00:00Z",
                }
            ]

        self.assertEqual(self.plan("linux-blue", snapshot(released))["outcome"], "safe_now")

    def test_cluster_blue_cluster_green_shared_cohort_is_reported_with_the_exam_conflict(
        self,
    ):
        def active_cluster_blue(value):
            for member in (
                "cluster-control",
                "cluster-worker-one",
                "cluster-worker-two",
            ):
                row = guest(value, member)
                row["state"] = "running"
                row["observed_memory_bytes"] = 2 * GIB
                row["owner_environment"] = "cluster-blue"
            value["leases"] = [
                {
                    "id": "lease-alpha",
                    "environment_id": "cluster-blue",
                    "class": "exam",
                    "state": "active",
                    "expires_at": "2035-06-15T14:00:00Z",
                }
            ]

        result = self.plan("cluster-green", snapshot(active_cluster_blue))
        self.assertEqual(result["outcome"], "queued_exclusivity")
        self.assertIn("shared_cohort_active", result["reason_codes"])

    def test_manually_started_different_exam_blocks_instead_of_being_adopted(self):
        def manual(value):
            for member in ("linux-node-one", "linux-node-two"):
                row = guest(value, member)
                row["state"] = "running"
                row["observed_memory_bytes"] = 2 * GIB
                row["owner_environment"] = "linux-blue"

        result = self.plan("security-range", snapshot(manual))
        self.assertEqual(result["outcome"], "blocked")
        self.assertIn("unmanaged_exam_active", result["reason_codes"])
        self.assertEqual(result["actions"], [])

    def test_partial_cohort_fails_closed(self):
        def partial(value):
            row = guest(value, "cluster-control")
            row["state"] = "running"
            row["observed_memory_bytes"] = 2 * GIB

        result = self.plan("cluster-blue", snapshot(partial))
        self.assertEqual(result["outcome"], "unknown")
        self.assertIn("environment_state_uncertain", result["reason_codes"])


if __name__ == "__main__":
    unittest.main()
