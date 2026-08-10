"""Pure, deterministic capacity, coexistence, and donor planner.

The module deliberately imports no filesystem, HTTP, database, subprocess, or
clock APIs. Callers provide validated policy, an immutable snapshot, and an
explicit evaluation time.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Iterable, TypedDict

from .canonical import digest
from .types import (
    LEASE_HOLDING_STATES,
    MAX_I64,
    RESERVATION_HOLDING_STATES,
    Catalog,
    DonorSet,
    EnvironmentPolicy,
    Guest,
    InputError,
    PlanRequest,
    Snapshot,
    format_time,
)

OUTCOMES = frozenset(
    {
        "safe_now",
        "safe_with_donors",
        "queued_exclusivity",
        "blocked",
        "unknown",
        "already_active",
    }
)
REASON_ORDER = (
    "telemetry_incomplete",
    "telemetry_future_dated",
    "telemetry_stale",
    "telemetry_source_skew",
    "inventory_binding_unknown",
    "environment_state_uncertain",
    "unmanaged_exam_active",
    "exam_slot_occupied",
    "shared_cohort_active",
    "exclusive_environment_active",
    "host_affinity_unsatisfied",
    "network_prerequisite_missing",
    "storage_floor_breached",
    "swap_evidence_unknown",
    "swap_pressure",
    "guest_locked",
    "controller_unhealthy",
    "backup_stale",
    "backup_unknown",
    "capacity_arithmetic_invalid",
    "capacity_conservative_shortfall",
    "capacity_observed_only",
    "donor_set_unavailable",
    "reviewed_donors_required",
    "already_active",
    "all_hard_gates_pass",
)
REASON_RANK = {reason: index for index, reason in enumerate(REASON_ORDER)}


class EvidenceUnknown(RuntimeError):
    pass


class CapacityEnvelope(TypedDict):
    physical_memory_bytes: int
    memory_available_bytes: int
    host_reserve_bytes: int
    running_configured_bytes: int
    unrealized_reservations_bytes: int
    requested_reserve_bytes: int
    guaranteed_headroom_bytes: int
    observed_headroom_bytes: int
    ksm_shared_diagnostic_bytes: int
    swap_in_bytes_per_second: int | None


def _ordered_reasons(values: Iterable[str]) -> list[str]:
    return sorted(set(values), key=lambda value: (REASON_RANK.get(value, 10_000), value))


def _bounded_sum(values: Iterable[int]) -> int:
    result = 0
    for value in values:
        if type(value) is not int or value < 0 or result > MAX_I64 - value:
            raise EvidenceUnknown("capacity arithmetic overflow")
        result += value
    return result


def environment_state(policy: EnvironmentPolicy, snapshot: Snapshot) -> tuple[str, list[str]]:
    """Reconcile one environment from every exact cohort member."""

    members: list[Guest] = []
    for member_id in policy.cohort:
        guest = snapshot.guests.get(member_id)
        if guest is None:
            return "unknown", ["inventory_binding_unknown"]
        members.append(guest)
    raw_states = {guest.state for guest in members}
    if raw_states == {"stopped"}:
        return "stopped", []
    if "unknown" in raw_states or "degraded" in raw_states:
        return "unknown", ["environment_state_uncertain"]

    # Alternative desired states can share the same guests. Ownership selects
    # which definition is active; a different reviewed sibling is not treated
    # as this environment also being active.
    owners = {guest.owner_environment for guest in members if guest.state != "stopped"}
    if policy.shares_cohort_with and len(owners) == 1:
        owner = next(iter(owners))
        if owner in policy.shares_cohort_with:
            return "stopped", []
    if owners and owners != {policy.id}:
        return "unknown", ["inventory_binding_unknown"]
    if raw_states == {"running"}:
        return "running", []
    if raw_states == {"starting"}:
        return "starting", []
    if raw_states == {"stopping"}:
        return "stopping", []
    return "partial", ["environment_state_uncertain"]


def _freshness(
    catalog: Catalog, snapshot: Snapshot, request: PlanRequest
) -> tuple[list[str], list[dict[str, Any]]]:
    reasons: list[str] = []
    gates: list[dict[str, Any]] = []
    missing = sorted(set(catalog.required_sources) - set(snapshot.source_observed_at))
    if missing:
        reasons.append("telemetry_incomplete")
        gates.append(
            {
                "gate": "snapshot_sources",
                "status": "unknown",
                "reason_code": "telemetry_incomplete",
                "evidence": {"missing_sources": missing},
            }
        )
        return reasons, gates

    source_times = [snapshot.source_observed_at[source] for source in catalog.required_sources]
    future = [
        source
        for source in catalog.required_sources
        if snapshot.source_observed_at[source] > request.evaluated_at
    ]
    if (
        snapshot.generated_at > request.evaluated_at
        or snapshot.collected_at > request.evaluated_at
        or snapshot.observed_at > request.evaluated_at
        or future
    ):
        reasons.append("telemetry_future_dated")
        gates.append(
            {
                "gate": "snapshot_time",
                "status": "unknown",
                "reason_code": "telemetry_future_dated",
                "evidence": {"future_sources": sorted(future)},
            }
        )
    ages = {
        source: int((request.evaluated_at - snapshot.source_observed_at[source]).total_seconds())
        for source in catalog.required_sources
    }
    generated_age = int((request.evaluated_at - snapshot.generated_at).total_seconds())
    stale = sorted(
        source for source, age in ages.items() if age < 0 or age > catalog.max_snapshot_age_seconds
    )
    if stale or generated_age < 0 or generated_age > catalog.max_snapshot_age_seconds:
        reasons.append("telemetry_stale")
        gates.append(
            {
                "gate": "snapshot_freshness",
                "status": "unknown",
                "reason_code": "telemetry_stale",
                "evidence": {
                    "ages_seconds": ages,
                    "generated_age_seconds": generated_age,
                    "maximum_seconds": catalog.max_snapshot_age_seconds,
                },
            }
        )
    skew = int((max(source_times) - min(source_times)).total_seconds())
    contradictory = (
        snapshot.observed_at > snapshot.collected_at
        or snapshot.collected_at > snapshot.generated_at
        or any(observed_at > snapshot.collected_at for observed_at in source_times)
    )
    if skew > catalog.max_source_skew_seconds or contradictory:
        reasons.append("telemetry_source_skew")
        gates.append(
            {
                "gate": "snapshot_skew",
                "status": "unknown",
                "reason_code": "telemetry_source_skew",
                "evidence": {
                    "skew_seconds": skew,
                    "maximum_seconds": catalog.max_source_skew_seconds,
                    "collection_order_consistent": not contradictory,
                },
            }
        )
    if not reasons:
        gates.append(
            {
                "gate": "snapshot_freshness",
                "status": "pass",
                "reason_code": "all_hard_gates_pass",
                "evidence": {
                    "ages_seconds": ages,
                    "generated_age_seconds": generated_age,
                    "skew_seconds": skew,
                },
            }
        )
    return reasons, gates


def _reservation_unrealized(snapshot: Snapshot, node_id: str) -> int:
    seen_members: set[str] = set()
    unrealized: list[int] = []
    for reservation in snapshot.reservations:
        if reservation.state not in RESERVATION_HOLDING_STATES or reservation.node != node_id:
            continue
        realized_values: list[int] = []
        for member_id in reservation.member_ids:
            if member_id in seen_members:
                raise EvidenceUnknown("reservation member correlation is ambiguous")
            seen_members.add(member_id)
            guest = snapshot.guests.get(member_id)
            if guest is None or guest.node != node_id:
                raise EvidenceUnknown("reservation member correlation is incomplete")
            if guest.state in {"running", "starting", "stopping", "degraded"}:
                realized_values.append(guest.configured_memory_bytes)
            elif guest.state == "unknown":
                raise EvidenceUnknown("reservation member state is unknown")
        realized = min(reservation.reserved_bytes, _bounded_sum(realized_values))
        unrealized.append(reservation.reserved_bytes - realized)
    return _bounded_sum(unrealized)


def node_envelope(
    snapshot: Snapshot,
    node_id: str,
    *,
    requested_bytes: int = 0,
    stopped_guest_ids: frozenset[str] = frozenset(),
) -> CapacityEnvelope:
    """Compute both memory envelopes without counting KSM or swap as capacity."""

    node = snapshot.nodes.get(node_id)
    if node is None:
        raise EvidenceUnknown("host affinity does not resolve")
    if type(requested_bytes) is not int or not 0 <= requested_bytes <= MAX_I64:
        raise EvidenceUnknown("requested memory is invalid")
    running = [
        guest
        for guest in snapshot.guests.values()
        if guest.node == node_id
        and guest.id not in stopped_guest_ids
        and guest.state in {"running", "starting", "stopping", "degraded"}
    ]
    if any(
        guest.node == node_id and guest.state == "unknown" for guest in snapshot.guests.values()
    ):
        raise EvidenceUnknown("node has an unknown guest state")
    configured = _bounded_sum(guest.configured_memory_bytes for guest in running)
    observed_freed = _bounded_sum(
        guest.observed_memory_bytes
        for guest in snapshot.guests.values()
        if guest.node == node_id and guest.id in stopped_guest_ids and guest.state == "running"
    )
    unrealized = _reservation_unrealized(snapshot, node_id)
    committed = _bounded_sum((node.host_reserve_bytes, configured, unrealized, requested_bytes))
    observed_committed = _bounded_sum((node.host_reserve_bytes, unrealized, requested_bytes))
    guaranteed = node.memory_total_bytes - committed
    observed = node.memory_available_bytes + observed_freed - observed_committed
    if not -MAX_I64 <= guaranteed <= MAX_I64 or not -MAX_I64 <= observed <= MAX_I64:
        raise EvidenceUnknown("capacity arithmetic exceeds signed range")
    return {
        "physical_memory_bytes": node.memory_total_bytes,
        "memory_available_bytes": node.memory_available_bytes,
        "host_reserve_bytes": node.host_reserve_bytes,
        "running_configured_bytes": configured,
        "unrealized_reservations_bytes": unrealized,
        "requested_reserve_bytes": requested_bytes,
        "guaranteed_headroom_bytes": guaranteed,
        "observed_headroom_bytes": observed,
        "ksm_shared_diagnostic_bytes": node.ksm_shared_bytes,
        "swap_in_bytes_per_second": node.swap_in_bytes_per_second,
    }


def _policy_capacity(
    snapshot: Snapshot,
    policy: EnvironmentPolicy,
    *,
    stopped_guest_ids: frozenset[str] = frozenset(),
) -> tuple[dict[str, CapacityEnvelope], dict[str, CapacityEnvelope]]:
    before: dict[str, CapacityEnvelope] = {}
    after: dict[str, CapacityEnvelope] = {}
    for placement in policy.placements:
        before[placement.node] = node_envelope(snapshot, placement.node)
        after[placement.node] = node_envelope(
            snapshot,
            placement.node,
            requested_bytes=placement.reserved_memory_bytes,
            stopped_guest_ids=stopped_guest_ids,
        )
    return before, after


def _holding_exam_leases(snapshot: Snapshot) -> list[Any]:
    return sorted(
        (
            lease
            for lease in snapshot.leases
            if lease.lease_class == "exam" and lease.state in LEASE_HOLDING_STATES
        ),
        key=lambda lease: (lease.environment_id, lease.id),
    )


def _commitment_binding_gate(
    catalog: Catalog,
    snapshot: Snapshot,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Validate live commitments before they influence any decision.

    Historical terminal rows may outlive a removed catalog entry. A live lease
    or reservation may not: silently ignoring one could overbook memory or the
    single exam semaphore.
    """

    issues: set[str] = set()
    member_owners: dict[str, set[str]] = {}
    for policy in catalog.environments.values():
        for placement in policy.placements:
            if placement.node not in snapshot.nodes:
                issues.add(placement.node)
        if policy.controller not in snapshot.controllers:
            issues.add(policy.controller)
        for network_id in policy.required_networks:
            if network_id not in snapshot.networks:
                issues.add(network_id)
        permitted_owners = {policy.id, *policy.shares_cohort_with}
        for placement in policy.placements:
            for member_id in placement.cohort:
                member_owners.setdefault(member_id, set()).add(policy.id)
                guest = snapshot.guests.get(member_id)
                if (
                    guest is None
                    or guest.node != placement.node
                    or guest.owner_environment not in permitted_owners
                ):
                    issues.add(member_id)
    for member_id, owners in member_owners.items():
        if len(owners) < 2:
            continue
        for owner_id in owners:
            owner = catalog.environments[owner_id]
            if owners - {owner_id} != set(owner.shares_cohort_with):
                issues.add(member_id)
            if any(
                {
                    member: placement.node
                    for placement in catalog.environments[peer].placements
                    for member in placement.cohort
                }
                != {
                    member: placement.node
                    for placement in owner.placements
                    for member in placement.cohort
                }
                for peer in owners - {owner_id}
            ):
                issues.add(member_id)

    holding_leases = [lease for lease in snapshot.leases if lease.state in LEASE_HOLDING_STATES]
    for lease in holding_leases:
        lease_policy = catalog.environments.get(lease.environment_id)
        if lease_policy is None or lease.lease_class != lease_policy.environment_class:
            issues.add(lease.environment_id)
    if len([lease for lease in holding_leases if lease.lease_class == "exam"]) > 1:
        issues.add("global-single-exam")

    claimed_members: set[str] = set()
    reservations_by_environment: dict[str, list[Any]] = {}
    for reservation in snapshot.reservations:
        if reservation.state not in RESERVATION_HOLDING_STATES:
            continue
        reservations_by_environment.setdefault(reservation.environment_id, []).append(reservation)
        reservation_policy = catalog.environments.get(reservation.environment_id)
        reservation_placement = (
            next(
                (
                    candidate
                    for candidate in reservation_policy.placements
                    if candidate.node == reservation.node
                ),
                None,
            )
            if reservation_policy is not None
            else None
        )
        if (
            reservation_policy is None
            or reservation_placement is None
            or reservation.node not in snapshot.nodes
        ) or (
            reservation.reserved_bytes != reservation_placement.reserved_memory_bytes
            or set(reservation.member_ids) != set(reservation_placement.cohort)
            or any(
                member_id not in snapshot.guests
                or snapshot.guests[member_id].node != reservation_placement.node
                for member_id in reservation.member_ids
            )
        ):
            issues.add(reservation.environment_id)
        if claimed_members.intersection(reservation.member_ids):
            issues.add(reservation.environment_id)
        claimed_members.update(reservation.member_ids)
    for environment_id, reservations in reservations_by_environment.items():
        environment_policy = catalog.environments.get(environment_id)
        if environment_policy is None:
            continue
        if len(reservations) != len(environment_policy.placements) or {
            reservation.node for reservation in reservations
        } != {placement.node for placement in environment_policy.placements}:
            issues.add(environment_id)

    if issues:
        return ["inventory_binding_unknown"], [
            {
                "gate": "commitment_bindings",
                "status": "unknown",
                "reason_code": "inventory_binding_unknown",
                "evidence": {"unresolved_aliases": sorted(issues)},
            }
        ]
    return [], [
        {
            "gate": "commitment_bindings",
            "status": "pass",
            "reason_code": "all_hard_gates_pass",
            "evidence": {
                "holding_leases": len(holding_leases),
                "holding_reservations": sum(
                    reservation.state in RESERVATION_HOLDING_STATES
                    for reservation in snapshot.reservations
                ),
            },
        }
    ]


def active_exam_summary(catalog: Catalog, snapshot: Snapshot) -> dict[str, Any] | None:
    leases = _holding_exam_leases(snapshot)
    if leases:
        lease = leases[0]
        policy = catalog.environments.get(lease.environment_id)
        return {
            "environment_id": lease.environment_id,
            "display_name": policy.display_name if policy else lease.environment_id,
            "state": lease.state,
            "managed": True,
            "expires_at": format_time(lease.expires_at),
        }
    active: list[tuple[str, str]] = []
    for policy in catalog.environments.values():
        if policy.environment_class != "exam":
            continue
        state, _reasons = environment_state(policy, snapshot)
        if state != "stopped":
            active.append((policy.id, state))
    if active:
        environment_id, state = sorted(active)[0]
        return {
            "environment_id": environment_id,
            "display_name": catalog.environments[environment_id].display_name,
            "state": state,
            "managed": False,
            "expires_at": None,
        }
    return None


def _hard_gates(
    catalog: Catalog,
    snapshot: Snapshot,
    policy: EnvironmentPolicy,
) -> tuple[list[str], list[dict[str, Any]]]:
    reasons: list[str] = []
    gates: list[dict[str, Any]] = []
    missing_nodes = sorted(
        placement.node for placement in policy.placements if placement.node not in snapshot.nodes
    )
    if missing_nodes:
        return ["host_affinity_unsatisfied"], [
            {
                "gate": "host_affinity",
                "status": "block",
                "reason_code": "host_affinity_unsatisfied",
                "evidence": {"missing_nodes": missing_nodes},
            }
        ]
    nodes = [snapshot.nodes[placement.node] for placement in policy.placements]
    gates.append(
        {
            "gate": "host_affinity",
            "status": "pass",
            "reason_code": "all_hard_gates_pass",
            "evidence": {"nodes": [node.id for node in nodes]},
        }
    )
    missing_networks = sorted(
        network
        for network in policy.required_networks
        if snapshot.networks.get(network) is not True
    )
    if missing_networks:
        reasons.append("network_prerequisite_missing")
        gates.append(
            {
                "gate": "network",
                "status": "block",
                "reason_code": "network_prerequisite_missing",
                "evidence": {"missing": missing_networks},
            }
        )
    else:
        gates.append(
            {
                "gate": "network",
                "status": "pass",
                "reason_code": "all_hard_gates_pass",
                "evidence": {"required": list(policy.required_networks)},
            }
        )
    storage = [
        {
            "node": placement.node,
            "free_bytes": snapshot.nodes[placement.node].root_free_bytes,
            "minimum_bytes": placement.minimum_root_free_bytes,
        }
        for placement in policy.placements
    ]
    if any(
        snapshot.nodes[placement.node].root_free_bytes < placement.minimum_root_free_bytes
        for placement in policy.placements
    ):
        reasons.append("storage_floor_breached")
        storage_status = "block"
        storage_reason = "storage_floor_breached"
    else:
        storage_status = "pass"
        storage_reason = "all_hard_gates_pass"
    gates.append(
        {
            "gate": "root_storage",
            "status": storage_status,
            "reason_code": storage_reason,
            "evidence": {"nodes": storage},
        }
    )
    swap = [
        {
            "node": node.id,
            "bytes_per_second": node.swap_in_bytes_per_second,
            "maximum_bytes_per_second": catalog.maximum_swap_in_bytes_per_second,
        }
        for node in nodes
    ]
    if any(node.swap_in_bytes_per_second is None for node in nodes):
        reasons.append("swap_evidence_unknown")
        swap_status = "unknown"
        swap_reason = "swap_evidence_unknown"
    elif any(
        node.swap_in_bytes_per_second is not None
        and node.swap_in_bytes_per_second > catalog.maximum_swap_in_bytes_per_second
        for node in nodes
    ):
        reasons.append("swap_pressure")
        swap_status = "block"
        swap_reason = "swap_pressure"
    else:
        swap_status = "pass"
        swap_reason = "all_hard_gates_pass"
    gates.append(
        {
            "gate": "swap_activity",
            "status": swap_status,
            "reason_code": swap_reason,
            "evidence": {"nodes": swap},
        }
    )
    locked = sorted(
        member_id
        for member_id in policy.cohort
        if snapshot.guests.get(member_id) and snapshot.guests[member_id].locked
    )
    if locked:
        reasons.append("guest_locked")
        gates.append(
            {
                "gate": "guest_locks",
                "status": "block",
                "reason_code": "guest_locked",
                "evidence": {"members": locked},
            }
        )
    else:
        gates.append(
            {
                "gate": "guest_locks",
                "status": "pass",
                "reason_code": "all_hard_gates_pass",
                "evidence": {"members": []},
            }
        )
    if not snapshot.controllers.get(policy.controller, False):
        reasons.append("controller_unhealthy")
        controller_status = "block"
        controller_reason = "controller_unhealthy"
    else:
        controller_status = "pass"
        controller_reason = "all_hard_gates_pass"
    gates.append(
        {
            "gate": "controller",
            "status": controller_status,
            "reason_code": controller_reason,
            "evidence": {"controller": policy.controller},
        }
    )
    return reasons, gates


@dataclass(frozen=True, slots=True)
class DonorCandidate:
    donor_set: DonorSet
    stopped_guest_ids: frozenset[str]
    donor_states: tuple[tuple[str, str], ...]
    freed_configured_bytes: int
    freed_configured_bytes_by_node: tuple[tuple[str, int], ...]
    after: dict[str, CapacityEnvelope]
    rank: tuple[Any, ...]


def _donor_candidates(
    catalog: Catalog,
    snapshot: Snapshot,
    target: EnvironmentPolicy,
) -> tuple[list[DonorCandidate], list[str], list[dict[str, Any]]]:
    candidates: list[DonorCandidate] = []
    rejected_reasons: list[str] = []
    donor_gates: list[dict[str, Any]] = []
    holding_environments = {
        lease.environment_id for lease in snapshot.leases if lease.state in LEASE_HOLDING_STATES
    } | {
        reservation.environment_id
        for reservation in snapshot.reservations
        if reservation.state in RESERVATION_HOLDING_STATES
    }
    target_nodes = {placement.node for placement in target.placements}
    for donor_set in sorted(target.donor_sets, key=lambda candidate: candidate.id):
        set_reasons: list[str] = []
        stopped_ids: set[str] = set()
        donor_states: list[tuple[str, str]] = []
        disruption_count = 0
        for donor_id in donor_set.donors:
            donor = catalog.environments[donor_id]
            state, state_reasons = environment_state(donor, snapshot)
            donor_states.append((donor_id, state))
            if state_reasons or state not in {"running", "stopped"}:
                set_reasons.append("donor_set_unavailable")
                continue
            if target.id not in donor.can_donate_to or donor.environment_class == "core":
                set_reasons.append("donor_set_unavailable")
                continue
            members = [snapshot.guests.get(member) for member in donor.cohort]
            if any(member is None for member in members) or any(
                member
                and (member.core_protected or member.gpu_affine or member.node not in target_nodes)
                for member in members
            ):
                set_reasons.append("donor_set_unavailable")
                continue
            if donor_id in holding_environments:
                set_reasons.append("donor_set_unavailable")
                continue
            if donor_set.requires_fresh_backup or donor.backup_required:
                backup = snapshot.backups.get(donor_id)
                if backup is None or backup.state == "unknown":
                    set_reasons.append("backup_unknown")
                    continue
                if backup.state != "fresh":
                    set_reasons.append("backup_stale")
                    continue
            if state == "running":
                disruption_count += 1
                stopped_ids.update(member.id for member in members if member is not None)
        if set_reasons:
            rejected_reasons.extend(set_reasons)
            donor_gates.append(
                {
                    "gate": "donor_set",
                    "status": "block",
                    "reason_code": _ordered_reasons(set_reasons)[0],
                    "evidence": {
                        "donor_set_id": donor_set.id,
                        "donors": list(donor_set.donors),
                    },
                }
            )
            continue
        try:
            _before, after = _policy_capacity(
                snapshot,
                target,
                stopped_guest_ids=frozenset(stopped_ids),
            )
            freed = _bounded_sum(
                snapshot.guests[guest_id].configured_memory_bytes for guest_id in stopped_ids
            )
            freed_by_node = tuple(
                (
                    placement.node,
                    _bounded_sum(
                        snapshot.guests[guest_id].configured_memory_bytes
                        for guest_id in stopped_ids
                        if snapshot.guests[guest_id].node == placement.node
                    ),
                )
                for placement in target.placements
            )
        except EvidenceUnknown:
            rejected_reasons.append("donor_set_unavailable")
            continue
        if any(envelope["guaranteed_headroom_bytes"] < 0 for envelope in after.values()):
            rejected_reasons.append("donor_set_unavailable")
            donor_gates.append(
                {
                    "gate": "donor_set",
                    "status": "block",
                    "reason_code": "donor_set_unavailable",
                    "evidence": {
                        "donor_set_id": donor_set.id,
                        "donors": list(donor_set.donors),
                    },
                }
            )
            continue
        excess = _bounded_sum(envelope["guaranteed_headroom_bytes"] for envelope in after.values())
        candidate = DonorCandidate(
            donor_set=donor_set,
            stopped_guest_ids=frozenset(stopped_ids),
            donor_states=tuple(donor_states),
            freed_configured_bytes=freed,
            freed_configured_bytes_by_node=freed_by_node,
            after=after,
            rank=(
                excess,
                disruption_count,
                donor_set.service_impact,
                donor_set.restore_seconds,
                donor_set.dependencies,
                len(donor_set.donors),
                donor_set.id,
            ),
        )
        candidates.append(candidate)
        donor_gates.append(
            {
                "gate": "donor_set",
                "status": "pass",
                "reason_code": "reviewed_donors_required",
                "evidence": {
                    "donor_set_id": donor_set.id,
                    "donors": list(donor_set.donors),
                    "freed_configured_bytes": freed,
                    "freed_configured_bytes_by_node": [
                        {"node": node, "bytes": value} for node, value in freed_by_node
                    ],
                },
            }
        )
    return (
        sorted(candidates, key=lambda candidate: candidate.rank),
        rejected_reasons,
        donor_gates,
    )


def _action(
    sequence: int,
    adapter: str,
    operation: str,
    target: str,
    *,
    timeout_seconds: int,
    arguments: dict[str, Any],
    compensation: dict[str, str] | None,
) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "adapter": adapter,
        "operation": operation,
        "target": target,
        "arguments": arguments,
        "preconditions": ["snapshot_digest_matches", "target_state_matches"],
        "postconditions": ["controller_reports_converged"],
        "timeout_seconds": timeout_seconds,
        "compensation": compensation,
    }


def _actions(
    policy: EnvironmentPolicy,
    duration: int,
    donor: DonorCandidate | None,
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    sequence = 1
    if donor is not None:
        actions.append(
            _action(
                sequence,
                donor.donor_set.adapter,
                "prepare_reviewed_donors",
                donor.donor_set.id,
                timeout_seconds=600,
                arguments={"donors": list(donor.donor_set.donors)},
                compensation={
                    "adapter": donor.donor_set.adapter,
                    "operation": "restore_changed_donors",
                    "target": donor.donor_set.id,
                },
            )
        )
        sequence += 1
    if policy.environment_class == "exam":
        actions.append(
            _action(
                sequence,
                "broker-state",
                "reserve-exam-slot",
                "global-single-exam",
                timeout_seconds=10,
                arguments={"duration_seconds": duration},
                compensation={
                    "adapter": "broker-state",
                    "operation": "release-exam-slot",
                    "target": "global-single-exam",
                },
            )
        )
        sequence += 1
    for placement in policy.placements:
        actions.append(
            _action(
                sequence,
                "broker-state",
                "reserve-capacity",
                placement.node,
                timeout_seconds=10,
                arguments={
                    "memory_bytes": placement.reserved_memory_bytes,
                    "member_ids": list(placement.cohort),
                },
                compensation={
                    "adapter": "broker-state",
                    "operation": "release-capacity",
                    "target": placement.node,
                },
            )
        )
        sequence += 1
    actions.append(
        _action(
            sequence,
            policy.controller,
            "start-environment",
            policy.id,
            timeout_seconds=900,
            arguments={"lease_duration_seconds": duration},
            compensation={
                "adapter": policy.cleanup_adapter,
                "operation": "cleanup-environment",
                "target": policy.id,
            },
        )
    )
    return actions


def _base_plan(
    catalog: Catalog,
    snapshot: Snapshot,
    request: PlanRequest,
    policy: EnvironmentPolicy,
    *,
    outcome: str,
    reasons: list[str],
    state: str,
    gates: list[dict[str, Any]],
    before: dict[str, CapacityEnvelope] | None,
    after: dict[str, CapacityEnvelope] | None,
    donor: DonorCandidate | None,
    actions: list[dict[str, Any]],
    duration: int,
) -> dict[str, Any]:
    required_observations = [
        snapshot.source_observed_at[source]
        for source in catalog.required_sources
        if source in snapshot.source_observed_at
    ]
    try:
        request_expiry = request.evaluated_at + timedelta(seconds=60)
        evidence_expiry = (
            min(required_observations) + timedelta(seconds=catalog.max_snapshot_age_seconds)
            if len(required_observations) == len(catalog.required_sources)
            else request.evaluated_at
        )
    except OverflowError:
        request_expiry = request.evaluated_at
        evidence_expiry = request.evaluated_at
    valid_until = min(request_expiry, evidence_expiry)
    capacity_nodes: list[dict[str, Any]] = [
        {
            "node": placement.node,
            "reserved_memory_bytes": placement.reserved_memory_bytes,
            "member_ids": list(placement.cohort),
            "before": before.get(placement.node, {}) if before is not None else {},
            "after": after.get(placement.node, {}) if after is not None else {},
        }
        for placement in policy.placements
    ]
    single_node = len(capacity_nodes) == 1
    plan: dict[str, Any] = {
        "schema_version": 1,
        "canonical_profile": catalog.canonical_profile,
        "intent": "start",
        "environment_id": policy.id,
        "lease_id": None,
        "environment_name": policy.display_name,
        "environment_class": policy.environment_class,
        "environment_state": state,
        "outcome": outcome,
        "reason_codes": _ordered_reasons(reasons),
        "evaluated_at": format_time(request.evaluated_at),
        "valid_until": format_time(valid_until),
        "snapshot_revision": snapshot.revision,
        "catalog_digest": catalog.digest,
        "binding_digest": snapshot.binding_digest,
        "capacity": {
            "node": capacity_nodes[0]["node"] if single_node else None,
            "before": capacity_nodes[0]["before"] if single_node else {},
            "after": capacity_nodes[0]["after"] if single_node else {},
            "nodes": capacity_nodes,
            "units": "bytes",
        },
        "coexists_with": sorted(policy.coexists_with),
        "gates": gates,
        "donor_set_id": donor.donor_set.id if donor else None,
        "required_donors": list(donor.donor_set.donors) if donor else [],
        "actions": actions,
        "lease_terms": {
            "class": policy.environment_class,
            "duration_seconds": duration,
            "cleanup_adapter": policy.cleanup_adapter,
        },
        "read_only": True,
    }
    plan["digest"] = digest(plan)
    return plan


def plan_start(
    request: PlanRequest,
    snapshot: Snapshot,
    catalog: Catalog,
) -> dict[str, Any]:
    """Return a total, deterministic start plan from immutable inputs."""

    if snapshot.catalog_digest != catalog.digest:
        raise InputError("snapshot catalog digest does not match the loaded catalog")
    policy = catalog.environments.get(request.environment_id)
    if policy is None or not policy.user_visible:
        raise InputError("requested environment is not allowlisted")
    duration = request.normalized_duration(policy)
    state, state_reasons = environment_state(policy, snapshot)
    freshness_reasons, gates = _freshness(catalog, snapshot, request)
    if freshness_reasons:
        return _base_plan(
            catalog,
            snapshot,
            request,
            policy,
            outcome="unknown",
            reasons=freshness_reasons,
            state=state,
            gates=gates,
            before=None,
            after=None,
            donor=None,
            actions=[],
            duration=duration,
        )
    binding_reasons, binding_gates = _commitment_binding_gate(catalog, snapshot)
    gates.extend(binding_gates)
    if binding_reasons:
        return _base_plan(
            catalog,
            snapshot,
            request,
            policy,
            outcome="unknown",
            reasons=binding_reasons,
            state=state,
            gates=gates,
            before=None,
            after=None,
            donor=None,
            actions=[],
            duration=duration,
        )
    if state == "running":
        return _base_plan(
            catalog,
            snapshot,
            request,
            policy,
            outcome="already_active",
            reasons=["already_active"],
            state=state,
            gates=gates,
            before=None,
            after=None,
            donor=None,
            actions=[],
            duration=duration,
        )
    if state in {"unknown", "partial", "degraded", "starting", "stopping"}:
        return _base_plan(
            catalog,
            snapshot,
            request,
            policy,
            outcome="unknown" if state in {"unknown", "partial", "degraded"} else "blocked",
            reasons=state_reasons or ["environment_state_uncertain"],
            state=state,
            gates=gates,
            before=None,
            after=None,
            donor=None,
            actions=[],
            duration=duration,
        )

    active_states: dict[str, str] = {}
    for candidate in catalog.environments.values():
        candidate_state, _candidate_reasons = environment_state(candidate, snapshot)
        if candidate_state != "stopped":
            active_states[candidate.id] = candidate_state
    active_leases = _holding_exam_leases(snapshot)
    if policy.environment_class == "exam":
        managed_envs = {lease.environment_id for lease in active_leases}
        unmanaged = sorted(
            environment_id
            for environment_id, candidate_state in active_states.items()
            if catalog.environments[environment_id].environment_class == "exam"
            and candidate_state != "stopped"
            and environment_id not in managed_envs
        )
        if unmanaged:
            gates.append(
                {
                    "gate": "single_exam",
                    "status": "block",
                    "reason_code": "unmanaged_exam_active",
                    "evidence": {"active_environments": unmanaged},
                }
            )
            return _base_plan(
                catalog,
                snapshot,
                request,
                policy,
                outcome="blocked",
                reasons=["unmanaged_exam_active"],
                state=state,
                gates=gates,
                before=None,
                after=None,
                donor=None,
                actions=[],
                duration=duration,
            )
        if active_leases:
            holders = sorted({lease.environment_id for lease in active_leases})
            reasons = ["exam_slot_occupied"]
            if any(
                holder in policy.shares_cohort_with or holder in policy.exclusive_with
                for holder in holders
            ):
                reasons.append("shared_cohort_active")
            gates.append(
                {
                    "gate": "single_exam",
                    "status": "queue",
                    "reason_code": "exam_slot_occupied",
                    "evidence": {"holders": holders},
                }
            )
            return _base_plan(
                catalog,
                snapshot,
                request,
                policy,
                outcome="queued_exclusivity",
                reasons=reasons,
                state=state,
                gates=gates,
                before=None,
                after=None,
                donor=None,
                actions=[],
                duration=duration,
            )
    exclusive_active = sorted(
        environment_id
        for environment_id in policy.exclusive_with
        if active_states.get(environment_id) not in {None, "stopped"}
    )
    if exclusive_active:
        gates.append(
            {
                "gate": "environment_exclusivity",
                "status": "block",
                "reason_code": "exclusive_environment_active",
                "evidence": {"active_environments": exclusive_active},
            }
        )
        return _base_plan(
            catalog,
            snapshot,
            request,
            policy,
            outcome="blocked",
            reasons=["exclusive_environment_active"],
            state=state,
            gates=gates,
            before=None,
            after=None,
            donor=None,
            actions=[],
            duration=duration,
        )

    hard_reasons, hard_gates = _hard_gates(catalog, snapshot, policy)
    gates.extend(hard_gates)
    if hard_reasons:
        return _base_plan(
            catalog,
            snapshot,
            request,
            policy,
            outcome=("unknown" if "swap_evidence_unknown" in hard_reasons else "blocked"),
            reasons=hard_reasons,
            state=state,
            gates=gates,
            before=None,
            after=None,
            donor=None,
            actions=[],
            duration=duration,
        )
    try:
        before, after = _policy_capacity(snapshot, policy)
    except EvidenceUnknown:
        return _base_plan(
            catalog,
            snapshot,
            request,
            policy,
            outcome="unknown",
            reasons=["capacity_arithmetic_invalid"],
            state=state,
            gates=gates,
            before=None,
            after=None,
            donor=None,
            actions=[],
            duration=duration,
        )
    if all(envelope["guaranteed_headroom_bytes"] >= 0 for envelope in after.values()):
        gates.append(
            {
                "gate": "conservative_capacity",
                "status": "pass",
                "reason_code": "all_hard_gates_pass",
                "evidence": {
                    "nodes": [
                        {
                            "node": node,
                            "headroom_bytes": envelope["guaranteed_headroom_bytes"],
                        }
                        for node, envelope in sorted(after.items())
                    ]
                },
            }
        )
        return _base_plan(
            catalog,
            snapshot,
            request,
            policy,
            outcome="safe_now",
            reasons=["all_hard_gates_pass"],
            state=state,
            gates=gates,
            before=before,
            after=after,
            donor=None,
            actions=_actions(policy, duration, None),
            duration=duration,
        )

    candidates, donor_reasons, donor_gates = _donor_candidates(catalog, snapshot, policy)
    gates.extend(donor_gates)
    if candidates:
        selected = candidates[0]
        gates.append(
            {
                "gate": "conservative_capacity",
                "status": "conditional",
                "reason_code": "reviewed_donors_required",
                "evidence": {
                    "nodes": [
                        {
                            "node": node,
                            "headroom_bytes": envelope["guaranteed_headroom_bytes"],
                        }
                        for node, envelope in sorted(selected.after.items())
                    ],
                    "donor_set_id": selected.donor_set.id,
                },
            }
        )
        return _base_plan(
            catalog,
            snapshot,
            request,
            policy,
            outcome="safe_with_donors",
            reasons=["capacity_conservative_shortfall", "reviewed_donors_required"],
            state=state,
            gates=gates,
            before=before,
            after=selected.after,
            donor=selected,
            actions=_actions(policy, duration, selected),
            duration=duration,
        )
    reasons = ["capacity_conservative_shortfall"]
    reasons.extend(donor_reasons or (["donor_set_unavailable"] if policy.donor_sets else []))
    if all(envelope["observed_headroom_bytes"] >= 0 for envelope in after.values()):
        reasons.append("capacity_observed_only")
    gates.append(
        {
            "gate": "conservative_capacity",
            "status": "block",
            "reason_code": "capacity_conservative_shortfall",
            "evidence": {
                "nodes": [
                    {
                        "node": node,
                        "guaranteed_headroom_bytes": envelope["guaranteed_headroom_bytes"],
                        "observed_headroom_bytes": envelope["observed_headroom_bytes"],
                    }
                    for node, envelope in sorted(after.items())
                ]
            },
        }
    )
    return _base_plan(
        catalog,
        snapshot,
        request,
        policy,
        outcome="blocked",
        reasons=reasons,
        state=state,
        gates=gates,
        before=before,
        after=after,
        donor=None,
        actions=[],
        duration=duration,
    )


def build_overview(
    snapshot: Snapshot,
    catalog: Catalog,
    *,
    evaluated_at: Any,
    mode: str = "synthetic-read-only",
) -> dict[str, Any]:
    """Build the entire dashboard view from one immutable snapshot revision."""

    if mode not in {"synthetic-read-only", "live-read-only"}:
        raise InputError("overview mode is unsupported")

    requests = [
        PlanRequest.create(policy.id, evaluated_at)
        for policy in sorted(catalog.environments.values(), key=lambda item: item.id)
        if policy.user_visible
    ]
    plans = [plan_start(request, snapshot, catalog) for request in requests]
    environments = [
        {
            "id": plan["environment_id"],
            "display_name": plan["environment_name"],
            "class": plan["environment_class"],
            "state": plan["environment_state"],
            "outcome": plan["outcome"],
            "reason_codes": plan["reason_codes"],
            "coexists_with": plan["coexists_with"],
            "required_donors": plan["required_donors"],
            "reservation_seconds": plan["lease_terms"]["duration_seconds"],
            "plan_digest": plan["digest"],
        }
        for plan in plans
    ]
    freshness_request = (
        requests[0]
        if requests
        else PlanRequest.create(
            min(catalog.environments),
            evaluated_at,
        )
    )
    freshness_reasons, _gates = _freshness(
        catalog,
        snapshot,
        freshness_request,
    )
    nodes: list[dict[str, Any]] = []
    for node in sorted(snapshot.nodes.values(), key=lambda item: item.id):
        envelope: CapacityEnvelope | dict[str, Any]
        try:
            envelope = node_envelope(snapshot, node.id)
            status = "unknown" if freshness_reasons else "current"
        except EvidenceUnknown:
            envelope = {}
            status = "unknown"
        nodes.append(
            {
                "id": node.id,
                "status": status,
                "envelope": envelope,
            }
        )
    outcome_counts = {
        outcome: sum(1 for plan in plans if plan["outcome"] == outcome)
        for outcome in sorted(OUTCOMES)
    }
    return {
        "ok": True,
        "schema_version": 1,
        "mode": mode,
        "evaluated_at": format_time(evaluated_at),
        "generated_at": format_time(snapshot.generated_at),
        "snapshot_revision": snapshot.revision,
        "snapshot_status": "unknown" if freshness_reasons else "current",
        "snapshot_reason_codes": _ordered_reasons(freshness_reasons),
        "summary": {
            "managed_environments": len(environments),
            "outcomes": outcome_counts,
            "mutations_enabled": False,
        },
        "active_exam": active_exam_summary(catalog, snapshot),
        "environments": environments,
        "nodes": nodes,
    }
