"""Strict immutable inputs for the pure capacity planner."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from .canonical import digest

MAX_I64 = 2**63 - 1
ENV_STATES = frozenset({"stopped", "starting", "running", "stopping", "degraded", "unknown"})
LEASE_HOLDING_STATES = frozenset(
    {"reserved", "activating", "active", "cleanup_due", "releasing", "cleanup_failed"}
)
RESERVATION_HOLDING_STATES = LEASE_HOLDING_STATES
ENV_CLASSES = frozenset({"exam", "application", "core"})
BACKUP_STATES = frozenset({"fresh", "stale", "unknown", "not_required"})
IDENTIFIER = re.compile(r"\A[a-z0-9][a-z0-9-]{0,63}\Z", re.ASCII)


class InputError(ValueError):
    """A policy or snapshot violates its exact public schema."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise InputError(f"{label} has unexpected or missing fields")
    return value


def _exact_with_optional(
    value: Any,
    required: set[str],
    optional: set[str],
    label: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or not required <= set(value)
        or not set(value) <= required | optional
    ):
        raise InputError(f"{label} has unexpected or missing fields")
    return value


def _string(value: Any, label: str, *, maximum: int = 120) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise InputError(f"{label} must be bounded non-empty text")
    if any(ord(char) < 0x20 for char in value):
        raise InputError(f"{label} contains a control character")
    return value


def _identifier(value: Any, label: str) -> str:
    text = _string(value, label, maximum=64)
    if not IDENTIFIER.fullmatch(text):
        raise InputError(f"{label} must be a lowercase semantic alias")
    return text


def _digest(value: Any, label: str) -> str:
    text = _string(value, label, maximum=71)
    prefix = "sha256:"
    encoded = text[len(prefix) :]
    if (
        not text.startswith(prefix)
        or len(encoded) != 64
        or any(char not in "0123456789abcdef" for char in encoded)
    ):
        raise InputError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _integer(value: Any, label: str, *, minimum: int = 0, maximum: int = MAX_I64) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise InputError(f"{label} is outside its integer range")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise InputError(f"{label} must be a boolean")
    return value


def _identifiers(value: Any, label: str, *, maximum: int = 64) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise InputError(f"{label} must be a bounded list")
    output = tuple(_identifier(item, f"{label} item") for item in value)
    if len(set(output)) != len(output):
        raise InputError(f"{label} contains duplicates")
    return output


def parse_time(value: Any, label: str) -> datetime:
    text = _string(value, label, maximum=40)
    if not text.endswith("Z"):
        raise InputError(f"{label} must be UTC with a Z suffix")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise InputError(f"{label} is not RFC 3339 UTC time") from exc
    if parsed.tzinfo != UTC:
        parsed = parsed.astimezone(UTC)
    return parsed


def format_time(value: datetime) -> str:
    if value.tzinfo is None:
        raise InputError("planner time must be timezone-aware")
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class Node:
    id: str
    memory_total_bytes: int
    memory_available_bytes: int
    host_reserve_bytes: int
    ksm_shared_bytes: int
    swap_in_bytes_per_second: int | None
    root_free_bytes: int

    @classmethod
    def from_dict(cls, value: Any) -> "Node":
        item = _exact(
            value,
            {
                "id",
                "memory_total_bytes",
                "memory_available_bytes",
                "host_reserve_bytes",
                "ksm_shared_bytes",
                "swap_in_bytes_per_second",
                "root_free_bytes",
            },
            "node",
        )
        node = cls(
            id=_identifier(item["id"], "node id"),
            memory_total_bytes=_integer(item["memory_total_bytes"], "node total memory", minimum=1),
            memory_available_bytes=_integer(
                item["memory_available_bytes"], "node available memory"
            ),
            host_reserve_bytes=_integer(item["host_reserve_bytes"], "node host reserve"),
            ksm_shared_bytes=_integer(item["ksm_shared_bytes"], "node KSM shared memory"),
            swap_in_bytes_per_second=(
                None
                if item["swap_in_bytes_per_second"] is None
                else _integer(item["swap_in_bytes_per_second"], "node swap rate")
            ),
            root_free_bytes=_integer(item["root_free_bytes"], "node root free bytes"),
        )
        if node.memory_available_bytes > node.memory_total_bytes:
            raise InputError("node available memory exceeds physical memory")
        if node.host_reserve_bytes >= node.memory_total_bytes:
            raise InputError("node reserve consumes all physical memory")
        return node


@dataclass(frozen=True, slots=True)
class Guest:
    id: str
    node: str
    configured_memory_bytes: int
    observed_memory_bytes: int
    state: str
    owner_environment: str
    core_protected: bool
    gpu_affine: bool
    locked: bool

    @classmethod
    def from_dict(cls, value: Any) -> "Guest":
        item = _exact(
            value,
            {
                "id",
                "node",
                "configured_memory_bytes",
                "observed_memory_bytes",
                "state",
                "owner_environment",
                "core_protected",
                "gpu_affine",
                "locked",
            },
            "guest",
        )
        state = _string(item["state"], "guest state", maximum=20)
        if state not in ENV_STATES:
            raise InputError("guest state is unsupported")
        guest = cls(
            id=_identifier(item["id"], "guest id"),
            node=_identifier(item["node"], "guest node"),
            configured_memory_bytes=_integer(
                item["configured_memory_bytes"], "guest configured memory", minimum=1
            ),
            observed_memory_bytes=_integer(item["observed_memory_bytes"], "guest observed memory"),
            state=state,
            owner_environment=_identifier(item["owner_environment"], "guest owner"),
            core_protected=_boolean(item["core_protected"], "guest core protection"),
            gpu_affine=_boolean(item["gpu_affine"], "guest GPU affinity"),
            locked=_boolean(item["locked"], "guest lock"),
        )
        if guest.observed_memory_bytes > guest.configured_memory_bytes:
            raise InputError("guest observed memory exceeds configured maximum")
        return guest


@dataclass(frozen=True, slots=True)
class DonorSet:
    id: str
    donors: tuple[str, ...]
    adapter: str
    requires_fresh_backup: bool
    service_impact: int
    restore_seconds: int
    dependencies: int

    @classmethod
    def from_dict(cls, value: Any) -> "DonorSet":
        item = _exact(
            value,
            {
                "id",
                "donors",
                "adapter",
                "requires_fresh_backup",
                "service_impact",
                "restore_seconds",
                "dependencies",
            },
            "donor set",
        )
        donors = _identifiers(item["donors"], "donor set donors", maximum=16)
        if not donors:
            raise InputError("donor set must contain at least one reviewed donor")
        return cls(
            id=_identifier(item["id"], "donor set id"),
            donors=donors,
            adapter=_identifier(item["adapter"], "donor adapter"),
            requires_fresh_backup=_boolean(
                item["requires_fresh_backup"], "donor backup requirement"
            ),
            service_impact=_integer(item["service_impact"], "donor service impact", maximum=100),
            restore_seconds=_integer(
                item["restore_seconds"], "donor restore seconds", maximum=86_400
            ),
            dependencies=_integer(item["dependencies"], "donor dependency count", maximum=100),
        )


@dataclass(frozen=True, slots=True)
class EnvironmentPlacement:
    node: str
    reserved_memory_bytes: int
    minimum_root_free_bytes: int
    cohort: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: Any) -> "EnvironmentPlacement":
        item = _exact(
            value,
            {"node", "reserved_memory_bytes", "minimum_root_free_bytes", "cohort"},
            "environment placement",
        )
        placement = cls(
            node=_identifier(item["node"], "placement node"),
            reserved_memory_bytes=_integer(
                item["reserved_memory_bytes"],
                "placement memory reserve",
                minimum=1,
            ),
            minimum_root_free_bytes=_integer(
                item["minimum_root_free_bytes"],
                "placement root storage floor",
            ),
            cohort=_identifiers(item["cohort"], "placement cohort", maximum=64),
        )
        if not placement.cohort:
            raise InputError("environment placement cohort cannot be empty")
        return placement


@dataclass(frozen=True, slots=True)
class EnvironmentPolicy:
    id: str
    display_name: str
    environment_class: str
    user_visible: bool
    host_affinity: str
    reserved_memory_bytes: int
    minimum_root_free_bytes: int
    cohort: tuple[str, ...]
    placements: tuple[EnvironmentPlacement, ...]
    exclusive_with: tuple[str, ...]
    shares_cohort_with: tuple[str, ...]
    required_networks: tuple[str, ...]
    can_donate_to: tuple[str, ...]
    coexists_with: tuple[str, ...]
    controller: str
    cleanup_adapter: str
    default_lease_seconds: int
    maximum_lease_seconds: int
    backup_required: bool
    donor_sets: tuple[DonorSet, ...]

    @classmethod
    def from_dict(cls, value: Any) -> "EnvironmentPolicy":
        required = {
            "id",
            "display_name",
            "class",
            "user_visible",
            "host_affinity",
            "reserved_memory_bytes",
            "minimum_root_free_bytes",
            "cohort",
            "exclusive_with",
            "shares_cohort_with",
            "required_networks",
            "can_donate_to",
            "coexists_with",
            "controller",
            "cleanup_adapter",
            "default_lease_seconds",
            "maximum_lease_seconds",
            "backup_required",
            "donor_sets",
        }
        item = _exact_with_optional(
            value,
            required,
            {"placements"},
            "environment policy",
        )
        environment_class = _string(item["class"], "environment class", maximum=20)
        if environment_class not in ENV_CLASSES:
            raise InputError("environment class is unsupported")
        raw_sets = item["donor_sets"]
        if not isinstance(raw_sets, list) or len(raw_sets) > 16:
            raise InputError("environment donor sets must be a bounded list")
        donor_sets = tuple(DonorSet.from_dict(raw) for raw in raw_sets)
        if len({candidate.id for candidate in donor_sets}) != len(donor_sets):
            raise InputError("environment donor set IDs must be unique")
        host_affinity = _identifier(item["host_affinity"], "environment host affinity")
        reserved_memory_bytes = _integer(
            item["reserved_memory_bytes"], "environment memory reserve", minimum=1
        )
        minimum_root_free_bytes = _integer(
            item["minimum_root_free_bytes"], "environment root storage floor"
        )
        cohort = _identifiers(item["cohort"], "environment cohort", maximum=64)
        raw_placements = item.get("placements")
        placements: tuple[EnvironmentPlacement, ...]
        if raw_placements is None:
            placements = (
                EnvironmentPlacement(
                    node=host_affinity,
                    reserved_memory_bytes=reserved_memory_bytes,
                    minimum_root_free_bytes=minimum_root_free_bytes,
                    cohort=cohort,
                ),
            )
        else:
            if not isinstance(raw_placements, list) or not 1 <= len(raw_placements) <= 32:
                raise InputError("environment placements must be a bounded non-empty list")
            placements = tuple(
                sorted(
                    (EnvironmentPlacement.from_dict(raw) for raw in raw_placements),
                    key=lambda placement: placement.node,
                )
            )
            if len({placement.node for placement in placements}) != len(placements):
                raise InputError("environment placement nodes must be unique")
            placed_members = [member for placement in placements for member in placement.cohort]
            if len(set(placed_members)) != len(placed_members) or set(placed_members) != set(
                cohort
            ):
                raise InputError("environment placements must partition the exact cohort")
            total_reserved = sum(placement.reserved_memory_bytes for placement in placements)
            if total_reserved > MAX_I64 or total_reserved != reserved_memory_bytes:
                raise InputError("environment placement reserves must equal the aggregate reserve")
            if (
                max(placement.minimum_root_free_bytes for placement in placements)
                != minimum_root_free_bytes
            ):
                raise InputError("environment root floor must equal the maximum placement floor")
            if host_affinity not in {placement.node for placement in placements}:
                raise InputError("environment host affinity must be a placement node")
        policy = cls(
            id=_identifier(item["id"], "environment id"),
            display_name=_string(item["display_name"], "environment display name", maximum=100),
            environment_class=environment_class,
            user_visible=_boolean(item["user_visible"], "environment visibility"),
            host_affinity=host_affinity,
            reserved_memory_bytes=reserved_memory_bytes,
            minimum_root_free_bytes=minimum_root_free_bytes,
            cohort=cohort,
            placements=placements,
            exclusive_with=_identifiers(
                item["exclusive_with"], "environment exclusivity", maximum=64
            ),
            shares_cohort_with=_identifiers(
                item["shares_cohort_with"], "environment shared cohorts", maximum=64
            ),
            required_networks=_identifiers(
                item["required_networks"], "environment required networks", maximum=16
            ),
            can_donate_to=_identifiers(
                item["can_donate_to"], "environment donation allowlist", maximum=32
            ),
            coexists_with=_identifiers(
                item["coexists_with"], "environment coexistence list", maximum=64
            ),
            controller=_identifier(item["controller"], "environment controller"),
            cleanup_adapter=_identifier(item["cleanup_adapter"], "environment cleanup adapter"),
            default_lease_seconds=_integer(
                item["default_lease_seconds"],
                "default lease",
                minimum=60,
                maximum=86_400,
            ),
            maximum_lease_seconds=_integer(
                item["maximum_lease_seconds"],
                "maximum lease",
                minimum=60,
                maximum=172_800,
            ),
            backup_required=_boolean(item["backup_required"], "environment backup requirement"),
            donor_sets=donor_sets,
        )
        if not policy.cohort:
            raise InputError("environment cohort cannot be empty")
        if policy.default_lease_seconds > policy.maximum_lease_seconds:
            raise InputError("default lease exceeds maximum lease")
        return policy

    def placement_for_member(self, member_id: str) -> EnvironmentPlacement | None:
        for placement in self.placements:
            if member_id in placement.cohort:
                return placement
        return None


@dataclass(frozen=True, slots=True)
class Catalog:
    schema_version: int
    canonical_profile: str
    max_snapshot_age_seconds: int
    max_source_skew_seconds: int
    maximum_swap_in_bytes_per_second: int
    required_sources: tuple[str, ...]
    environments: Mapping[str, EnvironmentPolicy]
    digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "environments", MappingProxyType(dict(self.environments)))

    @classmethod
    def from_dict(cls, value: Any) -> "Catalog":
        item = _exact(
            value,
            {
                "schema_version",
                "canonical_profile",
                "max_snapshot_age_seconds",
                "max_source_skew_seconds",
                "maximum_swap_in_bytes_per_second",
                "required_sources",
                "environments",
            },
            "policy catalog",
        )
        if _integer(item["schema_version"], "policy schema", minimum=1, maximum=1) != 1:
            raise InputError("unsupported policy schema")
        profile = _string(item["canonical_profile"], "canonical profile", maximum=40)
        if profile != "broker-cjson-v1":
            raise InputError("unsupported canonical profile")
        raw_environments = item["environments"]
        if not isinstance(raw_environments, list) or not 1 <= len(raw_environments) <= 128:
            raise InputError("policy environments must be a bounded non-empty list")
        policies = [EnvironmentPolicy.from_dict(raw) for raw in raw_environments]
        environments = {policy.id: policy for policy in policies}
        if len(environments) != len(policies):
            raise InputError("environment IDs must be unique")
        catalog = cls(
            schema_version=1,
            canonical_profile=profile,
            max_snapshot_age_seconds=_integer(
                item["max_snapshot_age_seconds"],
                "maximum snapshot age",
                minimum=1,
                maximum=3600,
            ),
            max_source_skew_seconds=_integer(
                item["max_source_skew_seconds"], "maximum source skew", maximum=600
            ),
            maximum_swap_in_bytes_per_second=_integer(
                item["maximum_swap_in_bytes_per_second"], "maximum swap rate"
            ),
            required_sources=_identifiers(item["required_sources"], "required sources", maximum=16),
            environments=environments,
            digest=digest(item),
        )
        if not catalog.required_sources:
            raise InputError("at least one source is required")
        for policy in policies:
            if any(placement.node == policy.id for placement in policy.placements):
                raise InputError("environment host affinity cannot reference itself")
            references = (
                policy.exclusive_with
                + policy.shares_cohort_with
                + policy.can_donate_to
                + policy.coexists_with
            )
            if any(reference not in environments for reference in references):
                raise InputError(f"environment {policy.id} references an unknown environment")
            if policy.id in policy.exclusive_with or policy.id in policy.shares_cohort_with:
                raise InputError(f"environment {policy.id} cannot conflict with itself")
            if policy.id in policy.can_donate_to:
                raise InputError(f"environment {policy.id} cannot donate to itself")
            for peer_id in policy.exclusive_with:
                if policy.id not in environments[peer_id].exclusive_with:
                    raise InputError("environment exclusivity must be reciprocal")
            for peer_id in policy.shares_cohort_with:
                peer = environments[peer_id]
                policy_placement = {
                    member: placement.node
                    for placement in policy.placements
                    for member in placement.cohort
                }
                peer_placement = {
                    member: placement.node
                    for placement in peer.placements
                    for member in placement.cohort
                }
                if (
                    policy.id not in peer.shares_cohort_with
                    or set(policy.cohort) != set(peer.cohort)
                    or policy_placement != peer_placement
                ):
                    raise InputError("shared cohorts must be reciprocal and exact")
            for donor_set in policy.donor_sets:
                if any(donor not in environments for donor in donor_set.donors):
                    raise InputError(f"donor set {donor_set.id} references an unknown environment")
                if policy.id in donor_set.donors:
                    raise InputError(f"donor set {donor_set.id} cannot include its target")
        return catalog


@dataclass(frozen=True, slots=True)
class Lease:
    id: str
    environment_id: str
    lease_class: str
    state: str
    expires_at: datetime

    @classmethod
    def from_dict(cls, value: Any) -> "Lease":
        item = _exact(value, {"id", "environment_id", "class", "state", "expires_at"}, "lease")
        lease_class = _string(item["class"], "lease class", maximum=20)
        if lease_class not in ENV_CLASSES:
            raise InputError("lease class is unsupported")
        state = _string(item["state"], "lease state", maximum=24)
        if state not in LEASE_HOLDING_STATES | {
            "released",
            "cancelled",
            "expired_unstarted",
        }:
            raise InputError("lease state is unsupported")
        return cls(
            id=_identifier(item["id"], "lease id"),
            environment_id=_identifier(item["environment_id"], "lease environment"),
            lease_class=lease_class,
            state=state,
            expires_at=parse_time(item["expires_at"], "lease expiry"),
        )


@dataclass(frozen=True, slots=True)
class Reservation:
    environment_id: str
    node: str
    reserved_bytes: int
    member_ids: tuple[str, ...]
    state: str

    @classmethod
    def from_dict(cls, value: Any) -> "Reservation":
        item = _exact(
            value,
            {"environment_id", "node", "reserved_bytes", "member_ids", "state"},
            "reservation",
        )
        state = _string(item["state"], "reservation state", maximum=24)
        if state not in RESERVATION_HOLDING_STATES | {"released", "cancelled"}:
            raise InputError("reservation state is unsupported")
        members = _identifiers(item["member_ids"], "reservation members", maximum=64)
        if not members:
            raise InputError("reservation members cannot be empty")
        return cls(
            environment_id=_identifier(item["environment_id"], "reservation environment"),
            node=_identifier(item["node"], "reservation node"),
            reserved_bytes=_integer(item["reserved_bytes"], "reservation bytes", minimum=1),
            member_ids=members,
            state=state,
        )


@dataclass(frozen=True, slots=True)
class BackupObservation:
    environment_id: str
    state: str
    age_seconds: int | None

    @classmethod
    def from_dict(cls, value: Any) -> "BackupObservation":
        item = _exact(value, {"environment_id", "state", "age_seconds"}, "backup observation")
        state = _string(item["state"], "backup state", maximum=20)
        if state not in BACKUP_STATES:
            raise InputError("backup state is unsupported")
        age_raw = item["age_seconds"]
        age = None if age_raw is None else _integer(age_raw, "backup age")
        if state == "fresh" and age is None:
            raise InputError("fresh backup evidence needs an age")
        return cls(
            environment_id=_identifier(item["environment_id"], "backup environment"),
            state=state,
            age_seconds=age,
        )


@dataclass(frozen=True, slots=True)
class Snapshot:
    schema_version: int
    revision: str
    generated_at: datetime
    demo_evaluation_time: datetime
    observed_at: datetime
    collected_at: datetime
    source_observed_at: Mapping[str, datetime]
    nodes: Mapping[str, Node]
    guests: Mapping[str, Guest]
    networks: Mapping[str, bool]
    controllers: Mapping[str, bool]
    backups: Mapping[str, BackupObservation]
    leases: tuple[Lease, ...]
    reservations: tuple[Reservation, ...]
    catalog_digest: str
    binding_digest: str

    def __post_init__(self) -> None:
        for field_name in (
            "source_observed_at",
            "nodes",
            "guests",
            "networks",
            "controllers",
            "backups",
        ):
            object.__setattr__(
                self,
                field_name,
                MappingProxyType(dict(getattr(self, field_name))),
            )

    @classmethod
    def from_dict(cls, value: Any) -> "Snapshot":
        item = _exact(
            value,
            {
                "schema_version",
                "revision",
                "generated_at",
                "demo_evaluation_time",
                "observed_at",
                "collected_at",
                "source_observed_at",
                "nodes",
                "guests",
                "networks",
                "controllers",
                "backups",
                "leases",
                "reservations",
                "catalog_digest",
                "binding_digest",
            },
            "snapshot",
        )
        if _integer(item["schema_version"], "snapshot schema", minimum=1, maximum=1) != 1:
            raise InputError("unsupported snapshot schema")
        raw_sources = item["source_observed_at"]
        if not isinstance(raw_sources, dict) or len(raw_sources) > 32:
            raise InputError("snapshot sources must be a bounded object")
        sources = {
            _identifier(key, "snapshot source"): parse_time(value, f"source {key} time")
            for key, value in raw_sources.items()
        }
        raw_nodes = item["nodes"]
        raw_guests = item["guests"]
        raw_networks = item["networks"]
        raw_controllers = item["controllers"]
        raw_backups = item["backups"]
        raw_leases = item["leases"]
        raw_reservations = item["reservations"]
        for raw, label, limit in (
            (raw_nodes, "nodes", 32),
            (raw_guests, "guests", 512),
            (raw_backups, "backups", 256),
            (raw_leases, "leases", 256),
            (raw_reservations, "reservations", 256),
        ):
            if not isinstance(raw, list) or len(raw) > limit:
                raise InputError(f"snapshot {label} must be a bounded list")
        if not isinstance(raw_networks, dict) or len(raw_networks) > 128:
            raise InputError("snapshot networks must be a bounded object")
        if not isinstance(raw_controllers, dict) or len(raw_controllers) > 128:
            raise InputError("snapshot controllers must be a bounded object")
        nodes_list = [Node.from_dict(raw) for raw in raw_nodes]
        guests_list = [Guest.from_dict(raw) for raw in raw_guests]
        backups_list = [BackupObservation.from_dict(raw) for raw in raw_backups]
        leases = tuple(Lease.from_dict(raw) for raw in raw_leases)
        reservations = tuple(Reservation.from_dict(raw) for raw in raw_reservations)
        nodes = {node.id: node for node in nodes_list}
        guests = {guest.id: guest for guest in guests_list}
        backups = {backup.environment_id: backup for backup in backups_list}
        if len(nodes) != len(nodes_list) or len(guests) != len(guests_list):
            raise InputError("snapshot aliases must be unique")
        if len(backups) != len(backups_list):
            raise InputError("backup observations must be unique per environment")
        if len({lease.id for lease in leases}) != len(leases):
            raise InputError("lease IDs must be unique")
        if any(guest.node not in nodes for guest in guests.values()):
            raise InputError("snapshot guest references an unknown node")
        networks = {
            _identifier(key, "network id"): _boolean(value, f"network {key} state")
            for key, value in raw_networks.items()
        }
        controllers = {
            _identifier(key, "controller id"): _boolean(value, f"controller {key} state")
            for key, value in raw_controllers.items()
        }
        return cls(
            schema_version=1,
            revision=_identifier(item["revision"], "snapshot revision"),
            generated_at=parse_time(item["generated_at"], "snapshot generation time"),
            demo_evaluation_time=parse_time(item["demo_evaluation_time"], "demo evaluation time"),
            observed_at=parse_time(item["observed_at"], "snapshot observation time"),
            collected_at=parse_time(item["collected_at"], "snapshot collection time"),
            source_observed_at=sources,
            nodes=nodes,
            guests=guests,
            networks=networks,
            controllers=controllers,
            backups=backups,
            leases=leases,
            reservations=reservations,
            catalog_digest=_digest(item["catalog_digest"], "snapshot catalog digest"),
            binding_digest=_digest(item["binding_digest"], "snapshot binding digest"),
        )


@dataclass(frozen=True, slots=True)
class PlanRequest:
    environment_id: str
    evaluated_at: datetime
    duration_seconds: int | None = None

    def normalized_duration(self, policy: EnvironmentPolicy) -> int:
        if self.duration_seconds is None:
            return policy.default_lease_seconds
        return _integer(
            self.duration_seconds,
            "requested duration",
            minimum=60,
            maximum=policy.maximum_lease_seconds,
        )

    @classmethod
    def create(
        cls, environment_id: Any, evaluated_at: datetime, duration_seconds: Any = None
    ) -> "PlanRequest":
        if not isinstance(evaluated_at, datetime) or evaluated_at.tzinfo is None:
            raise InputError("evaluation time must be timezone-aware")
        duration = (
            None
            if duration_seconds is None
            else _integer(duration_seconds, "requested duration", minimum=60, maximum=172_800)
        )
        return cls(
            environment_id=_identifier(environment_id, "requested environment"),
            evaluated_at=evaluated_at.astimezone(UTC),
            duration_seconds=duration,
        )
