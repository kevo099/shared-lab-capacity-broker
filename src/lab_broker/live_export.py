"""Credential-side Proxmox collector and sanitized atomic snapshot exporter.

This module runs on the collection host. The resulting snapshot contains only
reviewed semantic aliases and bounded evidence; source node names, VMIDs,
credentials, and raw Proxmox payloads never cross the export boundary.
"""

from __future__ import annotations

import http.client
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import quote

from .domain.canonical import digest, strict_json_loads
from .domain.types import (
    LEASE_HOLDING_STATES,
    Catalog,
    InputError,
    Snapshot,
    format_time,
    parse_time,
)
from .fixtures import read_json_file, write_atomic_json

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_I64 = 2**63 - 1
SOURCE_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SEMANTIC_ID = re.compile(r"\A[a-z0-9][a-z0-9-]{0,63}\Z")
NODE_TASK_HISTORY_PATH = re.compile(
    r"\A/nodes/[A-Za-z0-9][A-Za-z0-9._-]{0,127}/tasks"
    r"\?limit=([1-9][0-9]{0,2})&typefilter=vzdump\Z"
)
NODE_TASK_LOG_PATH = re.compile(
    r"\A/nodes/(?P<node>[A-Za-z0-9][A-Za-z0-9._-]{0,127})/tasks/"
    r"UPID%3A(?P=node)%3A[0-9A-Fa-f]{8}%3A[0-9A-Fa-f]{8}%3A"
    r"[0-9A-Fa-f]{8}%3Avzdump%3A[A-Za-z0-9._~-]{0,128}%3A"
    r"[A-Za-z0-9._~-]{1,64}%40[A-Za-z0-9._~-]{1,64}%3A/log"
    r"\?limit=([1-9][0-9]{0,3})\Z"
)
MAX_TASK_HISTORY_TOTAL = 1_000_000
MAX_TASK_LOG_ROWS = 5_000
MAX_TASK_LOG_TOTAL = 1_000_000


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise InputError(f"{label} has unexpected or missing fields")
    return value


def _text(value: Any, label: str, *, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise InputError(f"{label} must be bounded non-empty text")
    if any(ord(char) < 0x20 for char in value):
        raise InputError(f"{label} contains a control character")
    return value


def _semantic_id(value: Any, label: str) -> str:
    result = _text(value, label, maximum=64)
    if not SEMANTIC_ID.fullmatch(result):
        raise InputError(f"{label} must be a lowercase semantic alias")
    return result


def _source_name(value: Any, label: str) -> str:
    result = _text(value, label)
    if not SOURCE_NAME.fullmatch(result):
        raise InputError(f"{label} is not a safe source name")
    return result


def _integer(value: Any, label: str, *, minimum: int = 0, maximum: int = MAX_I64) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise InputError(f"{label} is outside its integer range")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise InputError(f"{label} must be a boolean")
    return value


def _semantic_map(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > 128:
        raise InputError(f"{label} must be a bounded object")
    return {_semantic_id(key, f"{label} key"): item for key, item in value.items()}


def _unwrap_pve_envelope(api_path: str, envelope: Any) -> Any:
    """Accept pagination metadata only for exact bounded task and log reads."""

    task_match = NODE_TASK_HISTORY_PATH.fullmatch(api_path)
    log_match = NODE_TASK_LOG_PATH.fullmatch(api_path)
    if task_match is None and log_match is None:
        if not isinstance(envelope, dict) or set(envelope) != {"data"}:
            raise InputError("PVE response envelope is invalid")
        return envelope["data"]

    if not isinstance(envelope, dict) or set(envelope) != {"data", "total"}:
        label = "task-history" if task_match is not None else "task-log"
        raise InputError(f"PVE {label} response envelope is invalid")
    rows = envelope["data"]
    total = envelope["total"]
    if task_match is not None:
        label = "task-history"
        limit = int(task_match.group(1))
        maximum_limit = 256
        maximum_total = MAX_TASK_HISTORY_TOTAL
    else:
        assert log_match is not None
        label = "task-log"
        limit = int(log_match.group(2))
        maximum_limit = MAX_TASK_LOG_ROWS
        maximum_total = MAX_TASK_LOG_TOTAL
    if (
        not 1 <= limit <= maximum_limit
        or not isinstance(rows, list)
        or len(rows) > limit
        or type(total) is not int
        or not len(rows) <= total <= maximum_total
    ):
        raise InputError(f"PVE {label} pagination metadata is invalid")
    return rows


@dataclass(frozen=True, slots=True)
class NodeBinding:
    alias: str
    source_node: str
    host_reserve_bytes: int

    @classmethod
    def from_dict(cls, value: Any) -> "NodeBinding":
        item = _exact(
            value,
            {"alias", "source_node", "host_reserve_bytes"},
            "node binding",
        )
        return cls(
            alias=_semantic_id(item["alias"], "node alias"),
            source_node=_source_name(item["source_node"], "source node"),
            host_reserve_bytes=_integer(
                item["host_reserve_bytes"],
                "host reserve",
                minimum=1,
            ),
        )


@dataclass(frozen=True, slots=True)
class GuestBinding:
    alias: str
    node_alias: str
    source_kind: str
    source_id: int
    owner_environments: tuple[str, ...]
    core_protected: bool
    gpu_affine: bool

    @classmethod
    def from_dict(cls, value: Any) -> "GuestBinding":
        item = _exact(
            value,
            {
                "alias",
                "node_alias",
                "source_kind",
                "source_id",
                "owner_environments",
                "core_protected",
                "gpu_affine",
            },
            "guest binding",
        )
        kind = _text(item["source_kind"], "guest source kind", maximum=8)
        if kind not in {"qemu", "lxc"}:
            raise InputError("guest source kind must be qemu or lxc")
        raw_owners = item["owner_environments"]
        if not isinstance(raw_owners, list) or not 1 <= len(raw_owners) <= 4:
            raise InputError("guest owners must be a bounded non-empty list")
        owners = tuple(_semantic_id(owner, "guest owner") for owner in raw_owners)
        if len(set(owners)) != len(owners):
            raise InputError("guest owners contain duplicates")
        return cls(
            alias=_semantic_id(item["alias"], "guest alias"),
            node_alias=_semantic_id(item["node_alias"], "guest node alias"),
            source_kind=kind,
            source_id=_integer(
                item["source_id"], "guest source ID", minimum=1, maximum=999_999_999
            ),
            owner_environments=owners,
            core_protected=_boolean(item["core_protected"], "guest core protection"),
            gpu_affine=_boolean(item["gpu_affine"], "guest GPU affinity"),
        )


@dataclass(frozen=True, slots=True)
class LiveBindings:
    nodes: tuple[NodeBinding, ...]
    guests: tuple[GuestBinding, ...]
    binding_digest: str

    @classmethod
    def from_dict(cls, value: Any, catalog: Catalog) -> "LiveBindings":
        item = _exact(
            value,
            {"schema_version", "canonical_profile", "nodes", "guests"},
            "live bindings",
        )
        if (
            type(item["schema_version"]) is not int
            or item["schema_version"] != 1
            or item["canonical_profile"] != "broker-cjson-v1"
        ):
            raise InputError("unsupported live binding schema")
        raw_nodes = item["nodes"]
        raw_guests = item["guests"]
        if not isinstance(raw_nodes, list) or not 1 <= len(raw_nodes) <= 32:
            raise InputError("live binding nodes must be a bounded non-empty list")
        if not isinstance(raw_guests, list) or not 1 <= len(raw_guests) <= 512:
            raise InputError("live binding guests must be a bounded non-empty list")
        nodes = tuple(NodeBinding.from_dict(raw) for raw in raw_nodes)
        guests = tuple(GuestBinding.from_dict(raw) for raw in raw_guests)
        if len({node.alias for node in nodes}) != len(nodes) or len(
            {node.source_node for node in nodes}
        ) != len(nodes):
            raise InputError("node bindings must be one-to-one")
        if len({guest.alias for guest in guests}) != len(guests) or len(
            {(guest.source_kind, guest.source_id) for guest in guests}
        ) != len(guests):
            raise InputError("guest bindings must be one-to-one")

        node_aliases = {node.alias for node in nodes}
        required_nodes = {
            placement.node
            for policy in catalog.environments.values()
            for placement in policy.placements
        }
        if node_aliases != required_nodes:
            raise InputError("node bindings must exactly cover policy host affinities")
        if any(guest.node_alias not in node_aliases for guest in guests):
            raise InputError("guest binding references an unknown node alias")
        if any(
            owner not in catalog.environments
            for guest in guests
            for owner in guest.owner_environments
        ):
            raise InputError("guest binding references an unknown owner environment")

        by_alias = {guest.alias: guest for guest in guests}
        managed_members = {
            member for policy in catalog.environments.values() for member in policy.cohort
        }
        if not managed_members <= set(by_alias):
            raise InputError("guest bindings do not cover every managed cohort member")
        for policy in catalog.environments.values():
            permitted_owners = {policy.id, *policy.shares_cohort_with}
            for placement in policy.placements:
                for member_id in placement.cohort:
                    binding = by_alias[member_id]
                    if (
                        binding.node_alias != placement.node
                        or not set(binding.owner_environments) <= permitted_owners
                        or policy.id not in binding.owner_environments
                    ):
                        raise InputError("managed cohort binding conflicts with policy")
        if any(guest.alias not in managed_members and not guest.core_protected for guest in guests):
            raise InputError("inventory-only guests must be core protected")
        return cls(nodes=nodes, guests=guests, binding_digest=digest(item))


@dataclass(frozen=True, slots=True)
class LiveEvidence:
    catalog_digest: str
    source_observed_at: dict[str, datetime]
    node_swap_in_bytes_per_second: dict[str, int | None]
    networks: dict[str, bool]
    controllers: dict[str, bool]
    backups: tuple[dict[str, Any], ...]
    active_owners: dict[str, str]
    exam_lease: dict[str, Any] | None

    @classmethod
    def from_dict(
        cls,
        value: Any,
        catalog: Catalog,
        bindings: LiveBindings,
    ) -> "LiveEvidence":
        item = _exact(
            value,
            {
                "schema_version",
                "catalog_digest",
                "source_observed_at",
                "node_swap_in_bytes_per_second",
                "networks",
                "controllers",
                "backups",
                "active_owners",
                "exam_lease",
            },
            "live evidence",
        )
        if type(item["schema_version"]) is not int or item["schema_version"] != 1:
            raise InputError("unsupported live evidence schema")
        evidence_catalog_digest = _text(
            item["catalog_digest"],
            "evidence catalog digest",
            maximum=71,
        )
        if evidence_catalog_digest != catalog.digest:
            raise InputError("live evidence catalog digest does not match the loaded catalog")
        raw_sources = _semantic_map(item["source_observed_at"], "evidence sources")
        if set(raw_sources) != {"telemetry", "controllers", "backups"}:
            raise InputError("live evidence must timestamp telemetry, controllers, and backups")
        sources = {
            source: parse_time(observed_at, f"{source} observation time")
            for source, observed_at in raw_sources.items()
        }

        raw_swap = _semantic_map(item["node_swap_in_bytes_per_second"], "node swap rates")
        expected_nodes = {node.alias for node in bindings.nodes}
        if set(raw_swap) != expected_nodes:
            raise InputError("swap-rate evidence must exactly cover bound nodes")
        swap = {
            node: None if value is None else _integer(value, f"swap rate for {node}")
            for node, value in raw_swap.items()
        }

        raw_networks = _semantic_map(item["networks"], "network evidence")
        required_networks = {
            network
            for policy in catalog.environments.values()
            for network in policy.required_networks
        }
        if set(raw_networks) != required_networks:
            raise InputError("network evidence must exactly cover declared networks")
        networks = {
            network: _boolean(present, f"network {network} state")
            for network, present in raw_networks.items()
        }

        raw_controllers = _semantic_map(item["controllers"], "controller evidence")
        required_controllers = {policy.controller for policy in catalog.environments.values()}
        if set(raw_controllers) != required_controllers:
            raise InputError("controller evidence must exactly cover declared controllers")
        controllers = {
            controller: _boolean(healthy, f"controller {controller} health")
            for controller, healthy in raw_controllers.items()
        }

        raw_backups = item["backups"]
        if not isinstance(raw_backups, list) or len(raw_backups) > 256:
            raise InputError("backup evidence must be a bounded list")
        backups: list[dict[str, Any]] = []
        seen_backups: set[str] = set()
        for raw in raw_backups:
            backup = _exact(raw, {"environment_id", "state", "age_seconds"}, "backup evidence")
            environment_id = _semantic_id(backup["environment_id"], "backup environment")
            state = _text(backup["state"], "backup state", maximum=20)
            if state not in {"fresh", "stale", "unknown", "not_required"}:
                raise InputError("backup state is unsupported")
            age = backup["age_seconds"]
            if age is not None:
                age = _integer(age, "backup age")
            if state == "fresh" and age is None:
                raise InputError("fresh backup evidence requires an age")
            if environment_id in seen_backups or environment_id not in catalog.environments:
                raise InputError("backup evidence contains an unknown or duplicate environment")
            seen_backups.add(environment_id)
            backups.append({"environment_id": environment_id, "state": state, "age_seconds": age})
        required_backups = {
            policy.id for policy in catalog.environments.values() if policy.backup_required
        }
        if not required_backups <= seen_backups:
            raise InputError("backup evidence does not cover every backup-gated environment")

        raw_owners = _semantic_map(item["active_owners"], "active owner evidence")
        by_guest = {guest.alias: guest for guest in bindings.guests}
        active_owners: dict[str, str] = {}
        for guest_alias, raw_owner in raw_owners.items():
            owner = _semantic_id(raw_owner, f"active owner for {guest_alias}")
            binding = by_guest.get(guest_alias)
            if binding is None or owner not in binding.owner_environments:
                raise InputError("active owner evidence conflicts with bindings")
            active_owners[guest_alias] = owner
        raw_lease = item["exam_lease"]
        exam_lease: dict[str, Any] | None = None
        if raw_lease is not None:
            lease = _exact(
                raw_lease,
                {"environment_id", "state", "expires_at"},
                "exam lease evidence",
            )
            environment_id = _semantic_id(
                lease["environment_id"],
                "exam lease environment",
            )
            state = _text(lease["state"], "exam lease state", maximum=24)
            policy = catalog.environments.get(environment_id)
            if (
                policy is None
                or policy.environment_class != "exam"
                or state not in LEASE_HOLDING_STATES
            ):
                raise InputError("exam lease evidence is not a holding exam commitment")
            exam_lease = {
                "environment_id": environment_id,
                "state": state,
                "expires_at": format_time(parse_time(lease["expires_at"], "exam lease expiry")),
            }
        return cls(
            catalog_digest=evidence_catalog_digest,
            source_observed_at=sources,
            node_swap_in_bytes_per_second=swap,
            networks=networks,
            controllers=controllers,
            backups=tuple(sorted(backups, key=lambda row: row["environment_id"])),
            active_owners=active_owners,
            exam_lease=exam_lease,
        )


class PVEReader(Protocol):
    def get(self, api_path: str) -> Any: ...


class ProxmoxHTTPSReader:
    """Bounded GET-only Proxmox client with no proxy or redirect behavior."""

    def __init__(
        self,
        host: str,
        port: int,
        token_id: str,
        token_secret: str,
        *,
        ca_file: Path | None = None,
        insecure_tls: bool = False,
        request_timeout_seconds: float = 10.0,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if not SOURCE_NAME.fullmatch(host):
            raise InputError("PVE host must be a hostname or address without a URL scheme")
        if type(port) is not int or not 1 <= port <= 65_535:
            raise InputError("PVE port is invalid")
        self.host = host
        self.port = port
        self.token_id = _text(token_id, "PVE token ID", maximum=256)
        self.token_secret = _text(token_secret, "PVE token secret", maximum=512)
        if ca_file is not None and insecure_tls:
            raise InputError("a CA file and insecure TLS are mutually exclusive")
        if insecure_tls:
            self.context = ssl._create_unverified_context()
        else:
            self.context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        if not 0.25 <= request_timeout_seconds <= 60:
            raise InputError("PVE request timeout is outside the supported range")
        self.request_timeout_seconds = request_timeout_seconds
        self.monotonic = monotonic

    @classmethod
    def from_environment(
        cls,
        *,
        port: int = 8006,
        ca_file: Path | None = None,
        insecure_tls: bool = False,
    ) -> "ProxmoxHTTPSReader":
        host = os.environ.get("PVE_HOST", "")
        read_only = {
            "token_id": os.environ.get("PVE_RO_TOKEN_ID", ""),
            "token_secret": os.environ.get("PVE_RO_TOKEN_SECRET", ""),
        }
        if any(read_only.values()) and not all(read_only.values()):
            raise InputError("the PVE_RO_TOKEN_* pair is incomplete")
        values = {"host": host, **read_only}
        if any(not value for value in values.values()):
            raise InputError("PVE_HOST and a complete PVE_RO_TOKEN_* pair are required")
        return cls(
            values["host"],
            port,
            values["token_id"],
            values["token_secret"],
            ca_file=ca_file,
            insecure_tls=insecure_tls,
        )

    def get(self, api_path: str) -> Any:
        if (
            not api_path.startswith("/")
            or ".." in api_path
            or any(char in api_path for char in "\r\n#")
        ):
            raise InputError("PVE API path is invalid")
        deadline = self.monotonic() + self.request_timeout_seconds
        connection = http.client.HTTPSConnection(
            self.host,
            self.port,
            timeout=self.request_timeout_seconds,
            context=self.context,
        )
        try:
            connection.request(
                "GET",
                f"/api2/json{api_path}",
                headers={
                    "Authorization": f"PVEAPIToken={self.token_id}={self.token_secret}",
                    "Accept": "application/json",
                    "User-Agent": "shared-lab-capacity-broker/0.1",
                },
            )
            response = connection.getresponse()
            if response.status != 200:
                raise InputError("PVE returned a non-success response")
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].lower()
            if content_type not in {"application/json", "text/json"}:
                raise InputError("PVE returned an unexpected content type")
            chunks: list[bytes] = []
            size = 0
            while True:
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    raise InputError("PVE response exceeded its wall-clock deadline")
                if connection.sock is not None:
                    connection.sock.settimeout(max(0.001, remaining))
                chunk = response.read1(min(65_536, MAX_RESPONSE_BYTES + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise InputError("PVE response exceeded its size limit")
                chunks.append(chunk)
            envelope = strict_json_loads(b"".join(chunks))
            return _unwrap_pve_envelope(api_path, envelope)
        except InputError:
            raise
        except (
            OSError,
            socket.timeout,
            ssl.SSLError,
            http.client.HTTPException,
            UnicodeError,
            ValueError,
            RecursionError,
        ) as exc:
            raise InputError("PVE read failed") from exc
        finally:
            connection.close()


def _raw_integer(value: Any, label: str, *, minimum: int = 0) -> int:
    return _integer(value, label, minimum=minimum)


def _raw_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{label} must be an object")
    return value


def build_live_snapshot(
    reader: PVEReader,
    bindings: LiveBindings,
    evidence: LiveEvidence,
    catalog: Catalog,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    """Collect, resolve, sanitize, and validate one complete snapshot."""

    node_rows = reader.get("/nodes")
    guest_rows = reader.get("/cluster/resources?type=vm")
    if not isinstance(node_rows, list) or len(node_rows) > 32:
        raise InputError("PVE node inventory is invalid")
    if not isinstance(guest_rows, list) or len(guest_rows) > 4096:
        raise InputError("PVE guest inventory is invalid")
    raw_nodes = [_raw_object(row, "PVE node") for row in node_rows]
    raw_guests = [_raw_object(row, "PVE guest") for row in guest_rows]

    expected_source_nodes = {binding.source_node for binding in bindings.nodes}
    actual_source_nodes = {_source_name(row.get("node"), "PVE node name") for row in raw_nodes}
    if actual_source_nodes != expected_source_nodes:
        raise InputError("PVE node inventory does not exactly match reviewed bindings")

    node_by_alias = {node.alias: node for node in bindings.nodes}
    sanitized_nodes: list[dict[str, Any]] = []
    for node_binding_row in sorted(bindings.nodes, key=lambda row: row.alias):
        matches = [row for row in raw_nodes if row.get("node") == node_binding_row.source_node]
        if len(matches) != 1 or matches[0].get("status") != "online":
            raise InputError("a bound PVE node is missing, duplicated, or offline")
        encoded_node = quote(node_binding_row.source_node, safe="")
        status = _raw_object(reader.get(f"/nodes/{encoded_node}/status"), "PVE node status")
        memory = _raw_object(status.get("memory"), "PVE node memory")
        rootfs = _raw_object(status.get("rootfs"), "PVE node root filesystem")
        ksm = _raw_object(status.get("ksm", {}), "PVE node KSM")
        sanitized_nodes.append(
            {
                "id": node_binding_row.alias,
                "memory_total_bytes": _raw_integer(
                    memory.get("total"), "node total memory", minimum=1
                ),
                "memory_available_bytes": _raw_integer(
                    memory.get("available"), "node available memory"
                ),
                "host_reserve_bytes": node_binding_row.host_reserve_bytes,
                "ksm_shared_bytes": _raw_integer(ksm.get("shared", 0), "node KSM shared memory"),
                "swap_in_bytes_per_second": evidence.node_swap_in_bytes_per_second[
                    node_binding_row.alias
                ],
                "root_free_bytes": _raw_integer(rootfs.get("avail"), "node root free bytes"),
            }
        )

    source_key_by_binding = {
        (guest.source_kind, guest.source_id): guest for guest in bindings.guests
    }
    relevant_raw: dict[tuple[str, int], dict[str, Any]] = {}
    for row in raw_guests:
        if row.get("template") in {1}:
            continue
        source_node = row.get("node")
        if source_node not in expected_source_nodes:
            raise InputError("a guest exists on an unbound node")
        kind = row.get("type")
        source_id = row.get("vmid")
        if kind not in {"qemu", "lxc"} or type(source_id) is not int:
            raise InputError("PVE guest identity is invalid")
        key = (kind, source_id)
        if key in relevant_raw:
            raise InputError("PVE guest identity is duplicated")
        relevant_raw[key] = row
    if set(relevant_raw) != set(source_key_by_binding):
        raise InputError("PVE guest inventory does not exactly match reviewed bindings")

    sanitized_guests: list[dict[str, Any]] = []
    for guest_binding in sorted(bindings.guests, key=lambda row: row.alias):
        row = relevant_raw[(guest_binding.source_kind, guest_binding.source_id)]
        node_binding = node_by_alias[guest_binding.node_alias]
        if row.get("node") != node_binding.source_node:
            raise InputError("a bound guest moved to an unreviewed node")
        raw_state = row.get("status")
        state = raw_state if raw_state in {"running", "stopped"} else "unknown"
        if len(guest_binding.owner_environments) == 1:
            owner = guest_binding.owner_environments[0]
        elif state == "stopped":
            owner = sorted(guest_binding.owner_environments)[0]
        else:
            owner = evidence.active_owners.get(guest_binding.alias, "unresolved")
        configured = _raw_integer(row.get("maxmem"), "guest configured memory", minimum=1)
        raw_observed = (
            0 if state == "stopped" else _raw_integer(row.get("mem"), "guest observed memory")
        )
        # QEMU accounting can include a small amount of process overhead above
        # maxmem. Keep the strict public invariant and never credit that excess:
        # guaranteed admission remains based on configured maxima and node
        # availability, while observed capacity is diagnostic only.
        observed = min(raw_observed, configured)
        raw_lock = row.get("lock")
        if raw_lock is not None and not isinstance(raw_lock, str):
            raise InputError("PVE guest lock evidence is invalid")
        sanitized_guests.append(
            {
                "id": guest_binding.alias,
                "node": guest_binding.node_alias,
                "configured_memory_bytes": configured,
                "observed_memory_bytes": observed,
                "state": state,
                "owner_environment": owner,
                "core_protected": guest_binding.core_protected,
                "gpu_affine": guest_binding.gpu_affine,
                "locked": raw_lock not in {None, ""},
            }
        )

    inventory_observed_at = clock().astimezone(UTC)
    collected_at = clock().astimezone(UTC)
    generated_at = clock().astimezone(UTC)
    source_times = {
        "inventory": inventory_observed_at,
        **evidence.source_observed_at,
    }
    base: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": format_time(generated_at),
        "demo_evaluation_time": format_time(generated_at),
        "observed_at": format_time(max(source_times.values())),
        "collected_at": format_time(collected_at),
        "source_observed_at": {
            source: format_time(observed_at) for source, observed_at in sorted(source_times.items())
        },
        "nodes": sanitized_nodes,
        "guests": sanitized_guests,
        "networks": dict(sorted(evidence.networks.items())),
        "controllers": dict(sorted(evidence.controllers.items())),
        "backups": list(evidence.backups),
        "leases": (
            []
            if evidence.exam_lease is None
            else [
                {
                    "id": "exam-broker-current",
                    "environment_id": evidence.exam_lease["environment_id"],
                    "class": "exam",
                    "state": evidence.exam_lease["state"],
                    "expires_at": evidence.exam_lease["expires_at"],
                }
            ]
        ),
        "reservations": [],
        "catalog_digest": catalog.digest,
        "binding_digest": bindings.binding_digest,
    }
    revision = "live-" + digest(base).removeprefix("sha256:")[:32]
    snapshot = {"revision": revision, **base}
    Snapshot.from_dict(snapshot)
    return snapshot


def export_live_snapshot(
    *,
    catalog_path: Path,
    bindings_path: Path,
    evidence_path: Path,
    output_path: Path,
    reader: PVEReader,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    catalog = Catalog.from_dict(read_json_file(catalog_path))
    bindings = LiveBindings.from_dict(read_json_file(bindings_path), catalog)
    evidence = LiveEvidence.from_dict(read_json_file(evidence_path), catalog, bindings)
    snapshot = build_live_snapshot(reader, bindings, evidence, catalog, clock=clock)
    write_atomic_json(output_path, snapshot)
    return snapshot
