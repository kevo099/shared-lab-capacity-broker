"""Strict read-only producer for live safety evidence.

Raw Proxmox identities and the broker socket path are supplied only through a
private probe configuration and binding manifest.  The emitted document uses
semantic aliases exclusively and is accepted by ``LiveEvidence`` unchanged.
"""

from __future__ import annotations

import math
import os
import re
import socket
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import quote

from .domain.canonical import strict_json_loads
from .domain.types import Catalog, InputError, format_time
from .fixtures import read_json_file, write_atomic_json
from .live_export import (
    MAX_TASK_LOG_ROWS,
    LiveBindings,
    LiveEvidence,
    PVEReader,
    _boolean,
    _exact,
    _integer,
    _semantic_id,
    _semantic_map,
    _source_name,
    _text,
)

MAX_BROKER_RESPONSE_BYTES = 8 * 1024
MAX_BACKUP_TASKS_TO_INSPECT = 512
BROKER_PHASES = frozenset({"idle", "starting", "ready", "stopping", "error"})
BROKER_ERROR_CODES = frozenset(
    {
        "start_failed",
        "end_failed",
        "environment_conflict",
        "environment_busy",
        "preflight_unavailable",
        "operation_failed",
    }
)
BACKUP_START = re.compile(r"\AINFO: Starting Backup of VM ([1-9][0-9]{0,8}) \((qemu|lxc)\)\Z")
BACKUP_FINISH = re.compile(
    r"\AINFO: Finished Backup of VM ([1-9][0-9]{0,8}) \([0-9]{2}:[0-9]{2}:[0-9]{2}\)\Z"
)


@dataclass(frozen=True, slots=True)
class NetworkProbe:
    alias: str
    source_vnet: str

    @classmethod
    def from_dict(cls, value: Any) -> "NetworkProbe":
        item = _exact(value, {"alias", "source_vnet"}, "network probe")
        return cls(
            alias=_semantic_id(item["alias"], "network probe alias"),
            source_vnet=_source_name(item["source_vnet"], "source vnet"),
        )


@dataclass(frozen=True, slots=True)
class ControllerProbe:
    alias: str
    pve_guest_aliases: tuple[str, ...]
    require_exam_broker: bool
    implemented: bool

    @classmethod
    def from_dict(cls, value: Any) -> "ControllerProbe":
        item = _exact(
            value,
            {
                "alias",
                "pve_guest_aliases",
                "require_exam_broker",
                "implemented",
            },
            "controller probe",
        )
        raw_guests = item["pve_guest_aliases"]
        if not isinstance(raw_guests, list) or len(raw_guests) > 16:
            raise InputError("controller guest checks must be a bounded list")
        guests = tuple(_semantic_id(alias, "controller guest alias") for alias in raw_guests)
        if len(set(guests)) != len(guests):
            raise InputError("controller guest checks contain duplicates")
        implemented = _boolean(item["implemented"], "controller implementation state")
        require_broker = _boolean(
            item["require_exam_broker"],
            "controller broker requirement",
        )
        if implemented and not guests and not require_broker:
            raise InputError("an implemented controller needs observable evidence")
        if not implemented and (guests or require_broker):
            raise InputError("an unimplemented controller cannot claim evidence checks")
        return cls(
            alias=_semantic_id(item["alias"], "controller probe alias"),
            pve_guest_aliases=guests,
            require_exam_broker=require_broker,
            implemented=implemented,
        )


@dataclass(frozen=True, slots=True)
class EvidenceProbeConfig:
    task_history_limit: int
    broker_status_socket: Path
    networks: tuple[NetworkProbe, ...]
    controllers: tuple[ControllerProbe, ...]
    backup_maximum_age_seconds: dict[str, int]
    broker_lab_owners: dict[str, str]

    @classmethod
    def from_dict(
        cls,
        value: Any,
        catalog: Catalog,
        bindings: LiveBindings,
    ) -> "EvidenceProbeConfig":
        item = _exact(
            value,
            {
                "schema_version",
                "task_history_limit",
                "broker_status_socket",
                "networks",
                "controllers",
                "backup_maximum_age_seconds",
                "broker_lab_owners",
            },
            "evidence probe configuration",
        )
        if type(item["schema_version"]) is not int or item["schema_version"] != 1:
            raise InputError("unsupported evidence probe schema")
        socket_text = _text(
            item["broker_status_socket"],
            "broker status socket",
            maximum=512,
        )
        socket_path = Path(socket_text)
        if not socket_path.is_absolute() or socket_path.name in {"", ".", ".."}:
            raise InputError("broker status socket must be an absolute path")

        raw_networks = item["networks"]
        raw_controllers = item["controllers"]
        if not isinstance(raw_networks, list) or len(raw_networks) > 128:
            raise InputError("network probes must be a bounded list")
        if not isinstance(raw_controllers, list) or len(raw_controllers) > 128:
            raise InputError("controller probes must be a bounded list")
        networks = tuple(
            sorted(
                (NetworkProbe.from_dict(raw) for raw in raw_networks),
                key=lambda probe: probe.alias,
            )
        )
        controllers = tuple(
            sorted(
                (ControllerProbe.from_dict(raw) for raw in raw_controllers),
                key=lambda probe: probe.alias,
            )
        )
        if len({probe.alias for probe in networks}) != len(networks):
            raise InputError("network probe aliases must be unique")
        if len({probe.alias for probe in controllers}) != len(controllers):
            raise InputError("controller probe aliases must be unique")
        required_networks = {
            network
            for policy in catalog.environments.values()
            for network in policy.required_networks
        }
        required_controllers = {policy.controller for policy in catalog.environments.values()}
        if {probe.alias for probe in networks} != required_networks:
            raise InputError("network probes must exactly cover the catalog")
        if {probe.alias for probe in controllers} != required_controllers:
            raise InputError("controller probes must exactly cover the catalog")

        guest_aliases = {binding.alias for binding in bindings.guests}
        if any(
            alias not in guest_aliases for probe in controllers for alias in probe.pve_guest_aliases
        ):
            raise InputError("controller probe references an unbound guest")

        raw_backup_ages = _semantic_map(
            item["backup_maximum_age_seconds"],
            "backup maximum ages",
        )
        required_backups = {
            policy.id for policy in catalog.environments.values() if policy.backup_required
        }
        if set(raw_backup_ages) != required_backups:
            raise InputError("backup age policy must exactly cover backup-gated environments")
        backup_ages = {
            environment_id: _integer(
                maximum_age,
                f"backup maximum age for {environment_id}",
                minimum=60,
                maximum=31 * 24 * 60 * 60,
            )
            for environment_id, maximum_age in raw_backup_ages.items()
        }

        raw_owners = _semantic_map(item["broker_lab_owners"], "broker lab owners")
        owners: dict[str, str] = {}
        for lab, raw_environment in raw_owners.items():
            environment_id = _semantic_id(raw_environment, f"broker owner for {lab}")
            policy = catalog.environments.get(environment_id)
            if policy is None or policy.environment_class != "exam":
                raise InputError("broker owner mapping references a non-exam environment")
            owners[lab] = environment_id
        if not owners or len(set(owners.values())) != len(owners):
            raise InputError("broker owner mappings must be non-empty and one-to-one")

        return cls(
            task_history_limit=_integer(
                item["task_history_limit"],
                "backup task history limit",
                minimum=1,
                maximum=256,
            ),
            broker_status_socket=socket_path,
            networks=networks,
            controllers=controllers,
            backup_maximum_age_seconds=backup_ages,
            broker_lab_owners=owners,
        )


@dataclass(frozen=True, slots=True)
class SwapRateEvidence:
    """One semantic, independently observed swap-in-rate sample."""

    observed_at: datetime
    node_swap_in_bytes_per_second: Mapping[str, int | None]


class SwapRateReader(Protocol):
    """Deployment-supplied reader for independently measured swap-in rates."""

    def read(self) -> SwapRateEvidence: ...


class SwapRateUnavailable(RuntimeError):
    """The optional swap-rate source could not produce trustworthy evidence."""


class BrokerStatusReader(Protocol):
    def read(self) -> Any: ...


class UnixBrokerStatusReader:
    """Bounded status-only client for the external exam broker socket."""

    def __init__(
        self,
        socket_path: Path,
        *,
        timeout_seconds: float = 2.0,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if not 0.1 <= timeout_seconds <= 10:
            raise InputError("broker status timeout is outside the supported range")
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds
        self.monotonic = monotonic

    def read(self) -> Any:
        try:
            if self.socket_path.resolve(strict=True) != self.socket_path:
                raise InputError("broker socket path cannot contain a symlink")
            info = self.socket_path.lstat()
        except OSError as exc:
            raise InputError("exam broker status is unavailable") from exc
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise InputError("exam broker socket is not private to the collector user")
        deadline = self.monotonic() + self.timeout_seconds
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.timeout_seconds)
                client.connect(str(self.socket_path))
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    raise InputError("exam broker status exceeded its wall-clock deadline")
                client.settimeout(remaining)
                client.sendall(b'{"action":"status"}\n')
                chunks: list[bytes] = []
                size = 0
                while True:
                    remaining = deadline - self.monotonic()
                    if remaining <= 0:
                        raise InputError("exam broker status exceeded its wall-clock deadline")
                    client.settimeout(remaining)
                    chunk = client.recv(min(4096, MAX_BROKER_RESPONSE_BYTES + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_BROKER_RESPONSE_BYTES:
                        raise InputError("exam broker status exceeded its size limit")
                    if b"\n" in chunk:
                        break
        except InputError:
            raise
        except (OSError, socket.timeout) as exc:
            raise InputError("exam broker status is unavailable") from exc
        raw = b"".join(chunks)
        line, separator, remainder = raw.partition(b"\n")
        if separator != b"\n" or remainder:
            raise InputError("exam broker returned an invalid status frame")
        try:
            return strict_json_loads(line)
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise InputError("exam broker returned invalid status JSON") from exc


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{label} must be an object")
    return value


def _aware_utc(clock: Callable[[], datetime], label: str) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise InputError(f"{label} clock must be timezone-aware")
    return value.astimezone(UTC)


def _validated_swap_rate_evidence(
    evidence: object,
    *,
    expected_nodes: set[str],
    configured_swap_totals: Mapping[str, int],
    pve_observed_at: datetime,
) -> tuple[dict[str, int | None], datetime]:
    if not isinstance(evidence, SwapRateEvidence):
        raise InputError("swap-rate reader returned an invalid evidence type")
    observed_at = evidence.observed_at
    if (
        not isinstance(observed_at, datetime)
        or observed_at.tzinfo is None
        or observed_at.utcoffset() is None
    ):
        raise InputError("swap-rate observation time must be timezone-aware")
    observed_at = observed_at.astimezone(UTC)
    if observed_at > pve_observed_at:
        raise InputError("swap-rate observation time is future-dated")

    raw_rates = evidence.node_swap_in_bytes_per_second
    if not isinstance(raw_rates, Mapping) or len(raw_rates) > 128:
        raise InputError("swap-rate evidence must be a bounded mapping")
    rates: dict[str, int | None] = {}
    for raw_alias, raw_rate in raw_rates.items():
        alias = _semantic_id(raw_alias, "swap-rate evidence alias")
        if alias in rates:
            raise InputError("swap-rate evidence aliases must be unique")
        rate = None if raw_rate is None else _integer(raw_rate, f"swap rate for {alias}")
        if configured_swap_totals.get(alias) == 0 and rate not in {None, 0}:
            raise InputError("swap-rate evidence conflicts with configured-zero swap")
        rates[alias] = rate
    if set(rates) != expected_nodes:
        raise InputError("swap-rate evidence must exactly cover bound nodes")
    return rates, observed_at


def _bound_inventory(
    reader: PVEReader,
    bindings: LiveBindings,
) -> dict[str, dict[str, Any]]:
    raw_rows = reader.get("/cluster/resources?type=vm")
    if not isinstance(raw_rows, list) or len(raw_rows) > 4096:
        raise InputError("PVE guest inventory is invalid")
    by_source: dict[tuple[str, int], dict[str, Any]] = {}
    for raw in raw_rows:
        row = _object(raw, "PVE guest")
        if row.get("template") in {1}:
            continue
        kind = row.get("type")
        source_id = row.get("vmid")
        if kind not in {"qemu", "lxc"} or type(source_id) is not int:
            raise InputError("PVE guest identity is invalid")
        key = (kind, source_id)
        if key in by_source:
            raise InputError("PVE guest identity is duplicated")
        by_source[key] = row
    expected = {(binding.source_kind, binding.source_id): binding for binding in bindings.guests}
    if set(by_source) != set(expected):
        raise InputError("PVE guest inventory does not exactly match reviewed bindings")
    output: dict[str, dict[str, Any]] = {}
    node_sources = {binding.alias: binding.source_node for binding in bindings.nodes}
    for key, binding in expected.items():
        row = by_source[key]
        if row.get("node") != node_sources[binding.node_alias]:
            raise InputError("a bound guest moved to an unreviewed node")
        output[binding.alias] = row
    return output


def _broker_status(value: Any, owners: dict[str, str]) -> tuple[str, str | None, int | None]:
    response = _exact(value, {"ok", "status"}, "exam broker response")
    if response["ok"] is not True:
        raise InputError("exam broker did not return a successful status")
    status = _object(response["status"], "exam broker status")
    required = {
        "phase",
        "job_id",
        "lab",
        "exam",
        "requested_at",
        "ready_at",
        "duration_seconds",
        "elapsed_seconds",
        "remaining_seconds",
        "lease_remaining_seconds",
        "grade_grace_seconds",
        "message",
    }
    phase = status["phase"]
    if not isinstance(phase, str) or phase not in BROKER_PHASES:
        raise InputError("exam broker phase is invalid")
    expected = required | ({"error_code"} if phase == "error" else set())
    if set(status) != expected:
        raise InputError("exam broker status fields are invalid")

    message = status["message"]
    _text(message, "exam broker status message", maximum=512)
    grade_grace = status["grade_grace_seconds"]
    if type(grade_grace) is not int or not 0 <= grade_grace <= 3_600:
        raise InputError("exam broker grade grace is invalid")

    lab = status["lab"]
    if phase == "idle":
        if any(
            status[field] is not None
            for field in (
                "job_id",
                "lab",
                "exam",
                "requested_at",
                "ready_at",
                "duration_seconds",
                "elapsed_seconds",
                "remaining_seconds",
                "lease_remaining_seconds",
            )
        ):
            raise InputError("idle exam broker reported active state")
        environment_id = None
    else:
        if not isinstance(lab, str) or lab not in owners:
            raise InputError("active exam broker owner is not mapped")
        _text(status["job_id"], "exam broker job identity", maximum=128)
        if type(status["exam"]) is not int or not 1 <= status["exam"] <= 100:
            raise InputError("active exam broker exam number is invalid")
        requested_at = status["requested_at"]
        if (
            type(requested_at) not in {int, float}
            or not math.isfinite(requested_at)
            or not 0 <= requested_at <= 10**12
        ):
            raise InputError("active exam broker request time is invalid")
        environment_id = owners[lab]

    for field in ("ready_at",):
        number = status[field]
        if number is not None and (
            type(number) not in {int, float}
            or not math.isfinite(number)
            or not 0 <= number <= 10**12
        ):
            raise InputError(f"exam broker {field} is invalid")
    for field in (
        "duration_seconds",
        "elapsed_seconds",
        "remaining_seconds",
        "lease_remaining_seconds",
    ):
        number = status[field]
        if number is not None and (type(number) is not int or not 0 <= number <= 172_800):
            raise InputError(f"exam broker {field} is invalid")

    remaining = status["lease_remaining_seconds"]
    if phase == "ready":
        if any(
            status[field] is None
            for field in (
                "ready_at",
                "duration_seconds",
                "elapsed_seconds",
                "remaining_seconds",
                "lease_remaining_seconds",
            )
        ):
            raise InputError("ready exam broker omitted timer evidence")
        if remaining > status["duration_seconds"] + grade_grace:
            raise InputError("ready exam broker lease remainder is invalid")
    elif any(
        status[field] is not None
        for field in (
            "duration_seconds",
            "elapsed_seconds",
            "remaining_seconds",
            "lease_remaining_seconds",
        )
    ):
        raise InputError("non-ready exam broker reported ready-only timers")

    if phase == "error" and status["error_code"] not in BROKER_ERROR_CODES:
        raise InputError("exam broker error code is invalid")
    return phase, environment_id, remaining


def _backup_evidence(
    reader: PVEReader,
    bindings: LiveBindings,
    catalog: Catalog,
    config: EvidenceProbeConfig,
    clock: Callable[[], datetime],
) -> tuple[list[dict[str, Any]], datetime]:
    binding_by_alias = {binding.alias: binding for binding in bindings.guests}
    targets = {
        (binding_by_alias[member].source_kind, binding_by_alias[member].source_id)
        for environment_id in config.backup_maximum_age_seconds
        for member in catalog.environments[environment_id].cohort
    }
    latest_attempt: dict[tuple[str, int], tuple[int, bool]] = {}
    tasks: list[tuple[int, str, str]] = []
    for node in bindings.nodes:
        encoded_node = quote(node.source_node, safe="")
        rows = reader.get(
            f"/nodes/{encoded_node}/tasks?limit={config.task_history_limit}&typefilter=vzdump"
        )
        if not isinstance(rows, list) or len(rows) > config.task_history_limit:
            raise InputError("PVE backup task history is invalid")
        for raw in rows:
            row = _object(raw, "PVE backup task")
            if row.get("type") != "vzdump" or row.get("node") != node.source_node:
                raise InputError("PVE backup task identity is invalid")
            raw_completion = row.get("endtime")
            if raw_completion is None:
                raw_completion = row.get("starttime")
            endtime = _integer(raw_completion, "backup task completion", minimum=1)
            upid = _text(row.get("upid"), "backup task identity", maximum=512)
            tasks.append((endtime, encoded_node, upid))
    if len(tasks) > MAX_BACKUP_TASKS_TO_INSPECT or len(
        {(encoded_node, upid) for _endtime, encoded_node, upid in tasks}
    ) != len(tasks):
        raise InputError("PVE backup task history is ambiguous or too large")

    previous_endtime: int | None = None
    for endtime, encoded_node, upid in sorted(
        tasks,
        key=lambda task: (-task[0], task[1], task[2]),
    ):
        if (
            previous_endtime is not None
            and endtime < previous_endtime
            and targets <= set(latest_attempt)
        ):
            break
        previous_endtime = endtime
        encoded_upid = quote(upid, safe="")
        log = reader.get(
            f"/nodes/{encoded_node}/tasks/{encoded_upid}/log?limit={MAX_TASK_LOG_ROWS}"
        )
        if not isinstance(log, list) or len(log) > MAX_TASK_LOG_ROWS:
            raise InputError("PVE backup task log is invalid")
        started: set[tuple[str, int]] = set()
        finished_ids: set[int] = set()
        for raw_line in log:
            line = _object(raw_line, "PVE backup task log row")
            text = line.get("t")
            if not isinstance(text, str) or len(text.encode("utf-8")) > 4096:
                raise InputError("PVE backup task log line is invalid")
            start = BACKUP_START.fullmatch(text)
            finish = BACKUP_FINISH.fullmatch(text)
            if start:
                started.add((start.group(2), int(start.group(1))))
            if finish:
                finished_ids.add(int(finish.group(1)))
        for key in sorted(started & targets):
            succeeded = key[1] in finished_ids
            previous = latest_attempt.get(key)
            if previous is None:
                latest_attempt[key] = (endtime, succeeded)
            elif previous[0] == endtime:
                # Equal-time duplicate histories are ambiguous.  They count as
                # successful only if every matching newest task proves finish.
                latest_attempt[key] = (endtime, previous[1] and succeeded)

    observed_at = _aware_utc(clock, "backup observation")
    now_epoch = int(observed_at.timestamp())
    backups: list[dict[str, Any]] = []
    for environment_id, maximum_age in sorted(config.backup_maximum_age_seconds.items()):
        keys = [
            (
                binding_by_alias[member].source_kind,
                binding_by_alias[member].source_id,
            )
            for member in catalog.environments[environment_id].cohort
        ]
        attempts = [latest_attempt.get(key) for key in keys]
        if any(attempt is None or attempt[1] is not True for attempt in attempts):
            state = "unknown"
            age: int | None = None
        else:
            completed = [attempt[0] for attempt in attempts if attempt is not None]
            age = now_epoch - min(completed)
            if age < 0:
                raise InputError("backup task completion is future-dated")
            state = "fresh" if age <= maximum_age else "stale"
        backups.append(
            {
                "environment_id": environment_id,
                "state": state,
                "age_seconds": age,
            }
        )
    return backups, observed_at


def probe_live_evidence(
    reader: PVEReader,
    broker: BrokerStatusReader,
    bindings: LiveBindings,
    catalog: Catalog,
    config: EvidenceProbeConfig,
    *,
    swap_rate_reader: SwapRateReader | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    """Collect only independently provable safety evidence."""

    raw_swap_evidence: object | None = None
    has_swap_evidence = False
    if swap_rate_reader is not None:
        try:
            raw_swap_evidence = swap_rate_reader.read()
            has_swap_evidence = True
        except SwapRateUnavailable:
            pass

    inventory = _bound_inventory(reader, bindings)
    swap_rates: dict[str, int | None] = {}
    configured_swap_totals: dict[str, int] = {}
    for node_binding in bindings.nodes:
        encoded_node = quote(node_binding.source_node, safe="")
        status = _object(
            reader.get(f"/nodes/{encoded_node}/status"),
            "PVE node status",
        )
        swap = _object(status.get("swap"), "PVE node swap")
        total = _integer(swap.get("total"), "PVE node swap total")
        # Node status proves an exact zero only when no swap is configured.
        # A future trusted counter-delta source may provide a rate for other
        # nodes; until then nullable evidence keeps unrelated views available.
        configured_swap_totals[node_binding.alias] = total
        swap_rates[node_binding.alias] = 0 if total == 0 else None
    telemetry_observed_at = _aware_utc(clock, "telemetry observation")
    if has_swap_evidence:
        trusted_rates, swap_observed_at = _validated_swap_rate_evidence(
            raw_swap_evidence,
            expected_nodes=set(configured_swap_totals),
            configured_swap_totals=configured_swap_totals,
            pve_observed_at=telemetry_observed_at,
        )
        age = telemetry_observed_at - swap_observed_at
        if age <= timedelta(seconds=catalog.max_snapshot_age_seconds):
            swap_rates = trusted_rates
            telemetry_observed_at = min(telemetry_observed_at, swap_observed_at)

    raw_vnets = reader.get("/cluster/sdn/vnets")
    if not isinstance(raw_vnets, list) or len(raw_vnets) > 256:
        raise InputError("PVE SDN vnet inventory is invalid")
    vnets = [_object(row, "PVE SDN vnet") for row in raw_vnets]
    networks: dict[str, bool] = {}
    for network_probe in config.networks:
        matches = [row for row in vnets if row.get("vnet") == network_probe.source_vnet]
        networks[network_probe.alias] = (
            len(matches) == 1
            and matches[0].get("type") == "vnet"
            and matches[0].get("pending") in {None, False}
        )

    phase, broker_environment, lease_remaining = _broker_status(
        broker.read(),
        config.broker_lab_owners,
    )
    broker_healthy = phase != "error"
    controllers: dict[str, bool] = {}
    for controller_probe in config.controllers:
        if not controller_probe.implemented:
            controllers[controller_probe.alias] = False
            continue
        guest_checks = all(
            inventory[alias].get("status") == "running"
            for alias in controller_probe.pve_guest_aliases
        )
        controllers[controller_probe.alias] = guest_checks and (
            not controller_probe.require_exam_broker or broker_healthy
        )
    controllers_observed_at = _aware_utc(clock, "controller observation")

    active_owners: dict[str, str] = {}
    exam_lease: dict[str, Any] | None = None
    if broker_environment is not None:
        for guest_binding in bindings.guests:
            if (
                len(guest_binding.owner_environments) > 1
                and broker_environment in guest_binding.owner_environments
            ):
                active_owners[guest_binding.alias] = broker_environment
        state = {
            "starting": "activating",
            "ready": "active",
            "stopping": "releasing",
            "error": "cleanup_failed",
        }[phase]
        policy = catalog.environments[broker_environment]
        lifetime = (
            lease_remaining
            if phase == "ready" and lease_remaining is not None
            else policy.maximum_lease_seconds
        )
        exam_lease = {
            "environment_id": broker_environment,
            "state": state,
            "expires_at": format_time(controllers_observed_at + timedelta(seconds=lifetime)),
        }

    backups, backups_observed_at = _backup_evidence(
        reader,
        bindings,
        catalog,
        config,
        clock,
    )
    evidence = {
        "schema_version": 1,
        "catalog_digest": catalog.digest,
        "source_observed_at": {
            "telemetry": format_time(telemetry_observed_at),
            "controllers": format_time(controllers_observed_at),
            "backups": format_time(backups_observed_at),
        },
        "node_swap_in_bytes_per_second": dict(sorted(swap_rates.items())),
        "networks": dict(sorted(networks.items())),
        "controllers": dict(sorted(controllers.items())),
        "backups": backups,
        "active_owners": dict(sorted(active_owners.items())),
        "exam_lease": exam_lease,
    }
    LiveEvidence.from_dict(evidence, catalog, bindings)
    return evidence


def export_probe_evidence(
    *,
    catalog_path: Path,
    bindings_path: Path,
    probe_config_path: Path,
    output_path: Path,
    reader: PVEReader,
    broker: BrokerStatusReader | None = None,
    swap_rate_reader: SwapRateReader | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, Any]:
    catalog = Catalog.from_dict(read_json_file(catalog_path))
    bindings = LiveBindings.from_dict(read_json_file(bindings_path), catalog)
    config = EvidenceProbeConfig.from_dict(
        read_json_file(probe_config_path),
        catalog,
        bindings,
    )
    broker_reader = broker or UnixBrokerStatusReader(config.broker_status_socket)
    evidence = probe_live_evidence(
        reader,
        broker_reader,
        bindings,
        catalog,
        config,
        swap_rate_reader=swap_rate_reader,
        clock=clock,
    )
    write_atomic_json(output_path, evidence)
    return evidence
