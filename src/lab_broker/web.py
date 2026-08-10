"""Hardened, dependency-free HTTP shell for the synthetic read-only release."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import threading
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from .domain.canonical import strict_json_loads
from .domain.planner import OUTCOMES, build_overview, plan_start
from .domain.types import Catalog, InputError, PlanRequest, Snapshot
from .fixtures import load_catalog, load_demo, load_snapshot

MAX_REQUEST_BYTES = 4_096
MAX_PATH_BYTES = 512
ENVIRONMENT_PATH = re.compile(r"\A/api/v1/environments/([a-z0-9][a-z0-9-]{0,63})\Z")
STATIC_ROOT = Path(__file__).resolve().parent / "ui" / "static"
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/favicon.svg": ("favicon.svg", "image/svg+xml"),
}
ServerRequest = socket.socket | tuple[bytes, socket.socket]


@dataclass(frozen=True, slots=True)
class WebSettings:
    bind: str = "127.0.0.1"
    port: int = 8087
    allow_nonloopback: bool = False

    def __post_init__(self) -> None:
        if type(self.port) is not int or not 1 <= self.port <= 65_535:
            raise ValueError("port must be between 1 and 65535")
        try:
            address = socket.getaddrinfo(self.bind, self.port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise ValueError("bind address does not resolve") from exc
        loopback = all(candidate[4][0] in {"127.0.0.1", "::1"} for candidate in address)
        if not loopback and not self.allow_nonloopback:
            raise ValueError("non-loopback bind requires --allow-nonloopback")

    @property
    def allowed_hosts(self) -> frozenset[str]:
        hosts = {"localhost", "127.0.0.1", "[::1]"}
        if self.allow_nonloopback:
            host = self.bind.lower()
            hosts.add(f"[{host}]" if ":" in host and not host.startswith("[") else host)
        return frozenset(hosts)


class DemoApplication:
    """Immutable synthetic input set shared by API, UI, CLI, and tests."""

    mode = "synthetic-read-only"

    def __init__(self, catalog: Catalog, snapshot: Snapshot):
        if snapshot.catalog_digest != catalog.digest:
            raise InputError("synthetic snapshot catalog digest does not match the catalog")
        self.catalog = catalog
        self.snapshot = snapshot
        self.evaluated_at = snapshot.demo_evaluation_time
        self._overview = build_overview(
            snapshot,
            catalog,
            evaluated_at=self.evaluated_at,
            mode="synthetic-read-only",
        )

    def overview(self) -> dict[str, Any]:
        return self._overview

    def plan(self, environment_id: str, duration_seconds: int | None = None) -> dict[str, Any]:
        policy = self.catalog.environments.get(environment_id)
        if policy is None or not policy.user_visible:
            raise KeyError(environment_id)
        request = PlanRequest.create(environment_id, self.evaluated_at, duration_seconds)
        return plan_start(request, self.snapshot, self.catalog)

    def environment(self, environment_id: str) -> dict[str, Any]:
        plan = self.plan(environment_id)
        summary = next(
            item for item in self._overview["environments"] if item["id"] == environment_id
        )
        return {
            "ok": True,
            "schema_version": 1,
            "mode": "synthetic-read-only",
            "environment": summary,
            "plan": plan,
        }

    def metrics(self) -> str:
        return render_metrics(
            self.catalog,
            self.snapshot,
            self._overview,
            self.evaluated_at,
        )


class ApplicationUnavailable(RuntimeError):
    """The sanitized live snapshot cannot currently support a response."""


class SnapshotFileApplication:
    """Credential-free live view over one atomically replaced snapshot file."""

    mode = "live-read-only"

    def __init__(
        self,
        catalog_path: Path,
        snapshot_path: Path,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        self.catalog = load_catalog(catalog_path)
        self.snapshot_path = snapshot_path
        self.clock = clock

    def _view(self) -> tuple[Snapshot, datetime, dict[str, Any]]:
        try:
            snapshot = load_snapshot(self.snapshot_path)
            if snapshot.catalog_digest != self.catalog.digest:
                raise InputError("snapshot catalog digest does not match the application catalog")
            evaluated_at = self.clock()
            if not isinstance(evaluated_at, datetime) or evaluated_at.tzinfo is None:
                raise InputError("live evaluation clock must be timezone-aware")
            evaluated_at = evaluated_at.astimezone(UTC)
            overview = build_overview(
                snapshot,
                self.catalog,
                evaluated_at=evaluated_at,
                mode="live-read-only",
            )
            return snapshot, evaluated_at, overview
        except (InputError, OSError, ValueError) as exc:
            raise ApplicationUnavailable("sanitized live snapshot is unavailable") from exc

    def overview(self) -> dict[str, Any]:
        return self._view()[2]

    def plan(self, environment_id: str, duration_seconds: int | None = None) -> dict[str, Any]:
        policy = self.catalog.environments.get(environment_id)
        if policy is None or not policy.user_visible:
            raise KeyError(environment_id)
        snapshot, evaluated_at, _overview = self._view()
        request = PlanRequest.create(environment_id, evaluated_at, duration_seconds)
        return plan_start(request, snapshot, self.catalog)

    def environment(self, environment_id: str) -> dict[str, Any]:
        policy = self.catalog.environments.get(environment_id)
        if policy is None or not policy.user_visible:
            raise KeyError(environment_id)
        snapshot, evaluated_at, overview = self._view()
        plan = plan_start(
            PlanRequest.create(environment_id, evaluated_at),
            snapshot,
            self.catalog,
        )
        summary = next(item for item in overview["environments"] if item["id"] == environment_id)
        return {
            "ok": True,
            "schema_version": 1,
            "mode": "live-read-only",
            "environment": summary,
            "plan": plan,
        }

    def metrics(self) -> str:
        snapshot, evaluated_at, overview = self._view()
        return render_metrics(self.catalog, snapshot, overview, evaluated_at)


def render_metrics(
    catalog: Catalog,
    snapshot: Snapshot,
    overview: dict[str, Any],
    evaluated_at: datetime,
) -> str:
    lines = [
        "# HELP lab_broker_collection_age_seconds Age of the oldest required source.",
        "# TYPE lab_broker_collection_age_seconds gauge",
    ]
    required_observations = [
        snapshot.source_observed_at[source]
        for source in catalog.required_sources
        if source in snapshot.source_observed_at
    ]
    if len(required_observations) == len(catalog.required_sources):
        oldest = min(required_observations)
        age = max(0, int((evaluated_at - oldest).total_seconds()))
        lines.append(f"lab_broker_collection_age_seconds {age}")
    lines.extend(
        [
            "# HELP lab_broker_node_memory_headroom_bytes Read-only memory envelope headroom.",
            "# TYPE lab_broker_node_memory_headroom_bytes gauge",
        ]
    )
    for node in overview["nodes"]:
        envelope = node["envelope"]
        if not envelope:
            continue
        lines.append(
            f'lab_broker_node_memory_headroom_bytes{{node="{node["id"]}",envelope="conservative"}} '
            f"{envelope['guaranteed_headroom_bytes']}"
        )
        lines.append(
            f'lab_broker_node_memory_headroom_bytes{{node="{node["id"]}",envelope="observed"}} '
            f"{envelope['observed_headroom_bytes']}"
        )
    lines.extend(
        [
            "# HELP lab_broker_environment_feasible Current deterministic planning outcome.",
            "# TYPE lab_broker_environment_feasible gauge",
        ]
    )
    for environment in overview["environments"]:
        for outcome in sorted(OUTCOMES):
            value = 1 if environment["outcome"] == outcome else 0
            lines.append(
                f'lab_broker_environment_feasible{{environment="{environment["id"]}",outcome="{outcome}"}} {value}'
            )
    return "\n".join(lines) + "\n"


def error_payload(code: str, message: str, *, retryable: bool = False) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "retryable": retryable,
            "details": {},
        }
    }


class BrokerHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(
        self,
        address: tuple[str, int],
        settings: WebSettings,
        application: DemoApplication | SnapshotFileApplication,
    ):
        super().__init__(address, BrokerHandler)
        self.settings = settings
        self.application = application
        self._handler_slots = threading.BoundedSemaphore(16)

    def get_request(self) -> tuple[socket.socket, Any]:
        request, client_address = super().get_request()
        request.settimeout(10.0)
        return request, client_address

    def process_request(self, request: ServerRequest, client_address: Any) -> None:
        if not self._handler_slots.acquire(blocking=False):
            if isinstance(request, tuple):
                request[1].close()
            else:
                request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._handler_slots.release()
            raise

    def process_request_thread(
        self,
        request: ServerRequest,
        client_address: Any,
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._handler_slots.release()


class BrokerHandler(BaseHTTPRequestHandler):
    server_version = "LabBroker"
    sys_version = ""

    @property
    def application(self) -> DemoApplication | SnapshotFileApplication:
        return self.server.application  # type: ignore[attr-defined,no-any-return]

    @property
    def settings(self) -> WebSettings:
        return self.server.settings  # type: ignore[attr-defined,no-any-return]

    def log_message(self, _format: str, *_args: object) -> None:
        # A deployment wrapper should emit structured, bounded access logs.
        # Synthetic demo mode avoids reflecting attacker-controlled paths.
        return

    def _security_headers(self, content_type: str, size: int, *, cache: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; "
            "img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'none'",
        )

    def _send(
        self, status: int, body: bytes, content_type: str, *, cache: str = "no-store"
    ) -> None:
        self.send_response(status)
        self._security_headers(content_type, len(body), cache=cache)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: int, code: str, message: str, *, retryable: bool = False) -> None:
        self._json(status, error_payload(code, message, retryable=retryable))

    def _valid_host(self) -> bool:
        values = self.headers.get_all("Host", failobj=[])
        if len(values) != 1:
            return False
        raw = values[0].strip().lower()
        if not raw or any(char in raw for char in "@/,\\\r\n\t "):
            return False
        host = raw
        supplied_port: int | None = None
        if raw.startswith("["):
            closing = raw.find("]")
            if closing < 0:
                return False
            host = raw[: closing + 1]
            suffix = raw[closing + 1 :]
            if suffix:
                if not suffix.startswith(":") or not suffix[1:].isdigit():
                    return False
                supplied_port = int(suffix[1:])
        elif raw.count(":") == 1:
            host, port_text = raw.rsplit(":", 1)
            if not port_text.isdigit():
                return False
            supplied_port = int(port_text)
        elif ":" in raw:
            return False
        return host in self.settings.allowed_hosts and (
            supplied_port is None or supplied_port == self.settings.port
        )

    def _authorize(self) -> bool:
        if not self._valid_host():
            self._error(HTTPStatus.FORBIDDEN, "forbidden", "The request host is not allowed.")
            return False
        return True

    def _parse_path(self) -> urllib.parse.SplitResult | None:
        try:
            if len(self.path.encode("utf-8")) > MAX_PATH_BYTES:
                raise ValueError
            parsed = urllib.parse.urlsplit(self.path)
        except (UnicodeEncodeError, ValueError):
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "The request path is invalid.",
            )
            return None
        if parsed.query or parsed.fragment:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "Queries are not accepted here.",
            )
            return None
        return parsed

    def _read_json(self) -> dict[str, Any] | None:
        if self.headers.get("Transfer-Encoding") is not None:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_request",
                "Transfer encoding is not accepted.",
            )
            return None
        lengths = self.headers.get_all("Content-Length", failobj=[])
        if len(lengths) != 1 or not lengths[0].isdigit():
            self._error(
                HTTPStatus.LENGTH_REQUIRED,
                "invalid_request",
                "A content length is required.",
            )
            return None
        length = int(lengths[0])
        if not 1 <= length <= MAX_REQUEST_BYTES:
            self._error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "invalid_request",
                "The request body is too large.",
            )
            return None
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._error(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "invalid_request",
                "JSON is required.",
            )
            return None
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("request body ended before Content-Length")
            value = strict_json_loads(raw)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
            RecursionError,
        ):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_json", "The JSON body is invalid.")
            return None
        if not isinstance(value, dict):
            self._error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "validation_failed",
                "A JSON object is required.",
            )
            return None
        return value

    def _serve_static(self, path: str) -> bool:
        target = STATIC_FILES.get(path)
        if target is None:
            return False
        filename, content_type = target
        try:
            body = (STATIC_ROOT / filename).read_bytes()
        except OSError:
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "ui_unavailable",
                "The dashboard asset is unavailable.",
                retryable=True,
            )
            return True
        self._send(HTTPStatus.OK, body, content_type, cache="no-cache")
        return True

    def do_GET(self) -> None:
        if not self._authorize():
            return
        parsed = self._parse_path()
        if parsed is None:
            return
        path = parsed.path
        if self._serve_static(path):
            return
        if path == "/health/live":
            self._json(
                HTTPStatus.OK,
                {"ok": True, "service": "lab-broker", "mode": self.application.mode},
            )
            return
        if path == "/health/ready":
            try:
                ready = self.application.overview()["snapshot_status"] == "current"
            except ApplicationUnavailable:
                ready = False
            self._json(
                HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE,
                {"ok": ready, "service": "lab-broker", "mode": self.application.mode},
            )
            return
        if path == "/metrics":
            try:
                metrics = self.application.metrics()
            except ApplicationUnavailable:
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "snapshot_unavailable",
                    "The sanitized live snapshot is unavailable.",
                    retryable=True,
                )
                return
            self._send(
                HTTPStatus.OK,
                metrics.encode("utf-8"),
                "text/plain; version=0.0.4; charset=utf-8",
            )
            return
        if path == "/api/v1/overview":
            try:
                overview = self.application.overview()
            except ApplicationUnavailable:
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "snapshot_unavailable",
                    "The sanitized live snapshot is unavailable.",
                    retryable=True,
                )
                return
            self._json(HTTPStatus.OK, overview)
            return
        if path == "/api/v1/environments":
            try:
                overview = self.application.overview()
            except ApplicationUnavailable:
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "snapshot_unavailable",
                    "The sanitized live snapshot is unavailable.",
                    retryable=True,
                )
                return
            self._json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "schema_version": 1,
                    "mode": overview["mode"],
                    "evaluated_at": overview["evaluated_at"],
                    "snapshot_revision": overview["snapshot_revision"],
                    "environments": overview["environments"],
                },
            )
            return
        match = ENVIRONMENT_PATH.fullmatch(path)
        if match:
            try:
                payload = self.application.environment(match.group(1))
            except KeyError:
                self._error(
                    HTTPStatus.NOT_FOUND,
                    "environment_not_found",
                    "The environment is not allowlisted.",
                )
                return
            except ApplicationUnavailable:
                self._error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "snapshot_unavailable",
                    "The sanitized live snapshot is unavailable.",
                    retryable=True,
                )
                return
            self._json(HTTPStatus.OK, payload)
            return
        self._error(HTTPStatus.NOT_FOUND, "not_found", "The requested resource does not exist.")

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        if not self._authorize():
            return
        try:
            client_ip = ipaddress.ip_address(self.client_address[0].split("%", 1)[0])
        except ValueError:
            client_ip = None
        if client_ip is None or not client_ip.is_loopback:
            self._error(
                HTTPStatus.FORBIDDEN,
                "forbidden",
                "Plan computation is available only to loopback clients.",
            )
            return
        parsed = self._parse_path()
        if parsed is None:
            return
        if parsed.path != "/api/v1/plans":
            self._error(
                HTTPStatus.NOT_FOUND,
                "not_found",
                "The requested resource does not exist.",
            )
            return
        value = self._read_json()
        if value is None:
            return
        if (
            not set(value) <= {"environment_id", "duration_seconds"}
            or "environment_id" not in value
        ):
            self._error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "validation_failed",
                "The plan request has unexpected fields.",
            )
            return
        try:
            plan = self.application.plan(value["environment_id"], value.get("duration_seconds"))
        except KeyError:
            self._error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "validation_failed",
                "The plan request is invalid.",
            )
            return
        except ApplicationUnavailable:
            self._error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "snapshot_unavailable",
                "The sanitized live snapshot is unavailable.",
                retryable=True,
            )
            return
        except InputError:
            self._error(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "validation_failed",
                "The plan request is invalid.",
            )
            return
        self._json(HTTPStatus.OK, {"ok": True, "read_only": True, "plan": plan})

    def _method_not_allowed(self) -> None:
        self._error(
            HTTPStatus.METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "This read-only release does not support that method.",
        )

    do_PUT = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_CONNECT = _method_not_allowed
    do_TRACE = _method_not_allowed

    def do_OPTIONS(self) -> None:
        self._method_not_allowed()


def create_server(
    settings: WebSettings,
    application: DemoApplication | SnapshotFileApplication | None = None,
) -> BrokerHTTPServer:
    if application is None:
        catalog, snapshot = load_demo()
        application = DemoApplication(catalog, snapshot)
    return BrokerHTTPServer((settings.bind, settings.port), settings, application)


def serve(
    settings: WebSettings,
    application: DemoApplication | SnapshotFileApplication | None = None,
) -> None:
    server = create_server(settings, application)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()


def add_serve_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8087)
    parser.add_argument(
        "--allow-nonloopback",
        action="store_true",
        help="explicitly expose the service beyond loopback; use a protected reverse proxy",
    )
    parser.add_argument(
        "--catalog-file",
        type=Path,
        help="validated catalog for credential-free live snapshot mode",
    )
    parser.add_argument(
        "--snapshot-file",
        type=Path,
        help="atomically replaced sanitized snapshot for live mode",
    )
