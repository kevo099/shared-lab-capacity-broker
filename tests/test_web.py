from __future__ import annotations

import http.client
import json
import socket
import tempfile
import threading
import unittest
from datetime import UTC, datetime
from pathlib import Path

from lab_broker.fixtures import load_demo, write_atomic_json
from lab_broker.web import (
    DemoApplication,
    SnapshotFileApplication,
    WebSettings,
    create_server,
)
from tests.support import raw_snapshot

ROOT = Path(__file__).resolve().parents[1]


class WebIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        cls.settings = WebSettings("127.0.0.1", port)
        catalog, snapshot = load_demo()
        cls.application = DemoApplication(catalog, snapshot)
        cls.server = create_server(cls.settings, cls.application)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def request(self, method, path, *, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.settings.port, timeout=3)
        actual_headers = {"Host": f"127.0.0.1:{self.settings.port}", **(headers or {})}
        connection.request(method, path, body=body, headers=actual_headers)
        response = connection.getresponse()
        raw = response.read()
        result = (response.status, dict(response.getheaders()), raw)
        connection.close()
        return result

    def json_request(self, method, path, value):
        raw = json.dumps(value).encode("utf-8")
        return self.request(
            method,
            path,
            body=raw,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(raw)),
            },
        )

    def test_overview_and_environment_endpoints_are_read_only_and_consistent(self):
        status, headers, raw = self.request("GET", "/api/v1/overview")
        self.assertEqual(status, 200)
        payload = json.loads(raw)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["mode"], "synthetic-read-only")
        self.assertFalse(payload["summary"]["mutations_enabled"])
        self.assertEqual(headers["Cache-Control"], "no-store")

        status, _headers, raw = self.request("GET", "/api/v1/environments/security-range")
        self.assertEqual(status, 200)
        detail = json.loads(raw)
        self.assertEqual(detail["plan"]["outcome"], "safe_with_donors")
        self.assertEqual(detail["plan"]["required_donors"], ["vision-workbench"])
        self.assertTrue(detail["plan"]["read_only"])

    def test_compute_only_plan_post_has_exact_schema_and_no_persistence(self):
        before = self.application.overview()
        status, _headers, raw = self.json_request(
            "POST", "/api/v1/plans", {"environment_id": "cluster-blue"}
        )
        self.assertEqual(status, 200)
        payload = json.loads(raw)
        self.assertTrue(payload["read_only"])
        self.assertEqual(payload["plan"]["outcome"], "safe_now")
        self.assertIs(before, self.application.overview())

        status, _headers, raw = self.json_request(
            "POST",
            "/api/v1/plans",
            {"environment_id": "cluster-blue", "command": "start"},
        )
        self.assertEqual(status, 422)
        self.assertEqual(json.loads(raw)["error"]["code"], "validation_failed")

    def test_mutation_methods_and_cors_preflight_are_not_available(self):
        for method in ("PUT", "PATCH", "DELETE", "OPTIONS"):
            with self.subTest(method=method):
                status, headers, raw = self.request(method, "/api/v1/environments/cluster-blue")
                self.assertEqual(status, 405)
                self.assertNotIn("Access-Control-Allow-Origin", headers)
                self.assertEqual(json.loads(raw)["error"]["code"], "method_not_allowed")

    def test_host_validation_blocks_dns_rebinding_shape(self):
        status, _headers, raw = self.request(
            "GET",
            "/api/v1/overview",
            headers={"Host": "attacker.invalid"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(raw)["error"]["code"], "forbidden")

    def test_duplicate_json_and_oversized_body_fail_closed(self):
        duplicate = b'{"environment_id":"cluster-blue","environment_id":"security-range"}'
        status, _headers, raw = self.request(
            "POST",
            "/api/v1/plans",
            body=duplicate,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(duplicate)),
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)["error"]["code"], "invalid_json")

        status, _headers, raw = self.request(
            "POST",
            "/api/v1/plans",
            body=b"{}",
            headers={"Content-Type": "application/json", "Content-Length": "99999"},
        )
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(raw)["error"]["code"], "invalid_request")

    def test_short_content_length_body_is_rejected(self):
        request = (
            f"POST /api/v1/plans HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{self.settings.port}\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 40\r\n"
            "Connection: close\r\n\r\n"
            "{}"
        ).encode("ascii")
        client = socket.create_connection(("127.0.0.1", self.settings.port), timeout=3)
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        response = b""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response += chunk
        client.close()
        self.assertIn(b" 400 ", response.partition(b"\r\n")[0])
        self.assertIn(b'"code":"invalid_json"', response)

    def test_security_headers_apply_to_html_json_and_metrics(self):
        for path in ("/", "/static/favicon.svg", "/api/v1/overview", "/metrics"):
            with self.subTest(path=path):
                status, headers, _raw = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(headers["X-Frame-Options"], "DENY")
                self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
                self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
                self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_metrics_use_only_bounded_catalog_labels(self):
        status, _headers, raw = self.request("GET", "/metrics")
        self.assertEqual(status, 200)
        text = raw.decode("utf-8")
        self.assertIn("lab_broker_node_memory_headroom_bytes", text)
        self.assertIn("lab_broker_environment_feasible", text)
        for forbidden in ("plan_id", "lease_id", "trace_id", "digest="):
            self.assertNotIn(forbidden, text)

    def test_health_semantics_distinguish_live_and_ready(self):
        for path in ("/health/live", "/health/ready"):
            status, _headers, raw = self.request("GET", path)
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(raw)["ok"])

    def test_unknown_paths_and_encoded_traversal_are_not_served(self):
        for path in (
            "/api/v1/environments/not-reviewed",
            "/static/../web.py",
            "/api/v1/overview?fresh=false",
        ):
            with self.subTest(path=path):
                status, _headers, _raw = self.request("GET", path)
                self.assertIn(status, {400, 404})


class LiveWebIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.snapshot_path = Path(self.temporary.name) / "live-snapshot.json"
        write_atomic_json(self.snapshot_path, raw_snapshot())
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        self.settings = WebSettings("127.0.0.1", port)
        application = SnapshotFileApplication(
            ROOT / "policies" / "examples" / "catalog.json",
            self.snapshot_path,
            clock=lambda: datetime(2035, 6, 15, 12, 0, tzinfo=UTC),
        )
        self.server = create_server(self.settings, application)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.temporary.cleanup()

    def request(self, path):
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.settings.port,
            timeout=3,
        )
        connection.request(
            "GET",
            path,
            headers={"Host": f"127.0.0.1:{self.settings.port}"},
        )
        response = connection.getresponse()
        result = response.status, json.loads(response.read())
        connection.close()
        return result

    def test_live_mode_is_reported_and_corrupt_replacement_fails_ready_closed(self):
        status, payload = self.request("/api/v1/overview")
        self.assertEqual(status, 200)
        self.assertEqual(payload["mode"], "live-read-only")

        self.snapshot_path.write_text("{not-json", encoding="utf-8")
        status, payload = self.request("/health/live")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["mode"], "live-read-only")
        status, payload = self.request("/health/ready")
        self.assertEqual(status, 503)
        self.assertFalse(payload["ok"])
        status, payload = self.request("/api/v1/overview")
        self.assertEqual(status, 503)
        self.assertEqual(payload["error"]["code"], "snapshot_unavailable")


if __name__ == "__main__":
    unittest.main()
