from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from scripts.check_public_tree import EXCLUDED_PARTS, scan_tree

ROOT = Path(__file__).resolve().parents[1]


def files():
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.is_file() and not path.is_symlink():
            yield path


class PublicHygieneTests(unittest.TestCase):
    def test_complete_public_tree_passes_the_release_scanner(self):
        self.assertEqual(scan_tree(ROOT), [])

    def test_no_secret_or_private_binding_file_is_present(self):
        bad_suffixes = {".env", ".pem", ".key", ".p12", ".pfx"}
        for path in files():
            with self.subTest(path=str(path.relative_to(ROOT))):
                self.assertNotIn(path.suffix.lower(), bad_suffixes)
                self.assertNotIn("private-binding", path.name.lower())

    def test_pure_planner_has_no_io_or_mutation_imports(self):
        import re

        domain = ROOT / "src" / "lab_broker" / "domain"
        forbidden_imports = re.compile(
            r"^\s*(?:from|import)\s+(?:os|pathlib|socket|subprocess|urllib|http|requests|sqlalchemy|psycopg)\b",
            re.MULTILINE,
        )
        for path in domain.glob("*.py"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertIsNone(forbidden_imports.search(text))
                self.assertNotIn("shell=True", text)

    def test_no_executor_or_mutation_adapter_exists(self):
        package = ROOT / "src" / "lab_broker"
        self.assertFalse((package / "execution").exists())
        self.assertFalse((package / "collectors").exists())
        combined = "\n".join(path.read_text(encoding="utf-8") for path in package.rglob("*.py"))
        for forbidden in ("status/start", "status/stop", "ssh ", "qm start", "qm stop"):
            self.assertNotIn(forbidden, combined.lower())

    def test_live_deployment_keeps_credentials_off_the_web_host(self):
        unit = (ROOT / "deploy" / "lab-broker-live.service").read_text(encoding="utf-8")
        nginx = (ROOT / "deploy" / "nginx-lab-capacity.conf").read_text(encoding="utf-8")
        self.assertIn("User=lab-broker", unit)
        self.assertIn("--bind 127.0.0.1", unit)
        self.assertIn("--snapshot-file /var/lib/lab-broker/live-snapshot.json", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("ReadOnlyPaths=/opt/shared-lab-capacity-broker /etc/lab-broker", unit)
        self.assertIn("/opt/shared-lab-capacity-broker/REVISION", unit)
        self.assertIn("test ! -w /etc/lab-broker/catalog.json", unit)
        self.assertIn(
            "test ! -w /opt/shared-lab-capacity-broker/src/lab_broker/ui/static/app.js",
            unit,
        )
        for secret_name in ("PVE_HOST", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET"):
            self.assertNotIn(secret_name, unit)
        self.assertIn("TLS-enabled", nginx)
        self.assertIn("auth_basic_user_file", nginx)
        self.assertIn("limit_except GET HEAD", nginx)
        self.assertIn("proxy_set_header Host 127.0.0.1:8087", nginx)
        self.assertIn('proxy_set_header Authorization ""', nginx)


class PublicScannerTests(unittest.TestCase):
    def test_scans_every_file_for_private_network_and_credential_shapes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            samples = {
                "ula.txt": "fd12" + "::1234",
                "link-local.txt": "fe80" + "::1%eth0",
                "colon-mac.txt": ":".join(("02", "11", "22", "33", "44", "55")),
                "dotted-mac.txt": ".".join(("0211", "2233", "4455")),
                "credential.txt": "client_" + 'secret: "fictional-value-123"',
            }
            for name, value in samples.items():
                (root / name).write_text(value + "\n", encoding="utf-8")
            findings = scan_tree(root)
            rules = {finding.rule for finding in findings}
            self.assertIn("private-ipv6", rules)
            self.assertIn("mac-address", rules)
            self.assertIn("credential-assignment", rules)

    def test_recognizes_all_common_private_key_headers_and_env_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            labels = ("", "RSA ", "EC ", "DSA ", "ENCRYPTED ", "OPENSSH ")
            lines = ["-" * 5 + "BEGIN " + label + "PRIVATE" + " KEY" + "-" * 5 for label in labels]
            (root / "headers.txt").write_text("\n".join(lines), encoding="utf-8")
            (root / ".env.local").write_text("placeholder\n", encoding="utf-8")
            findings = scan_tree(root)
            self.assertEqual(
                sum(finding.rule == "private-key-block" for finding in findings),
                len(labels),
            )
            self.assertTrue(any(finding.rule == "secret-filename" for finding in findings))

    def test_private_denylist_stays_external_owner_only_and_never_echoes_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "public"
            root.mkdir()
            literal = "private-" + "estate-codename"
            (root / "untracked-note.txt").write_text(
                f"accidental {literal}\n",
                encoding="utf-8",
            )
            denylist = base / "denylist.txt"
            denylist.write_text(literal + "\n", encoding="utf-8")
            os.chmod(denylist, 0o600)
            findings = scan_tree(root, denylist=denylist)
            self.assertEqual(
                [finding.rule for finding in findings],
                ["private-denylist"],
            )
            self.assertNotIn(literal, repr(findings))

            inside = root / "denylist.txt"
            inside.write_text(literal + "\n", encoding="utf-8")
            os.chmod(inside, 0o600)
            with self.assertRaisesRegex(ValueError, "outside|remain"):
                scan_tree(root, denylist=inside)

            inside.unlink()
            os.chmod(denylist, 0o644)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                scan_tree(root, denylist=denylist)


if __name__ == "__main__":
    unittest.main()
