from __future__ import annotations

import unittest
from pathlib import Path

from lab_broker.fixtures import DEFAULT_CATALOG, DEFAULT_SNAPSHOT, load_demo

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DATA = ROOT / "src" / "lab_broker" / "data"


class PackageResourceTests(unittest.TestCase):
    def test_runtime_defaults_are_wheel_bundled_resources(self):
        self.assertEqual(DEFAULT_CATALOG, PACKAGE_DATA / "catalog.json")
        self.assertEqual(DEFAULT_SNAPSHOT, PACKAGE_DATA / "snapshot.json")
        catalog, snapshot = load_demo()
        self.assertEqual(snapshot.catalog_digest, catalog.digest)

    def test_reviewable_sources_and_bundled_resources_are_byte_identical(self):
        pairs = {
            ROOT / "policies/examples/catalog.json": PACKAGE_DATA / "catalog.json",
            ROOT / "fixtures/synthetic/snapshot.json": PACKAGE_DATA / "snapshot.json",
            ROOT / "policies/schema-v1.json": PACKAGE_DATA / "schemas/policy-schema-v1.json",
            ROOT / "fixtures/snapshot-schema-v1.json": PACKAGE_DATA
            / "schemas/snapshot-schema-v1.json",
            ROOT / "deploy/contracts/live-bindings-schema-v1.json": PACKAGE_DATA
            / "schemas/live-bindings-schema-v1.json",
            ROOT / "deploy/contracts/live-evidence-schema-v1.json": PACKAGE_DATA
            / "schemas/live-evidence-schema-v1.json",
            ROOT / "deploy/contracts/live-probe-config-schema-v1.json": PACKAGE_DATA
            / "schemas/live-probe-config-schema-v1.json",
        }
        for source, bundled in pairs.items():
            with self.subTest(resource=bundled.name):
                self.assertEqual(source.read_bytes(), bundled.read_bytes())


if __name__ == "__main__":
    unittest.main()
