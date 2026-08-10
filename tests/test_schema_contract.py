from __future__ import annotations

import json
import unittest
from pathlib import Path

from lab_broker.domain.types import Catalog, Snapshot

ROOT = Path(__file__).resolve().parents[1]


class PublishedSchemaContractTests(unittest.TestCase):
    def load(self, relative: str):
        return json.loads((ROOT / relative).read_text(encoding="utf-8"))

    def assert_exact_shape(self, value: dict, schema: dict, optional=frozenset()):
        self.assertFalse(schema["additionalProperties"])
        required = set(schema["required"])
        properties = set(schema["properties"])
        self.assertTrue(required <= set(value) <= properties)
        self.assertEqual(properties - required, set(optional))

    def test_policy_fixture_and_published_schema_have_the_same_exact_shapes(self):
        schema = self.load("policies/schema-v1.json")
        fixture = self.load("policies/examples/catalog.json")
        self.assert_exact_shape(fixture, schema)
        environment_schema = schema["$defs"]["environment"]
        donor_schema = schema["$defs"]["donorSet"]
        for environment in fixture["environments"]:
            self.assert_exact_shape(environment, environment_schema, {"placements"})
            for donor_set in environment["donor_sets"]:
                self.assert_exact_shape(donor_set, donor_schema)
        Catalog.from_dict(fixture)

    def test_snapshot_fixture_and_published_schema_have_the_same_exact_shapes(self):
        schema = self.load("fixtures/snapshot-schema-v1.json")
        fixture = self.load("fixtures/synthetic/snapshot.json")
        self.assert_exact_shape(fixture, schema)
        mappings = {
            "nodes": "node",
            "guests": "guest",
            "backups": "backup",
            "leases": "lease",
            "reservations": "reservation",
        }
        for collection, definition in mappings.items():
            for value in fixture[collection]:
                self.assert_exact_shape(value, schema["$defs"][definition])
        Snapshot.from_dict(fixture)

    def test_every_published_schema_is_strict_json_and_versioned(self):
        for relative in (
            "policies/schema-v1.json",
            "fixtures/snapshot-schema-v1.json",
            "deploy/contracts/live-bindings-schema-v1.json",
            "deploy/contracts/live-evidence-schema-v1.json",
            "deploy/contracts/live-probe-config-schema-v1.json",
        ):
            with self.subTest(path=relative):
                schema = self.load(relative)
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertTrue(schema["$id"].endswith(":v1"))
                self.assertFalse(schema["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
