from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from tests.test_evidence_probe import probe_config_value
from tests.test_live_export import live_inputs

ROOT = Path(__file__).resolve().parents[1]


def load(relative: str):
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


class JsonSchemaValidationTests(unittest.TestCase):
    def validate(self, schema_path: str, instance):
        schema = load(schema_path)
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
        self.assertEqual(errors, [], "\n".join(error.message for error in errors))

    def test_public_catalog_and_snapshot_validate(self):
        self.validate("policies/schema-v1.json", load("policies/examples/catalog.json"))
        self.validate(
            "fixtures/snapshot-schema-v1.json",
            load("fixtures/synthetic/snapshot.json"),
        )

    def test_private_contract_shapes_validate_with_fictional_inputs(self):
        _catalog, bindings, evidence, _responses = live_inputs()
        self.validate("deploy/contracts/live-bindings-schema-v1.json", bindings)
        self.validate("deploy/contracts/live-evidence-schema-v1.json", evidence)
        self.validate(
            "deploy/contracts/live-probe-config-schema-v1.json",
            probe_config_value(),
        )


if __name__ == "__main__":
    unittest.main()
