from __future__ import annotations

import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "lab_broker" / "ui" / "static"


class ScriptParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts: list[dict[str, str | None]] = []
        self.styles: list[dict[str, str | None]] = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "script":
            self.scripts.append(values)
        if tag == "style":
            self.styles.append(values)


class DashboardContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (STATIC / "index.html").read_text(encoding="utf-8")
        cls.css = (STATIC / "app.css").read_text(encoding="utf-8")
        cls.js = (STATIC / "app.js").read_text(encoding="utf-8")

    def test_assets_are_local_and_inline_script_and_style_are_absent(self):
        parser = ScriptParser()
        parser.feed(self.html)
        self.assertEqual(parser.styles, [])
        self.assertEqual(len(parser.scripts), 1)
        self.assertEqual(parser.scripts[0].get("src"), "static/app.js")
        combined = self.html + self.css + self.js
        self.assertNotRegex(combined, r"https?://")
        self.assertNotIn("cdn", combined.lower())

    def test_dashboard_contains_required_operations_console_surfaces(self):
        for required in (
            "Read-only planning workspace",
            "Operational summary",
            "Single exam slot",
            "Node capacity",
            "Environment matrix",
            "Coexists with",
            "Required donors",
            "Plan evidence",
            "NO EXECUTOR INSTALLED",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.html)
        self.assertIn("--canvas", self.css)
        self.assertIn("--blue", self.css)
        self.assertIn("command-bar", self.css)
        self.assertIn("@media", self.css)
        self.assertIn("prefers-reduced-motion", self.css)

    def test_frontend_has_no_unsafe_html_sink_or_mutating_request(self):
        for forbidden in (
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
            'method: "POST"',
            'method: "PUT"',
            'method: "PATCH"',
            'method: "DELETE"',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.js)
        self.assertIn("textContent", self.js)
        self.assertIn('method: "GET"', self.js)
        self.assertIn('fetchJson(appPath("api/v1/overview"))', self.js)
        self.assertIn('byId("release-mode").textContent = live', self.js)
        self.assertIn('"Swap evidence unavailable"', self.js)
        self.assertIn('gate.status === "conditional"', self.js)
        self.assertIn("plan.capacity.nodes", self.js)

    def test_dynamic_environment_path_is_allowlisted_before_fetch(self):
        self.assertIn("/^[a-z0-9][a-z0-9-]{0,63}$/", self.js)
        self.assertIn("encodeURIComponent(environmentId)", self.js)
        self.assertIn('const appRoot = new URL(".", document.baseURI)', self.js)
        self.assertNotIn('href="/static/', self.html)
        # Network access is centralized in the fixed-options wrapper. The only
        # dynamic call site first validates the semantic alias, then encodes it.
        self.assertEqual(self.js.count("fetch("), 1)
        self.assertRegex(
            self.js,
            re.compile(
                r"async function fetchJson\(path\)\s*\{\s*const response = await fetch\(path,",
                re.DOTALL,
            ),
        )
        self.assertNotRegex(self.js, re.compile(r"fetch\(\s*`"))
        self.assertIn('byId("plan-detail").scrollIntoView', self.js)

    def test_accessibility_contract_is_present(self):
        for required in (
            'lang="en"',
            'class="skip-link"',
            'aria-live="polite"',
            'aria-label="Primary navigation"',
            "<caption",
            'scope="col"',
            'for="environment-filter"',
            'tabindex="-1"',
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.html)
        self.assertIn(":focus-visible", self.css)

    def test_failure_copy_is_explicitly_fail_closed(self):
        for phrase in (
            "No current node evidence. Capacity is unknown.",
            "No start decision can be made.",
            "The dashboard failed closed.",
        ):
            self.assertIn(phrase, self.js)


if __name__ == "__main__":
    unittest.main()
