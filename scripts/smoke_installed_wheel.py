#!/usr/bin/env python3
"""Run from outside the checkout with only the built wheel installed."""

from __future__ import annotations

import importlib.resources

from lab_broker.domain.planner import build_overview
from lab_broker.fixtures import load_demo


def main() -> int:
    package = importlib.resources.files("lab_broker")
    required = (
        "data/catalog.json",
        "data/snapshot.json",
        "data/schemas/policy-schema-v1.json",
        "data/schemas/snapshot-schema-v1.json",
        "data/schemas/live-bindings-schema-v1.json",
        "data/schemas/live-evidence-schema-v1.json",
        "data/schemas/live-probe-config-schema-v1.json",
        "ui/static/index.html",
        "ui/static/app.css",
        "ui/static/app.js",
        "ui/static/favicon.svg",
    )
    if any(not package.joinpath(relative).is_file() for relative in required):
        raise SystemExit("installed wheel is missing a runtime resource")
    catalog, snapshot = load_demo()
    overview = build_overview(
        snapshot,
        catalog,
        evaluated_at=snapshot.demo_evaluation_time,
    )
    if not overview["ok"] or snapshot.catalog_digest != catalog.digest:
        raise SystemExit("installed wheel failed its deterministic demo smoke")
    print("installed wheel smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
