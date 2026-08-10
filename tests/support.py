from __future__ import annotations

import copy
import json
from pathlib import Path

from lab_broker.domain.types import Catalog, Snapshot

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "policies" / "examples" / "catalog.json"
SNAPSHOT_PATH = ROOT / "fixtures" / "synthetic" / "snapshot.json"
GIB = 1024**3


def raw_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def raw_snapshot() -> dict:
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


def catalog(mutator=None) -> Catalog:
    value = copy.deepcopy(raw_catalog())
    if mutator:
        mutator(value)
    return Catalog.from_dict(value)


def snapshot(mutator=None) -> Snapshot:
    value = copy.deepcopy(raw_snapshot())
    if mutator:
        mutator(value)
    return Snapshot.from_dict(value)


def environment(value: dict, environment_id: str) -> dict:
    return next(item for item in value["environments"] if item["id"] == environment_id)


def guest(value: dict, guest_id: str) -> dict:
    return next(item for item in value["guests"] if item["id"] == guest_id)


def node(value: dict, node_id: str) -> dict:
    return next(item for item in value["nodes"] if item["id"] == node_id)
