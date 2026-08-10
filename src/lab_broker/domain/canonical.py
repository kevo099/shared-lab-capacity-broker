"""Canonical JSON helpers used for immutable policy and plan evidence."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from typing import Any


def _duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def strict_json_loads(raw: str | bytes) -> Any:
    """Load JSON while rejecting duplicate keys and non-finite numbers."""

    return json.loads(
        raw,
        object_pairs_hook=_duplicate_object,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite JSON number")),
    )


def _assert_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > 32:
        raise ValueError("JSON nesting exceeds the canonical limit")
    if value is None or isinstance(value, (str, bool)):
        return
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise ValueError("integer exceeds signed 64-bit range")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("non-finite JSON number")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _assert_json_value(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("canonical JSON object keys must be strings")
            _assert_json_value(item, depth=depth + 1)
        return
    raise ValueError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return stable UTF-8 JSON bytes for the repository's version-one contract.

    This intentionally supports integer-valued broker evidence only. It is a
    compact deterministic profile, not a claim of complete RFC 8785 support.
    The profile name is included in every digest-bearing schema.
    """

    _assert_json_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()
