#!/usr/bin/env python3
"""Fail closed when a proposed public tree contains common private material."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

MAX_TEXT_BYTES = 2 * 1024 * 1024
EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "htmlcov",
    }
)
SECRET_SUFFIXES = frozenset({".key", ".p12", ".pfx", ".pem"})
SECRET_NAMES = frozenset(
    {
        ".env",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "secrets",
        "secrets.json",
    }
)
MAX_DENYLIST_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class Finding:
    path: Path
    line: int | None
    rule: str


def _patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    private_ipv4 = re.compile(
        r"(?<![\d.])(?:"
        + r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        + r"|192\.168\.\d{1,3}\.\d{1,3}"
        + r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        + r")(?![\d.])"
    )
    absolute_user_path = re.compile(r"/(?:home|Users)/[A-Za-z0-9._-]+(?:/|\b)")
    private_ipv6 = re.compile(
        r"(?<![0-9A-Fa-f:])"
        r"f(?:[cd][0-9A-Fa-f]{2}|e[89ab][0-9A-Fa-f])"
        r"(?::[0-9A-Fa-f]{0,4}){1,7}"
        r"(?:%[A-Za-z0-9_.-]{1,32})?"
        r"(?![0-9A-Fa-f:])",
        re.IGNORECASE,
    )
    mac_address = re.compile(
        r"(?<![0-9A-Fa-f:.-])(?:"
        r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
        r"|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}"
        r")(?![0-9A-Fa-f:.-])"
    )
    credential_assignment = re.compile(
        r"(?i)(?<![A-Za-z0-9])['\"]?"
        r"(?:[A-Za-z][A-Za-z0-9_.-]{0,63})?"
        r"(?:api[_-]?key|password|passwd|private[_-]?key|secret|token)"
        r"[A-Za-z0-9_.-]{0,32}['\"]?\s*[:=]\s*"
        r"(?:['\"][^'\"\r\n]{8,}['\"]|"
        r"[A-Za-z0-9][A-Za-z0-9_./+@=:-]{11,})"
        r"(?=\s*(?:[,}]|#.*)?$)"
    )
    userinfo_url = re.compile(r"(?i)https?://[^\s/@:]+:[^\s/@]+@")
    pem_marker = re.compile(
        re.escape("-" * 5 + "BEGIN ") + r"(?:[A-Z0-9]+[ ]+)*PRIVATE[ ]+KEY" + re.escape("-" * 5),
        re.IGNORECASE,
    )
    return (
        ("private-ipv4", private_ipv4),
        ("private-ipv6", private_ipv6),
        ("mac-address", mac_address),
        ("absolute-user-path", absolute_user_path),
        ("credential-assignment", credential_assignment),
        ("url-userinfo", userinfo_url),
        ("private-key-block", pem_marker),
    )


def _public_files(root: Path):
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.is_symlink():
            yield path, "symlink"
        elif path.is_file():
            yield path, "file"


def _load_denylist(path: Path | None, root: Path) -> tuple[str, ...]:
    if path is None:
        return ()
    resolved = path.expanduser().resolve(strict=True)
    if resolved.is_relative_to(root):
        raise ValueError("the private denylist must remain outside the public tree")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(resolved, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size > MAX_DENYLIST_BYTES
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("the private denylist must be an owner-only bounded regular file")
        chunks: list[bytes] = []
        remaining = MAX_DENYLIST_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw_bytes = b"".join(chunks)
        if len(raw_bytes) > MAX_DENYLIST_BYTES:
            raise ValueError("the private denylist exceeds its size limit")
    finally:
        os.close(descriptor)
    try:
        lines = raw_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("the private denylist must be UTF-8 text") from exc
    values: list[str] = []
    for raw_line in lines:
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        if not 2 <= len(value.encode("utf-8")) <= 256 or any(ord(char) < 0x20 for char in value):
            raise ValueError("the private denylist contains an invalid literal")
        values.append(value)
    if len(values) > 256 or len(set(values)) != len(values):
        raise ValueError("the private denylist is duplicated or too large")
    return tuple(values)


def scan_tree(root: Path, *, denylist: Path | None = None) -> list[Finding]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("public tree must be a directory")
    private_literals = _load_denylist(denylist, root)
    patterns = _patterns()
    findings: list[Finding] = []
    for path, kind in _public_files(root):
        relative = path.relative_to(root)
        if kind == "symlink":
            findings.append(Finding(relative, None, "symlink"))
            continue
        lowered = path.name.lower()
        if (
            path.suffix.lower() in SECRET_SUFFIXES
            or lowered in SECRET_NAMES
            or lowered.startswith(".env.")
            or lowered.endswith(".env")
        ):
            findings.append(Finding(relative, None, "secret-filename"))
        size = path.stat().st_size
        if size > MAX_TEXT_BYTES:
            findings.append(Finding(relative, None, "oversized-file"))
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule, pattern in patterns:
                if pattern.search(line):
                    findings.append(Finding(relative, line_number, rule))
            if any(literal in line for literal in private_literals):
                findings.append(Finding(relative, line_number, "private-denylist"))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--denylist", type=Path)
    args = parser.parse_args(argv)
    try:
        findings = scan_tree(args.root, denylist=args.denylist)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"public-tree scan refused input: {exc}", file=sys.stderr)
        return 2
    for finding in findings:
        location = str(finding.path)
        if finding.line is not None:
            location += f":{finding.line}"
        print(f"{location}: {finding.rule}", file=sys.stderr)
    if findings:
        print(f"public-tree scan failed with {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print("public-tree scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
