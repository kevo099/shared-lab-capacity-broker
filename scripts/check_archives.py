#!/usr/bin/env python3
"""Verify that release archives contain the reviewed public resource set."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

WHEEL_RESOURCES = {
    "lab_broker/data/catalog.json": Path("policies/examples/catalog.json"),
    "lab_broker/data/snapshot.json": Path("fixtures/synthetic/snapshot.json"),
    "lab_broker/data/schemas/policy-schema-v1.json": Path("policies/schema-v1.json"),
    "lab_broker/data/schemas/snapshot-schema-v1.json": Path("fixtures/snapshot-schema-v1.json"),
    "lab_broker/data/schemas/live-bindings-schema-v1.json": Path(
        "deploy/contracts/live-bindings-schema-v1.json"
    ),
    "lab_broker/data/schemas/live-evidence-schema-v1.json": Path(
        "deploy/contracts/live-evidence-schema-v1.json"
    ),
    "lab_broker/data/schemas/live-probe-config-schema-v1.json": Path(
        "deploy/contracts/live-probe-config-schema-v1.json"
    ),
    "lab_broker/ui/static/app.css": Path("src/lab_broker/ui/static/app.css"),
    "lab_broker/ui/static/app.js": Path("src/lab_broker/ui/static/app.js"),
    "lab_broker/ui/static/favicon.svg": Path("src/lab_broker/ui/static/favicon.svg"),
    "lab_broker/ui/static/index.html": Path("src/lab_broker/ui/static/index.html"),
}
SDIST_REQUIRED = {
    "CONTRIBUTING.md",
    "DESIGN.md",
    "LICENSE",
    "NOTICE.md",
    "README.md",
    "ROADMAP.md",
    "SECURITY.md",
    "MANIFEST.in",
    "pyproject.toml",
    "requirements/ci.txt",
    "deploy/lab-broker-live.service",
    "deploy/lab-broker-synthetic.service",
    "deploy/nginx-lab-capacity.conf",
    "docs/LIVE-READ-ONLY.md",
    "fixtures/snapshot-schema-v1.json",
    "fixtures/synthetic/snapshot.json",
    "policies/examples/catalog.json",
    "policies/schema-v1.json",
    "scripts/check_archives.py",
    "scripts/check_public_tree.py",
    "scripts/smoke_installed_wheel.py",
}


def _safe(names: list[str]) -> bool:
    return all(
        name and not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts
        for name in names
    )


def main() -> int:
    wheels = sorted(Path("dist").glob("*.whl"))
    sdists = sorted(Path("dist").glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        print("expected exactly one wheel and one source archive", file=sys.stderr)
        return 1
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        if not _safe(names):
            print("wheel contains an unsafe path", file=sys.stderr)
            return 1
        for member, source in WHEEL_RESOURCES.items():
            if member not in names or archive.read(member) != source.read_bytes():
                print(f"wheel resource is missing or stale: {member}", file=sys.stderr)
                return 1
        if any(name.startswith(("tests/", "deploy/", "scripts/")) for name in names):
            print("wheel contains a non-runtime tree", file=sys.stderr)
            return 1
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            print("wheel metadata is missing or ambiguous", file=sys.stderr)
            return 1
        metadata = archive.read(metadata_names[0]).decode("utf-8")
        for marker in (
            "Name: shared-lab-capacity-broker",
            "Version: 0.1.0",
            "License-Expression: Apache-2.0",
            "Requires-Python: <3.15,>=3.12",
        ):
            if marker not in metadata:
                print(f"wheel metadata is missing: {marker}", file=sys.stderr)
                return 1
    with tarfile.open(sdists[0], mode="r:gz") as archive:
        names = archive.getnames()
        if not _safe(names):
            print("source archive contains an unsafe path", file=sys.stderr)
            return 1
        roots = {PurePosixPath(name).parts[0] for name in names if name}
        if len(roots) != 1:
            print("source archive has an ambiguous root", file=sys.stderr)
            return 1
        root = next(iter(roots))
        missing = [item for item in SDIST_REQUIRED if f"{root}/{item}" not in names]
        if missing:
            print(
                f"source archive is missing: {', '.join(sorted(missing))}",
                file=sys.stderr,
            )
            return 1
        members = {member.name: member for member in archive.getmembers()}
        for wheel_member, source in WHEEL_RESOURCES.items():
            bundled = Path("src") / wheel_member
            source_name = f"{root}/{source.as_posix()}"
            bundled_name = f"{root}/{bundled.as_posix()}"
            if source_name not in members or bundled_name not in members:
                print(
                    f"source archive resource pair is missing: {source}",
                    file=sys.stderr,
                )
                return 1
            source_file = archive.extractfile(members[source_name])
            bundled_file = archive.extractfile(members[bundled_name])
            if (
                source_file is None
                or bundled_file is None
                or source_file.read() != source.read_bytes()
                or bundled_file.read() != source.read_bytes()
            ):
                print(
                    f"source archive resource is stale: {source}",
                    file=sys.stderr,
                )
                return 1
    print("release archives passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
