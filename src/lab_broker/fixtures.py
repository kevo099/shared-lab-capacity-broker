"""Bounded, symlink-resistant loading for public synthetic JSON inputs."""

from __future__ import annotations

import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any

from .domain.canonical import canonical_json, strict_json_loads
from .domain.types import Catalog, InputError, Snapshot

MAX_FIXTURE_BYTES = 2 * 1024 * 1024
PACKAGE_DATA = Path(__file__).resolve().parent / "data"
DEFAULT_CATALOG = PACKAGE_DATA / "catalog.json"
DEFAULT_SNAPSHOT = PACKAGE_DATA / "snapshot.json"


def read_json_file(path: Path) -> Any:
    if not path.is_absolute():
        raise InputError("fixture path must be absolute")
    try:
        if path.resolve(strict=True) != path:
            raise InputError("fixture path cannot contain a symlink")
    except OSError as exc:
        raise InputError("fixture is unavailable") from exc
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InputError("fixture is unavailable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FIXTURE_BYTES:
            raise InputError("fixture is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = MAX_FIXTURE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(raw) > MAX_FIXTURE_BYTES:
            raise InputError("fixture exceeds its size limit")
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise InputError("fixture changed while it was read")
        return strict_json_loads(raw)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("fixture is not strict JSON") from exc
    finally:
        os.close(descriptor)


def load_catalog(path: Path = DEFAULT_CATALOG) -> Catalog:
    return Catalog.from_dict(read_json_file(path))


def load_snapshot(path: Path = DEFAULT_SNAPSHOT) -> Snapshot:
    return Snapshot.from_dict(read_json_file(path))


def load_demo() -> tuple[Catalog, Snapshot]:
    return load_catalog(), load_snapshot()


def write_atomic_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    """Durably replace one JSON file without following directory symlinks."""

    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise InputError("output path must be an absolute file path")
    parent = path.parent
    try:
        if parent.resolve(strict=True) != parent:
            raise InputError("output directory cannot contain a symlink")
    except OSError as exc:
        raise InputError("output directory is unavailable") from exc
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory = os.open(parent, flags)
    except OSError as exc:
        raise InputError("output directory is unavailable") from exc

    temporary = f".{path.name}.tmp-{secrets.token_hex(8)}"
    descriptor: int | None = None
    try:
        try:
            existing = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise InputError("output target must be a regular file")
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_CLOEXEC"):
            create_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            create_flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, create_flags, mode, dir_fd=directory)
        payload = canonical_json(value) + b"\n"
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(
            temporary,
            path.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        os.fsync(directory)
    except (OSError, ValueError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("atomic snapshot write failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        finally:
            os.close(directory)
