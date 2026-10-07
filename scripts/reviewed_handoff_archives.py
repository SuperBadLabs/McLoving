"""Content-pinned archival Markdown scope; no authorship or authority assertion.

Only independently reviewed registry commitments authorize an exclusion. The
archive's editable manifest cannot choose its own accepted digest. Optional
units may be absent; a present unit must have its exact regular sealed manifest.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Iterator

REGISTRY = Path(__file__).with_name("stale-claims-archives.json")
SCHEMA = "hyg-003-reviewed-handoff-archives-v1"
HEX = re.compile(r"[0-9a-f]{64}")
MANIFEST_LINE = re.compile(r"(?P<digest>[0-9a-f]{64})  (?P<path>.+)")


class ArchiveScopeError(ValueError):
    """A registry or manifest cannot establish the reviewed content boundary."""


def relative_parts(value: str) -> tuple[str, ...]:
    if (not isinstance(value, str) or not value or "\\" in value or "\x00" in value
            or value.startswith("/") or re.match(r"^[A-Za-z]:", value)
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise ArchiveScopeError("noncanonical or escaping archive path")
    return tuple(value.split("/"))


@contextmanager
def directory_fd(repository: Path, parts: tuple[str, ...]) -> Iterator[int]:
    """Traverse every in-repository ancestor without following aliases."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(repository, flags)
    try:
        for part in parts:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def regular_bytes(repository: Path, relative: str) -> bytes:
    """Read one regular file from the same no-follow descriptor we validate."""
    parts = relative_parts(relative)
    with directory_fd(repository, parts[:-1]) as parent:
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ArchiveScopeError("archive path is not a regular file")
            with os.fdopen(fd, "rb", closefd=False) as source:
                return source.read()
        finally:
            os.close(fd)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ArchiveScopeError("duplicate registry key")
        result[name] = value
    return result


def read_registry() -> list[dict[str, str]]:
    data = regular_bytes(REGISTRY.parent, REGISTRY.name)
    registry = json.loads(data, object_pairs_hook=unique_object)
    if (not isinstance(registry, dict) or set(registry) != {"schema", "units"}
            or registry["schema"] != SCHEMA or not isinstance(registry["units"], list)
            or len(registry["units"]) != 3):
        raise ArchiveScopeError("malformed reviewed archive registry")
    seen: set[tuple[str, ...]] = set()
    for unit in registry["units"]:
        if not isinstance(unit, dict) or set(unit) != {"root", "manifest", "sha256"}:
            raise ArchiveScopeError("malformed reviewed archive unit")
        root = relative_parts(unit["root"])
        relative_parts(unit["manifest"])
        if root[:2] != ("docs", "handoffs") or len(root) < 3:
            raise ArchiveScopeError("archive unit must stay beneath docs/handoffs")
        if not isinstance(unit["sha256"], str) or HEX.fullmatch(unit["sha256"]) is None:
            raise ArchiveScopeError("malformed reviewed manifest commitment")
        if any(root[:len(other)] == other or other[:len(root)] == root for other in seen):
            raise ArchiveScopeError("duplicate or overlapping reviewed archive roots")
        seen.add(root)
    return registry["units"]


def parse_manifest(data: bytes) -> dict[str, str]:
    """Accept the reviewed GNU text-seal shape, rejecting ambiguous paths."""
    if not data or not data.endswith(b"\n"):
        raise ArchiveScopeError("malformed archive manifest termination")
    entries = {}
    for line in data.decode("utf-8").splitlines():
        match = MANIFEST_LINE.fullmatch(line)
        if match is None:
            raise ArchiveScopeError("malformed archive manifest entry")
        path = match.group("path")
        relative_parts(path)
        if path in entries:
            raise ArchiveScopeError("duplicate archive manifest path")
        entries[path] = match.group("digest")
    return entries


def archive_scope(repository: Path) -> tuple[dict[str, str], list[str]]:
    """Return exact listed Markdown digests, not directory-wide eligibility."""
    eligible: dict[str, str] = {}
    defects: list[str] = []
    try:
        units = read_registry()
    except (OSError, ValueError, UnicodeError) as error:
        return {}, [f"archive scope: cannot validate reviewed registry: {error}"]
    for unit in units:
        root = unit["root"]
        try:
            with directory_fd(repository, relative_parts(root)):
                pass
        except FileNotFoundError:
            # Clean CI need not carry optional owner-local sealed archives.
            continue
        except OSError as error:
            defects.append(f"{root}: archive scope cannot open unit without symlink ancestors: {error}")
            continue
        manifest = root + "/" + unit["manifest"]
        try:
            data = regular_bytes(repository, manifest)
            entries = parse_manifest(data)
            if hashlib.sha256(data).hexdigest() != unit["sha256"]:
                raise ArchiveScopeError("archive seal commitment differs from reviewed registry")
        except (OSError, ValueError, UnicodeError) as error:
            defects.append(f"{manifest}: archive scope cannot validate sealed manifest: {error}")
            continue
        for path, digest in entries.items():
            if Path(path).suffix.lower() == ".md":
                eligible[root + "/" + path] = digest
    return eligible, defects
