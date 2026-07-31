#!/usr/bin/env python3
"""Classify whether a pull request can affect the hosted Windows agent gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any


ANCHOR_PACKAGE = "mcloving-agent"
ALWAYS_RUN_PATHS = {
    ".github/workflows/windows-agent.yml",
    "rust-toolchain.toml",
    "scripts/windows-agent-impact.py",
    "scripts/test-windows-agent-impact.py",
    "scripts/windows-agent-war.ps1",
}


def run(*args: str, cwd: Path | None = None, text: bool = True) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        args,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=text,
    )
    if completed.returncode != 0:
        stderr = completed.stderr
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(args)}\n{stderr}"
        )
    return completed


def changed_paths(base: str, head: str, repository: Path) -> set[str]:
    output = run(
        "git",
        "diff",
        "--name-only",
        "-z",
        base,
        head,
        cwd=repository,
        text=False,
    ).stdout
    return {
        entry.decode("utf-8")
        for entry in output.split(b"\0")
        if entry
    }


def export_revision(revision: str, repository: Path, destination: Path) -> None:
    archive = run(
        "git",
        "archive",
        "--format=tar",
        revision,
        cwd=repository,
        text=False,
    ).stdout
    with tempfile.NamedTemporaryFile(suffix=".tar") as handle:
        handle.write(archive)
        handle.flush()
        with tarfile.open(handle.name) as source:
            destination_root = destination.resolve()
            for member in source.getmembers():
                member_path = PurePosixPath(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise RuntimeError(f"unsafe archive member: {member.name}")
                if member.issym() or member.islnk():
                    raise RuntimeError(f"archive links are not admitted: {member.name}")
                target = (destination / member.name).resolve()
                if destination_root != target and destination_root not in target.parents:
                    raise RuntimeError(f"archive member escapes destination: {member.name}")
            source.extractall(destination)


def cargo_metadata(tree: Path) -> dict[str, Any]:
    cargo = ["cargo"]
    if os.environ.get("MCLOVING_CARGO_NO_TOOLCHAIN") != "1":
        cargo.append("+1.97.1")
    return json.loads(
        run(
            *cargo,
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--manifest-path",
            str(tree / "Cargo.toml"),
        ).stdout
    )


def package_key(package: dict[str, Any]) -> tuple[str, str, str]:
    return (
        package["name"],
        package["version"],
        package.get("source") or "workspace",
    )


def closure(metadata: dict[str, Any], tree: Path) -> tuple[set[Path], str]:
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    anchors = [
        package["id"]
        for package in metadata["packages"]
        if package["name"] == ANCHOR_PACKAGE and package.get("source") is None
    ]
    if len(anchors) != 1:
        raise RuntimeError(
            f"expected one workspace package named {ANCHOR_PACKAGE}, found {len(anchors)}"
        )

    pending = anchors
    package_ids: set[str] = set()
    while pending:
        package_id = pending.pop()
        if package_id in package_ids:
            continue
        package_ids.add(package_id)
        pending.extend(nodes[package_id]["dependencies"])

    local_directories: set[Path] = set()
    for package_id in package_ids:
        package = packages[package_id]
        if package.get("source") is None:
            manifest = Path(package["manifest_path"]).resolve()
            local_directories.add(manifest.parent.relative_to(tree.resolve()))

    normalized_nodes = []
    for package_id in sorted(package_ids, key=lambda item: package_key(packages[item])):
        node = nodes[package_id]
        dependencies = []
        for dependency in node.get("deps", []):
            dependency_id = dependency["pkg"]
            if dependency_id not in package_ids:
                continue
            dependencies.append(
                {
                    "package": package_key(packages[dependency_id]),
                    "name": dependency["name"],
                    "kinds": sorted(
                        (
                            kind.get("kind") or "normal",
                            kind.get("target") or "",
                        )
                        for kind in dependency.get("dep_kinds", [])
                    ),
                }
            )
        normalized_nodes.append(
            {
                "package": package_key(packages[package_id]),
                "dependencies": sorted(
                    dependencies,
                    key=lambda item: (
                        item["package"],
                        item["name"],
                        item["kinds"],
                    ),
                ),
            }
        )

    encoded = json.dumps(
        normalized_nodes,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return local_directories, hashlib.sha256(encoded).hexdigest()


def root_policy(tree: Path) -> str:
    with (tree / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    workspace = manifest.get("workspace")
    if isinstance(workspace, dict):
        workspace = dict(workspace)
        workspace.pop("members", None)
        manifest = dict(manifest)
        manifest["workspace"] = workspace
    encoded = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def path_is_within(path: str, directory: Path) -> bool:
    candidate = PurePosixPath(path)
    root = PurePosixPath(directory.as_posix())
    return candidate == root or root in candidate.parents


def classify(
    paths: set[str],
    base_directories: set[Path],
    head_directories: set[Path],
    base_closure: str,
    head_closure: str,
    base_policy: str,
    head_policy: str,
) -> tuple[bool, str]:
    always = sorted(paths & ALWAYS_RUN_PATHS)
    if always:
        return True, f"gate definition changed: {always[0]}"

    for path in sorted(paths):
        for directory in base_directories | head_directories:
            if path_is_within(path, directory):
                return True, f"agent dependency source changed: {path}"

    if base_closure != head_closure:
        return True, "resolved agent dependency closure changed"
    if base_policy != head_policy:
        return True, "workspace build policy changed"
    return False, "no Windows agent production or test dependency changed"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    arguments = parser.parse_args()

    repository = arguments.repository.resolve()
    paths = changed_paths(arguments.base, arguments.head, repository)
    with tempfile.TemporaryDirectory(prefix="mcloving-windows-impact-") as root:
        root_path = Path(root)
        base_tree = root_path / "base"
        head_tree = root_path / "head"
        base_tree.mkdir()
        head_tree.mkdir()
        export_revision(arguments.base, repository, base_tree)
        export_revision(arguments.head, repository, head_tree)
        base_directories, base_digest = closure(cargo_metadata(base_tree), base_tree)
        head_directories, head_digest = closure(cargo_metadata(head_tree), head_tree)
        run_windows, reason = classify(
            paths,
            base_directories,
            head_directories,
            base_digest,
            head_digest,
            root_policy(base_tree),
            root_policy(head_tree),
        )

    print(f"run-windows={'true' if run_windows else 'false'}")
    print(f"reason={reason}")


if __name__ == "__main__":
    main()
