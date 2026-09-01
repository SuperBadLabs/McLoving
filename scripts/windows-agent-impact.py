#!/usr/bin/env python3
"""Classify whether a pull request can affect the hosted Windows agent gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any


ANCHOR_PACKAGES = {"mcloving-agent", "mcloving-migration-package"}
ALWAYS_RUN_PATHS = {
    ".cargo/config",
    ".cargo/config.toml",
    ".gitattributes",
    ".github/workflows/windows-agent.yml",
    "rust-toolchain.toml",
    "scripts/windows-agent-impact.py",
    "scripts/test-windows-agent-impact.py",
    "scripts/windows-agent-war.ps1",
}
ALWAYS_RUN_PATHS_CASEFOLDED = frozenset(path.casefold() for path in ALWAYS_RUN_PATHS)
WINDOWS_VERIFIER_DIRECTORIES = {
    Path("crates/boundary-differential"),
    Path("crates/differential-aggregate"),
    Path("crates/jenkins-differential"),
    Path("crates/jenkins-state-transfer"),
    Path("crates/migration-package"),
    Path("crates/state-policy-differential"),
}
WINDOWS_VERIFIER_INPUT_DIRECTORIES = {Path("migration")}
WINDOWS_RESERVED_STEMS = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
    "com¹",
    "com²",
    "com³",
    "lpt¹",
    "lpt²",
    "lpt³",
}
WINDOWS_INVALID_CHARACTERS = frozenset('<>:"\\|?*')
WINDOWS_PROTECTED_GIT_NAMES = {
    "gitmodules": "gi7eba",
    "gitattributes": "gi7d29",
    "gitignore": "gi250a",
    "mailmap": "maba30",
}


def run(
    *args: str,
    cwd: Path | None = None,
    text: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    completed = subprocess.run(
        args,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=text,
        env=env,
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
        "--no-renames",
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


def revision_paths(revision: str, repository: Path) -> set[str]:
    output = run(
        "git",
        "ls-tree",
        "-r",
        "--name-only",
        "-z",
        revision,
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
    cargo_path = shutil.which("cargo")
    rustc_path = shutil.which("rustc")
    if cargo_path is None or rustc_path is None:
        raise RuntimeError("trusted cargo and rustc executables must be on PATH")
    cargo = [cargo_path]
    if os.environ.get("MCLOVING_CARGO_NO_TOOLCHAIN") != "1":
        cargo.append("+1.97.1")
    # Candidate `.cargo/config*` changes are short-circuited before this
    # function. Pin the compiler controls anyway, so a trusted base config or
    # environment cannot accidentally delegate metadata to a wrapper. The
    # absolute executable paths are resolved before Cargo reads any tree.
    cargo.extend(
        (
            "--config",
            f"build.rustc={json.dumps(rustc_path)}",
            "--config",
            'build.rustc-wrapper=""',
            "--config",
            'build.rustc-workspace-wrapper=""',
        )
    )
    environment = dict(os.environ)
    for variable in (
        "RUSTC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "GITHUB_OUTPUT",
        "GITHUB_ENV",
        "GITHUB_PATH",
        "GITHUB_STEP_SUMMARY",
    ):
        environment.pop(variable, None)
    return json.loads(
        run(
            *cargo,
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--manifest-path",
            str(tree / "Cargo.toml"),
            cwd=tree,
            env=environment,
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
    anchors = {
        package["name"]: package["id"]
        for package in metadata["packages"]
        if package["name"] in ANCHOR_PACKAGES and package.get("source") is None
    }
    if "mcloving-agent" not in anchors:
        raise RuntimeError(
            "expected workspace package mcloving-agent, "
            f"found {sorted(anchors)}"
        )

    pending = list(anchors.values())
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
    # The classified gate executes on Windows, whose checkout is
    # case-insensitive even though this classifier runs on Linux.
    candidate = PurePosixPath(path.casefold())
    root = PurePosixPath(directory.as_posix().casefold())
    return candidate == root or root in candidate.parents


def first_always_run_path(paths: set[str]) -> str | None:
    return next(
        (
            path
            for path in sorted(paths, key=lambda candidate: candidate.casefold())
            if path.casefold() in ALWAYS_RUN_PATHS_CASEFOLDED
        ),
        None,
    )


def is_protected_git_ntfs_alias(component: str) -> bool:
    """Mirror Git's protected 8.3-name grammar for control files."""
    candidate = component.casefold()
    if candidate == "git~1":
        return True

    for name, fallback_prefix in WINDOWS_PROTECTED_GIT_NAMES.items():
        if (
            len(candidate) == 8
            and candidate[:6] == name[:6]
            and candidate[6] == "~"
            and candidate[7] in "1234"
        ):
            return True

        if len(candidate) != 8 or "~" not in candidate:
            continue
        tilde = candidate.index("~")
        if (
            tilde <= 6
            and candidate[:tilde] == fallback_prefix[:tilde]
            and candidate[tilde + 1] in "123456789"
            and all(character in "0123456789" for character in candidate[tilde + 2 :])
        ):
            return True
    return False


def first_windows_unsafe_path(paths: set[str]) -> str | None:
    """Return a path Windows may normalize, reject, or collide at checkout."""
    seen_files: dict[str, str] = {}
    seen_directories: dict[str, str] = {}
    for path in sorted(paths, key=lambda candidate: candidate.casefold()):
        components = PurePosixPath(path).parts
        for component in components:
            stem = component.split(".", 1)[0].rstrip(" .").casefold()
            folded_component = component.casefold()
            if (
                component.endswith((".", " "))
                or any(character in WINDOWS_INVALID_CHARACTERS for character in component)
                or any(ord(character) < 32 for character in component)
                or stem in WINDOWS_RESERVED_STEMS
                or folded_component == ".git"
                or is_protected_git_ntfs_alias(component)
                or len(component.encode("utf-8")) > 255
            ):
                return path
        folded_components = tuple(component.casefold() for component in components)
        for index in range(1, len(folded_components)):
            directory_key = "/".join(folded_components[:index])
            if directory_key in seen_files:
                return path
            directory = "/".join(components[:index])
            if (
                directory_key in seen_directories
                and seen_directories[directory_key] != directory
            ):
                return path
            seen_directories[directory_key] = directory

        key = "/".join(folded_components)
        if key in seen_directories:
            return path
        if key in seen_files and seen_files[key] != path:
            return path
        seen_files[key] = path
    return None


def classify(
    paths: set[str],
    base_directories: set[Path],
    head_directories: set[Path],
    base_closure: str,
    head_closure: str,
    base_policy: str,
    head_policy: str,
) -> tuple[bool, str]:
    unsafe = first_windows_unsafe_path(paths)
    if unsafe is not None:
        return True, f"Windows-unsafe or colliding path changed: {unsafe}"

    always = first_always_run_path(paths)
    if always is not None:
        return True, f"gate definition changed: {always}"

    for path in sorted(paths):
        for directory in WINDOWS_VERIFIER_INPUT_DIRECTORIES:
            if path_is_within(path, directory):
                return True, f"Windows verifier input changed: {path}"
        for directory in WINDOWS_VERIFIER_DIRECTORIES:
            if path_is_within(path, directory):
                return True, f"Windows verifier source changed: {path}"
        for directory in base_directories | head_directories:
            if path_is_within(path, directory):
                return True, f"Windows dependency source changed: {path}"

    if base_closure != head_closure:
        return True, "resolved Windows dependency closure changed"
    if base_policy != head_policy:
        return True, "workspace build policy changed"
    return False, "no Windows production or verifier dependency changed"


def emit_result(run_windows: bool, reason: str) -> None:
    print(f"Windows impact decision: {reason}", file=sys.stderr)
    print(f"run-windows={'true' if run_windows else 'false'}")


def classify_revisions(base: str, head: str, repository: Path) -> tuple[bool, str]:
    """Classify revisions without executing changed gate configuration."""
    paths = changed_paths(base, head, repository)
    unsafe = first_windows_unsafe_path(paths)
    if unsafe is not None:
        return True, f"Windows-unsafe or colliding path changed: {unsafe}"
    always = first_always_run_path(paths)
    if always is not None:
        return True, f"gate definition changed: {always}"

    head_issue = first_windows_unsafe_path(revision_paths(head, repository))
    if head_issue is not None:
        return True, f"Windows-unsafe or colliding head tree: {head_issue}"

    with tempfile.TemporaryDirectory(prefix="mcloving-windows-impact-") as root:
        root_path = Path(root)
        base_tree = root_path / "base"
        head_tree = root_path / "head"
        base_tree.mkdir()
        head_tree.mkdir()
        export_revision(base, repository, base_tree)
        export_revision(head, repository, head_tree)
        base_directories, base_digest = closure(cargo_metadata(base_tree), base_tree)
        head_directories, head_digest = closure(cargo_metadata(head_tree), head_tree)
        return classify(
            paths,
            base_directories,
            head_directories,
            base_digest,
            head_digest,
            root_policy(base_tree),
            root_policy(head_tree),
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    arguments = parser.parse_args()

    repository = arguments.repository.resolve()
    run_windows, reason = classify_revisions(arguments.base, arguments.head, repository)
    emit_result(run_windows, reason)


if __name__ == "__main__":
    main()
