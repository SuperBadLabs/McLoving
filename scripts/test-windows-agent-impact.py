#!/usr/bin/env python3
"""Focused tests for the Windows-agent impact classifier."""

from __future__ import annotations

import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("windows-agent-impact.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("windows_agent_impact", SCRIPT)
assert SPEC and SPEC.loader
IMPACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPACT)


class WindowsAgentImpactTests(unittest.TestCase):
    def test_protected_git_ntfs_alias_grammar(self) -> None:
        for component in (
            "GIT~1",
            "GITMOD~1",
            "GITMOD~4",
            "GI7EBA~1",
            "GI7EB~12",
            "~1234567",
            "MAILMA~3",
            "MABA3~19",
        ):
            with self.subTest(component=component):
                self.assertTrue(IMPACT.is_protected_git_ntfs_alias(component))

        for component in (
            "GIT~2",
            "GITMOD~0",
            "GITMOD~5",
            "GI7EB~02",
            "GI7EB~1X",
            "GI7EBA~12",
            "ordinary.txt",
        ):
            with self.subTest(component=component):
                self.assertFalse(IMPACT.is_protected_git_ntfs_alias(component))

    def test_changed_cargo_configuration_short_circuits_before_execution(self) -> None:
        for path in (
            ".Cargo/Config.TOML",
            "crates/domain./src/lib.rs",
            "GIT~1/config",
            "GITMOD~4",
            "GI7EBA~1",
            "GI7EB~12",
            "docs/\u0131.txt",
        ):
            with (
                self.subTest(path=path),
                mock.patch.object(IMPACT, "changed_paths", return_value={path}),
                mock.patch.object(
                    IMPACT,
                    "revision_paths",
                    side_effect=AssertionError("short circuit must precede inventory"),
                ),
                mock.patch.object(
                    IMPACT,
                    "export_revision",
                    side_effect=AssertionError("candidate revision must not execute"),
                ),
                mock.patch.object(
                    IMPACT,
                    "cargo_metadata",
                    side_effect=AssertionError("candidate Cargo config must not load"),
                ),
            ):
                run_windows, reason = IMPACT.classify_revisions(
                    "base", "head", Path(".")
                )
            self.assertTrue(run_windows)
            self.assertIn(path, reason)

    def test_complete_head_inventory_detects_case_collision(self) -> None:
        for changed, inventory in (
            (
                "docs/README.md",
                {"docs/Readme.md", "docs/README.md"},
            ),
            (
                "docs/README/child.txt",
                {"docs/Readme", "docs/README/child.txt"},
            ),
            (
                "docs/README/b.txt",
                {"docs/Readme/a.txt", "docs/README/b.txt"},
            ),
            (
                "docs/README.md",
                {"docs/I.txt", "docs/\u0131.txt", "docs/README.md"},
            ),
        ):
            with (
                self.subTest(changed=changed),
                mock.patch.object(IMPACT, "changed_paths", return_value={changed}),
                mock.patch.object(IMPACT, "revision_paths", return_value=inventory),
                mock.patch.object(
                    IMPACT,
                    "export_revision",
                    side_effect=AssertionError("colliding revision must not export"),
                ),
                mock.patch.object(
                    IMPACT,
                    "cargo_metadata",
                    side_effect=AssertionError("colliding revision must not run Cargo"),
                ),
            ):
                run_windows, reason = IMPACT.classify_revisions(
                    "base", "head", Path(".")
                )
            self.assertTrue(run_windows)
            self.assertIn("colliding head tree", reason)

    def test_cargo_metadata_pins_compiler_controls(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"packages": []}', stderr=""
        )
        with tempfile.TemporaryDirectory() as root:
            tree = Path(root)
            with (
                mock.patch.object(
                    IMPACT.shutil,
                    "which",
                    side_effect=("/trusted/cargo", "/trusted/rustc"),
                ),
                mock.patch.object(IMPACT, "run", return_value=completed) as command,
                mock.patch.dict(
                    IMPACT.os.environ,
                    {
                        "MCLOVING_CARGO_NO_TOOLCHAIN": "1",
                        "RUSTC": "/candidate/rustc",
                        "RUSTC_WRAPPER": "/candidate/wrapper",
                        "RUSTC_WORKSPACE_WRAPPER": "/candidate/workspace-wrapper",
                        "CARGO_BUILD_RUSTC": "/candidate/rustc",
                        "CARGO_BUILD_RUSTC_WRAPPER": "/candidate/wrapper",
                        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER":
                            "/candidate/workspace-wrapper",
                        "GITHUB_OUTPUT": "/runner/command/output",
                        "GITHUB_ENV": "/runner/command/env",
                        "GITHUB_PATH": "/runner/command/path",
                        "GITHUB_STEP_SUMMARY": "/runner/command/summary",
                    },
                ),
            ):
                self.assertEqual(IMPACT.cargo_metadata(tree), {"packages": []})

        arguments = command.call_args.args
        options = command.call_args.kwargs
        self.assertEqual(
            arguments,
            (
                "/trusted/cargo",
                "--config",
                'build.rustc="/trusted/rustc"',
                "--config",
                'build.rustc-wrapper=""',
                "--config",
                'build.rustc-workspace-wrapper=""',
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--manifest-path",
                str(tree / "Cargo.toml"),
            ),
        )
        self.assertEqual(options["cwd"], tree)
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
            self.assertNotIn(variable, options["env"])

    def test_closure_includes_migration_verifier_dependencies(self) -> None:
        directories, _digest = IMPACT.closure(IMPACT.cargo_metadata(Path.cwd()), Path.cwd())
        self.assertTrue(
            {
                Path("bins/agent"),
                Path("crates/differential-aggregate"),
                Path("crates/jenkins-compiler-admission"),
                Path("crates/jenkins-mapping-catalog"),
                Path("crates/migration-package"),
                Path("crates/pipeline-ir"),
                Path("crates/state-policy-differential"),
            }
            <= directories
        )

    def test_rename_preserves_source_and_destination_paths(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            repository = Path(root)
            subprocess.run(["git", "init"], cwd=repository, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.email", "classifier@example.invalid"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Classifier Test"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "diff.renames", "true"],
                cwd=repository,
                check=True,
            )
            scripts = repository / "scripts"
            scripts.mkdir()
            source = scripts / "windows-agent-war.ps1"
            source.write_text("Write-Host 'war'\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repository, check=True)
            subprocess.run(
                ["git", "commit", "-m", "base"],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            base = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            source.rename(scripts / "windows-war.ps1")
            subprocess.run(["git", "add", "-A"], cwd=repository, check=True)
            subprocess.run(
                ["git", "commit", "-m", "rename"],
                cwd=repository,
                check=True,
                capture_output=True,
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            paths = IMPACT.changed_paths(base, head, repository)

        self.assertEqual(
            paths,
            {"scripts/windows-agent-war.ps1", "scripts/windows-war.ps1"},
        )

    def test_unrelated_workspace_member_does_not_trigger(self) -> None:
        run_windows, reason = IMPACT.classify(
            {"crates/jenkins-inventory/src/lib.rs", "Cargo.toml", "Cargo.lock"},
            {Path("bins/agent"), Path("crates/domain")},
            {Path("bins/agent"), Path("crates/domain")},
            "same-closure",
            "same-closure",
            "same-policy",
            "same-policy",
        )
        self.assertFalse(run_windows)
        self.assertIn("no Windows production or verifier", reason)

    def test_local_dependency_source_triggers(self) -> None:
        run_windows, reason = IMPACT.classify(
            {"crates/domain/src/lib.rs"},
            {Path("bins/agent"), Path("crates/domain")},
            {Path("bins/agent"), Path("crates/domain")},
            "same",
            "same",
            "same",
            "same",
        )
        self.assertTrue(run_windows)
        self.assertIn("Windows dependency source", reason)

        for paths in (
            {"crates/domain./src/lib.rs"},
            {"docs/NUL.txt"},
            {"GIT~1/config"},
            {"GITMOD~4"},
            {"GI7EBA~1"},
            {"GI7EB~12"},
            {"docs/\u0131.txt"},
            {"docs/Readme.md", "docs/README.md"},
            {"docs/Readme", "docs/README/child.txt"},
            {"docs/Readme/a.txt", "docs/README/b.txt"},
        ):
            with self.subTest(paths=paths):
                run_windows, reason = IMPACT.classify(
                    paths,
                    {Path("bins/agent"), Path("crates/domain")},
                    {Path("bins/agent"), Path("crates/domain")},
                    "same",
                    "same",
                    "same",
                    "same",
                )
                self.assertTrue(run_windows)
                self.assertIn("Windows-unsafe or colliding", reason)

        run_windows, reason = IMPACT.classify(
            {"CRATES/DOMAIN/src/lib.rs"},
            {Path("bins/agent"), Path("crates/domain")},
            {Path("bins/agent"), Path("crates/domain")},
            "same",
            "same",
            "same",
            "same",
        )
        self.assertTrue(run_windows)
        self.assertIn("Windows dependency source", reason)

    def test_windows_verifier_source_triggers(self) -> None:
        directories = {
            Path("bins/agent"),
            Path("crates/domain"),
            Path("crates/jenkins-compiler-admission"),
            Path("crates/jenkins-mapping-catalog"),
            Path("crates/jenkins-state-transfer"),
            Path("crates/migration-package"),
        }
        for path in (
            "crates/migration-package/src/lib.rs",
            "crates/jenkins-compiler-admission/src/lib.rs",
            "crates/jenkins-mapping-catalog/src/lib.rs",
            "crates/jenkins-state-transfer/src/lib.rs",
        ):
            with self.subTest(path=path):
                run_windows, reason = IMPACT.classify(
                    {path},
                    directories,
                    directories,
                    "same",
                    "same",
                    "same",
                    "same",
                )
                self.assertTrue(run_windows)
                self.assertIn("Windows", reason)

    def test_windows_verifier_evidence_triggers(self) -> None:
        run_windows, reason = IMPACT.classify(
            {"migration/migration-package-v1/migration-package.json"},
            {Path("bins/agent")},
            {Path("bins/agent")},
            "same",
            "same",
            "same",
            "same",
        )
        self.assertTrue(run_windows)
        self.assertIn("Windows verifier input", reason)

    def test_repository_cargo_configuration_triggers(self) -> None:
        for path in (
            ".cargo/config",
            ".cargo/config.toml",
            ".Cargo/Config.TOML",
            ".gitattributes",
            ".GITATTRIBUTES",
        ):
            with self.subTest(path=path):
                run_windows, reason = IMPACT.classify(
                    {path},
                    {Path("bins/agent")},
                    {Path("bins/agent")},
                    "same",
                    "same",
                    "same",
                    "same",
                )
                self.assertTrue(run_windows)
                self.assertIn("gate definition", reason)

    def test_reason_is_not_a_workflow_output(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        reason = "agent dependency source changed: bins/agent/x\nrun-windows=false"
        with redirect_stdout(stdout), redirect_stderr(stderr):
            IMPACT.emit_result(True, reason)
        self.assertEqual(stdout.getvalue(), "run-windows=true\n")
        self.assertIn(reason, stderr.getvalue())

    def test_resolved_external_dependency_change_triggers(self) -> None:
        run_windows, reason = IMPACT.classify(
            {"Cargo.lock"},
            {Path("bins/agent")},
            {Path("bins/agent")},
            "old",
            "new",
            "same",
            "same",
        )
        self.assertTrue(run_windows)
        self.assertIn("resolved Windows dependency", reason)

    def test_workspace_policy_change_triggers(self) -> None:
        run_windows, reason = IMPACT.classify(
            {"Cargo.toml"},
            {Path("bins/agent")},
            {Path("bins/agent")},
            "same",
            "same",
            "old",
            "new",
        )
        self.assertTrue(run_windows)
        self.assertIn("workspace build policy", reason)

    def test_members_are_excluded_from_root_policy(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            tree = Path(root)
            manifest = tree / "Cargo.toml"
            manifest.write_text(
                '[workspace]\nmembers = ["bins/agent"]\nresolver = "2"\n',
                encoding="utf-8",
            )
            before = IMPACT.root_policy(tree)
            manifest.write_text(
                '[workspace]\nmembers = ["bins/agent", "crates/unrelated"]\n'
                'resolver = "2"\n',
                encoding="utf-8",
            )
            after = IMPACT.root_policy(tree)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
