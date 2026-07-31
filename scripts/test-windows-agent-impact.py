#!/usr/bin/env python3
"""Focused tests for the Windows-agent impact classifier."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("windows-agent-impact.py")
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("windows_agent_impact", SCRIPT)
assert SPEC and SPEC.loader
IMPACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPACT)


class WindowsAgentImpactTests(unittest.TestCase):
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
        self.assertIn("no Windows agent", reason)

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
        self.assertIn("dependency source", reason)

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
        self.assertIn("resolved agent dependency", reason)

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
