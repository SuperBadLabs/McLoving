#!/usr/bin/env python3
"""Real pinned archive integration and explicit parser/path adversaries.

The production integration fixture uses the actual three manifest bytes and
four reviewed Markdown files, not synthetic manifests or substituted pins.
"""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from unittest.mock import patch

import reviewed_handoff_archives as ARCH
import stale_claims as CLAIMS

from stale_claims import document_defects, head_claim_defects

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "scripts/fixtures/hyg-003-owner-archives"
INDEX = json.loads((FIXTURES / "index.json").read_text())
DOCUMENTS = [entry for entry in INDEX["files"] if entry["encoding"] == "identity"]
SPEC = importlib.util.spec_from_file_location("archive_board_verifier", ROOT / "scripts/verify-execution-board.py")
assert SPEC and SPEC.loader
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def fixture_bytes(entry: dict) -> bytes:
    data = (FIXTURES / entry["fixture"]).read_bytes()
    if entry["encoding"] == "gzip":
        data = gzip.decompress(data)
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise AssertionError("retained exact owner-archive fixture changed")
    return data


@contextmanager
def archive_tree():
    with tempfile.TemporaryDirectory(prefix="hyg003-archive-controls-") as directory:
        root = Path(directory)
        (root / "scripts").mkdir()
        (root / "docs").mkdir()
        shutil.copyfile(ROOT / "docs/EXECUTION_BOARD.md", root / "docs/EXECUTION_BOARD.md")
        shutil.copyfile(ROOT / "README.md", root / "README.md")
        (root / "scripts/verify-execution-board.py").write_text("# real entry-point fixture\n")
        for entry in INDEX["files"]:
            path = root / entry["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(fixture_bytes(entry))
        yield root


def run_verifier(root: Path, today=None) -> tuple[int, str, str]:
    original = VERIFY.__file__
    out, err = io.StringIO(), io.StringIO()
    try:
        VERIFY.__file__ = str(root / "scripts/verify-execution-board.py")
        with redirect_stdout(out), redirect_stderr(err):
            try:
                VERIFY.main(today=today)
            except SystemExit as error:
                code = int(error.code or 0)
            else:
                code = 0
    finally:
        VERIFY.__file__ = original
    return code, out.getvalue(), err.getvalue()


class ArchiveBoundaryTests(unittest.TestCase):
    def test_real_three_seals_and_four_archival_documents_pass_entry_point(self) -> None:
        with archive_tree() as root:
            code, out, err = run_verifier(root)
        self.assertEqual(code, 0, err)
        self.assertIn("execution-board-ok", out)

    def test_recovered_main_is_not_live_main(self) -> None:
        entry = DOCUMENTS[0]
        self.assertEqual(head_claim_defects(Path("docs/handoffs/unsealed-readiness.md"),
                                          fixture_bytes(entry).decode()), [])

    def test_bare_and_protected_main_still_refused(self) -> None:
        for text in ("main is a5ffdb5.", "protected-main is a5ffdb5.", "protected main is a5ffdb5."):
            with self.subTest(text=text):
                self.assertTrue(head_claim_defects(Path("docs/handoffs/CURRENT.md"), text))

    def test_added_unlisted_nested_live_claim_is_refused(self) -> None:
        with archive_tree() as root:
            extra = root / Path(DOCUMENTS[1]["path"]).parent / "new/nested/CURRENT.md"
            extra.parent.mkdir(parents=True)
            extra.write_text("main is a5ffdb5.\n")
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("new/nested/CURRENT.md", err)
        self.assertIn("current head", err)

    def test_changed_listed_markdown_is_refused(self) -> None:
        with archive_tree() as root:
            path = root / DOCUMENTS[1]["path"]
            path.write_bytes(path.read_bytes() + b"\nmain is a5ffdb5.\n")
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("archive scope Markdown digest differs", err)

    def test_manifest_and_payload_cannot_update_their_own_pin(self) -> None:
        with archive_tree() as root:
            document = DOCUMENTS[1]
            path = root / document["path"]
            changed = path.read_bytes() + b"\nmain is a5ffdb5.\n"
            path.write_bytes(changed)
            seal = path.parent / "SHA256SUMS"
            old = f'{document["sha256"]}  START_HERE.md\n'.encode()
            new = hashlib.sha256(changed).hexdigest().encode() + b"  START_HERE.md\n"
            data = seal.read_bytes()
            self.assertEqual(data.count(old), 1)
            seal.write_bytes(data.replace(old, new))
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("archive seal commitment differs", err)

    def test_present_unit_missing_manifest_is_refused(self) -> None:
        with archive_tree() as root:
            seal = next(entry for entry in INDEX["files"] if entry["encoding"] == "gzip")
            (root / seal["path"]).unlink()
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("archive scope cannot validate sealed manifest", err)

    def test_malformed_real_manifest_is_refused(self) -> None:
        with archive_tree() as root:
            seal = root / next(entry["path"] for entry in INDEX["files"] if entry["encoding"] == "gzip")
            seal.write_bytes(seal.read_bytes() + b"malformed entry\n")
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("malformed archive manifest entry", err)

    def test_duplicate_real_manifest_entry_is_refused(self) -> None:
        with archive_tree() as root:
            seal = root / next(entry["path"] for entry in INDEX["files"] if entry["encoding"] == "gzip")
            data = seal.read_bytes()
            seal.write_bytes(data + data.splitlines()[0] + b"\n")
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("duplicate archive manifest path", err)

    def test_escaping_real_manifest_entry_is_refused(self) -> None:
        with archive_tree() as root:
            seal = root / next(entry["path"] for entry in INDEX["files"] if entry["encoding"] == "gzip")
            seal.write_bytes(seal.read_bytes() + b"a" * 64 + b"  ../escape.md\n")
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("noncanonical or escaping archive path", err)

    def test_seal_symlink_cannot_authorize_scope(self) -> None:
        with archive_tree() as root:
            seal = root / next(entry["path"] for entry in INDEX["files"] if entry["encoding"] == "gzip")
            external = root / "same-seal-bytes"
            seal.rename(external)
            seal.symlink_to(external)
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("archive scope cannot validate sealed manifest", err)

    def test_listed_markdown_symlink_is_refused_even_for_identical_bytes(self) -> None:
        with archive_tree() as root:
            document = root / DOCUMENTS[1]["path"]
            external = root / "same-document.md"
            document.rename(external)
            document.symlink_to(external)
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("handoff symlink", err)

    def test_registered_unit_root_symlink_is_refused(self) -> None:
        with archive_tree() as root:
            unit = root / ARCH.read_registry()[0]["root"]
            external = root / "same-unit"
            unit.rename(external)
            unit.symlink_to(external, target_is_directory=True)
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("archive scope cannot open unit without symlink ancestors", err)

    def test_registered_ancestor_no_follow_guard(self) -> None:
        with archive_tree() as root:
            ancestor = (root / ARCH.read_registry()[0]["root"]).parent
            external = root / "same-parent"
            ancestor.rename(external)
            ancestor.symlink_to(external, target_is_directory=True)
            _, defects = ARCH.archive_scope(root)
        self.assertTrue(any("archive scope cannot open unit without symlink ancestors" in d for d in defects))

    def test_handoff_scan_ancestor_symlink_is_refused(self) -> None:
        with archive_tree() as root:
            handoffs = root / "docs/handoffs"
            external = root / "same-handoffs"
            handoffs.rename(external)
            handoffs.symlink_to(external, target_is_directory=True)
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("cannot scan handoff ancestors without symlinks", err)

    def test_unlisted_nested_directory_symlink_is_refused(self) -> None:
        with archive_tree() as root:
            unit = root / ARCH.read_registry()[0]["root"]
            external = root / "live-external"
            external.mkdir()
            (external / "CURRENT.md").write_text("main is a5ffdb5.")
            (unit / "new-directory").symlink_to(external, target_is_directory=True)
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("handoff directory symlink", err)

    def test_unregistered_archive_label_and_date_do_not_exempt_claims(self) -> None:
        with archive_tree() as root:
            fake = root / "docs/handoffs/2026-09-10-forged-sealed-archive"
            fake.mkdir()
            (fake / "START_HERE.md").write_bytes(fixture_bytes(DOCUMENTS[1]))
            (fake / "SHA256SUMS").write_bytes(next(
                fixture_bytes(entry) for entry in INDEX["files"]
                if entry["path"].endswith("next-master-chief-post-mission/SHA256SUMS")))
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("forged-sealed-archive/START_HERE.md", err)
        self.assertIn("current head", err)

    def test_unlisted_closed_governance_window_remains_checked(self) -> None:
        with archive_tree() as root:
            extra = root / ARCH.read_registry()[0]["root"] / "new/CURRENT.md"
            extra.parent.mkdir()
            extra.write_text("McLoving is governed by its old contract through 2020-01-01.")
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("governance window that has ended", err)

    def test_archive_eligibility_uses_the_same_opened_markdown_bytes(self) -> None:
        with archive_tree() as root:
            target = DOCUMENTS[1]["path"]
            original_read = CLAIMS.regular_bytes

            def opened_then_path_replaced(repository: Path, relative: str) -> bytes:
                data = original_read(repository, relative)
                if relative == target:
                    (repository / relative).write_bytes(data + b"\nmain is a5ffdb5.\n")
                return data

            with patch.object(CLAIMS, "regular_bytes", opened_then_path_replaced):
                code, _, err = run_verifier(root)
            self.assertEqual(code, 0, err)
            # A later observation sees the changed bytes and refuses them.
            code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("archive scope Markdown digest differs", err)

    def test_absent_optional_archives_preserve_clean_tree_green(self) -> None:
        with archive_tree() as root:
            for unit in ARCH.read_registry():
                shutil.rmtree(root / unit["root"])
            code, _, err = run_verifier(root)
        self.assertEqual(code, 0, err)

    def test_missing_registry_fails_closed_even_on_clean_tree(self) -> None:
        with archive_tree() as root:
            for unit in ARCH.read_registry():
                shutil.rmtree(root / unit["root"])
            with patch.object(ARCH, "REGISTRY", root / "missing-reviewed-registry.json"):
                code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("archive scope: cannot validate reviewed registry", err)

    def test_malformed_registry_fails_closed_even_on_clean_tree(self) -> None:
        with archive_tree() as root:
            for unit in ARCH.read_registry():
                shutil.rmtree(root / unit["root"])
            policy = root / "malformed-registry.json"
            policy.write_text("not JSON")
            with patch.object(ARCH, "REGISTRY", policy):
                code, _, err = run_verifier(root)
        self.assertEqual(code, 1)
        self.assertIn("archive scope: cannot validate reviewed registry", err)


class ArchiveParserTests(unittest.TestCase):
    """Malformed input controls, not substitutes for real pinned-unit proof."""
    def test_duplicate_manifest_paths_cannot_be_collapsed(self) -> None:
        data = b"a" * 64 + b"  file.md\n" + b"b" * 64 + b"  file.md\n"
        with self.assertRaises(ARCH.ArchiveScopeError):
            ARCH.parse_manifest(data)

    def test_manifest_paths_cannot_escape(self) -> None:
        with self.assertRaises(ARCH.ArchiveScopeError):
            ARCH.parse_manifest(b"a" * 64 + b"  ../outside.md\n")

    def test_noncanonical_manifest_aliases_are_refused(self) -> None:
        for path in ("./file.md", "dir//file.md", "dir/../file.md", "/file.md", "dir\\file.md", "C:/file.md"):
            with self.subTest(path=path), self.assertRaises(ARCH.ArchiveScopeError):
                ARCH.parse_manifest(("a" * 64 + "  " + path + "\n").encode())

    def test_bad_manifest_digest_is_refused(self) -> None:
        with self.assertRaises(ARCH.ArchiveScopeError):
            ARCH.parse_manifest(b"not-a-digest  file.md\n")

    def test_unterminated_manifest_is_refused(self) -> None:
        with self.assertRaises(ARCH.ArchiveScopeError):
            ARCH.parse_manifest(b"a" * 64 + b"  file.md")

    def test_duplicate_registry_keys_are_refused(self) -> None:
        with self.assertRaises(ARCH.ArchiveScopeError):
            json.loads('{"schema": "one", "schema": "two"}', object_pairs_hook=ARCH.unique_object)

    def test_registry_overlapping_roots_are_refused(self) -> None:
        units = ARCH.read_registry()
        units[1] = dict(units[0])
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "invalid-policy.json"
            policy.write_text(json.dumps({"schema": ARCH.SCHEMA, "units": units}))
            with patch.object(ARCH, "REGISTRY", policy), self.assertRaises(ARCH.ArchiveScopeError):
                ARCH.read_registry()

    def test_registry_missing_unit_cannot_change_reviewed_scope(self) -> None:
        units = ARCH.read_registry()[:2]
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "invalid-policy.json"
            policy.write_text(json.dumps({"schema": ARCH.SCHEMA, "units": units}))
            with patch.object(ARCH, "REGISTRY", policy), self.assertRaises(ARCH.ArchiveScopeError):
                ARCH.read_registry()

    def test_registry_malformed_commitment_is_refused(self) -> None:
        units = ARCH.read_registry()
        units[0]["sha256"] = "not-a-content-commitment"
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "invalid-policy.json"
            policy.write_text(json.dumps({"schema": ARCH.SCHEMA, "units": units}))
            with patch.object(ARCH, "REGISTRY", policy), self.assertRaises(ARCH.ArchiveScopeError):
                ARCH.read_registry()

    def test_nonregular_file_cannot_supply_seal_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root / "not-a-regular-seal")
            with self.assertRaises(ARCH.ArchiveScopeError):
                ARCH.regular_bytes(root, "not-a-regular-seal")

    def test_registry_paths_cannot_escape_handoffs(self) -> None:
        units = ARCH.read_registry()
        units[0]["root"] = "docs/handoffs/../CURRENT.md"
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "invalid-policy.json"
            policy.write_text(json.dumps({"schema": ARCH.SCHEMA, "units": units}))
            with patch.object(ARCH, "REGISTRY", policy), self.assertRaises(ARCH.ArchiveScopeError):
                ARCH.read_registry()



if __name__ == "__main__":
    unittest.main()
