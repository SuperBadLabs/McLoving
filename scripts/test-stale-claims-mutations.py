#!/usr/bin/env python3
"""Replay HYG-003 green controls and isolated mutations without changing the tree.

Each control first passes unchanged, then fails by assertion after its production
check is removed/weakened. The temporary copies contain Python/documentation
fixtures only. --verify-history additionally compares retained text to Git history;
CI needs no historical Git objects because the exact fixtures are checked in.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BOARD = "test-execution-board.py"
CLOSURE = "test-ticket-closure-receipts.py"
ARCHIVES = "test-stale-claims-archives.py"
# (label, production source, exact mutation, named control)
MUTATIONS = (
    ("head-assertions", "stale_claims.py", "HEAD_ASSERTIONS", "pattern", BOARD,
     "ExecutionBoardVerifierTests.test_named_head_verified_now_fails"),
    ("live-gate", "stale_claims.py", "LIVE_GATE", "pattern", BOARD,
     "ExecutionBoardVerifierTests.test_second_discharge_draft_fails"),
    ("startable", "stale_claims.py", "STARTABLE", "pattern", BOARD,
     "ExecutionBoardVerifierTests.test_first_discharge_draft_fails"),
    ("governance-wording", "stale_claims.py", "GOVERNED_THROUGH", "pattern", BOARD,
     "ExecutionBoardVerifierTests.test_pre_thaw_governance_claim_fails_after_recorded_lift"),
    ("expired-window", "stale_claims.py", "if end < today:", "if False:", BOARD,
     "ExecutionBoardVerifierTests.test_expired_window_fails_even_without_lift_receipt"),
    ("early-lift", "stale_claims.py", 'elif (\n                "SEPTEMBER_2026_CODE_FREEZE.md" in match.group()',
     'elif (\n                False and "SEPTEMBER_2026_CODE_FREEZE.md" in match.group()', BOARD,
     "ExecutionBoardVerifierTests.test_pre_thaw_governance_claim_fails_after_recorded_lift"),
    ("every-governance-window", "stale_claims.py", 'for match in GOVERNED_THROUGH.finditer(normalize_prose(block)):',
     'for match in list(GOVERNED_THROUGH.finditer(normalize_prose(block)))[:1]:', BOARD,
     "StaleClaimBoundaryTests.test_later_expired_governance_window_in_paragraph_is_refused"),
    ("invalid-window", "stale_claims.py", 'defects.append(f"{current}:{line}: governance window has an invalid end date")',
     "pass", BOARD, "StaleClaimBoundaryTests.test_invalid_governance_date_is_refused"),
    ("comment-count", "stale_claims.py", "COMMENT_COUNT", "pattern", CLOSURE,
     "StaleCountCommentTests.test_pre_hyg003_comment_is_refused"),
    ("comment-adjacency", "stale_claims.py", 'start < token.start[0] <= end',
     'start < token.start[0] < declarations["TICKET_TABLE_HEADER"].lineno', CLOSURE,
     "StaleCountCommentTests.test_production_verifier_checks_its_count_comment"),
    ("missing-count-declarations", "stale_claims.py",
     'return ["closure verifier lacks its table-count declarations"]', 'return []', CLOSURE,
     "StaleCountCommentTests.test_missing_constant_declarations_fail_closed"),
    ("invalid-count-source", "stale_claims.py",
     'return ["closure verifier source cannot be parsed for table-count comments"]', 'return []', CLOSURE,
     "StaleCountCommentTests.test_invalid_source_cannot_bypass_count_check"),
    ("handoff-symlink", "stale_claims.py",
     'defects.append(f"{relative}: handoff symlink cannot be checked as repository prose")', 'pass', BOARD,
     "ExecutionBoardVerifierTests.test_handoff_symlink_is_refused_without_reading_target"),
    ("board-entry-integration", "verify-execution-board.py",
     'errors += document_defects(repository, text, today=today)', 'errors += []', BOARD,
     "ExecutionBoardVerifierTests.test_first_discharge_draft_fails"),
    ("clock-propagation", "verify-execution-board.py",
     'document_defects(repository, text, today=today)', 'document_defects(repository, text)', BOARD,
     "ExecutionBoardVerifierTests.test_pre_thaw_governance_claim_fails_after_recorded_lift"),
    ("handoff-head-integration", "stale_claims.py", 'defects += head_claim_defects(relative, content)',
     'defects += []', BOARD,
     "StaleClaimBoundaryTests.test_observation_keyword_does_not_excuse_live_assertion"),
    ("handoff-governance-integration", "stale_claims.py",
     'defects += governance_defects(\n                path, handoffs / "2026-09-06-freeze-thaw.md", today=today, content=content\n            )',
     'defects += []', BOARD,
     "ExecutionBoardVerifierTests.test_pre_thaw_governance_claim_fails_after_recorded_lift"),
    ("board-governance-integration", "stale_claims.py",
     'defects += governance_defects(\n        repository / "docs" / "EXECUTION_BOARD.md",\n        handoffs / "2026-09-06-freeze-thaw.md", today=today, content=board_text,\n    )',
     'defects += []', BOARD,
     "StaleClaimBoundaryTests.test_expired_window_in_board_fails_real_entry_point"),
    ("closure-entry-integration", "verify-ticket-closure-receipts.py",
     'errors += expected_tables_comment_defects(Path(__file__).read_text(encoding="utf-8"))',
     'errors += []', CLOSURE,
     "StaleCountCommentTests.test_production_verifier_checks_its_count_comment"),
    ("markdown-emphasis-normalization", "stale_claims.py", 'plain = normalize_prose(block)',
     'plain = block.replace("`", "").replace("**", "")', BOARD,
     "StaleClaimBoundaryTests.test_emphasized_live_head_assertion_is_refused"),
    ("matched-governance-identity", "stale_claims.py", '"SEPTEMBER_2026_CODE_FREEZE.md" in match.group()',
     '"SEPTEMBER_2026_CODE_FREEZE.md" in block', BOARD,
     "StaleClaimBoundaryTests.test_future_window_with_unrelated_september_history_passes"),
    ("observation-time-validation", "stale_claims.py",
     'def valid_observation_time(value: str) -> bool:',
     'def valid_observation_time(value: str) -> bool:\n    return True', BOARD,
     "StaleClaimBoundaryTests.test_invalid_observation_date_cannot_excuse_head_assertion"),
    ("retained-observation-refusal", "stale_claims.py", 'if not any(start <= match.start() and match.end() <= end',
     'if not any(False and start <= match.start() and match.end() <= end', BOARD,
     "ExecutionBoardVerifierTests.test_dated_observation_of_old_head_passes"),
    ("timed-observation-refusal", "stale_claims.py", 'if not any(start <= match.start() and match.end() <= end',
     'if not any(False and start <= match.start() and match.end() <= end', BOARD,
     "StaleClaimBoundaryTests.test_timed_observation_passes"),
    ("paragraph-wide-observation-bypass", "stale_claims.py", '        assertions = [',
     '        if dated_handoff and "observed" in plain:\n            observed_spans = [(0, len(plain))]\n        assertions = [', BOARD,
     "StaleClaimBoundaryTests.test_dated_observation_and_current_assertion_in_same_sentence_fails"),
    ("main-token-boundary", "stale_claims.py",
     'MAIN_SUBJECT = r"(?<![\\w-])(?:protected[- ]main|main)(?![\\w-])"',
     'MAIN_SUBJECT = r"\\b(?:protected[- ]main|main)\\b"', ARCHIVES,
     "ArchiveBoundaryTests.test_recovered_main_is_not_live_main"),
    ("reviewed-seal-commitment", "reviewed_handoff_archives.py",
     'if hashlib.sha256(data).hexdigest() != unit["sha256"]:', 'if False:', ARCHIVES,
     "ArchiveBoundaryTests.test_manifest_and_payload_cannot_update_their_own_pin"),
    ("listed-markdown-digest", "stale_claims.py",
     'if hashlib.sha256(data).hexdigest() != expected:', 'if False:', ARCHIVES,
     "ArchiveBoundaryTests.test_changed_listed_markdown_is_refused"),
    ("restored-archival-scope", "stale_claims.py", 'if expected is not None:',
     'if False and expected is not None:', ARCHIVES,
     "ArchiveBoundaryTests.test_real_three_seals_and_four_archival_documents_pass_entry_point"),
    ("same-opened-markdown", "stale_claims.py", 'if hashlib.sha256(data).hexdigest() != expected:',
     'if hashlib.sha256(path.read_bytes()).hexdigest() != expected:', ARCHIVES,
     "ArchiveBoundaryTests.test_archive_eligibility_uses_the_same_opened_markdown_bytes"),
    ("registry-fail-closed", "reviewed_handoff_archives.py",
     'return {}, [f"archive scope: cannot validate reviewed registry: {error}"]',
     'return {}, []', ARCHIVES,
     "ArchiveBoundaryTests.test_missing_registry_fails_closed_even_on_clean_tree"),
    ("seal-file-no-follow", "reviewed_handoff_archives.py",
     'os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW', 'os.O_RDONLY | os.O_NONBLOCK', ARCHIVES,
     "ArchiveBoundaryTests.test_seal_symlink_cannot_authorize_scope"),
    ("seal-ancestor-no-follow", "reviewed_handoff_archives.py",
     'os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW', 'os.O_RDONLY | os.O_DIRECTORY', ARCHIVES,
     "ArchiveBoundaryTests.test_registered_ancestor_no_follow_guard"),
    ("nested-directory-symlink", "stale_claims.py",
     'defects.append(f"{relative}: handoff directory symlink cannot be checked as repository prose")',
     'pass', ARCHIVES,
     "ArchiveBoundaryTests.test_unlisted_nested_directory_symlink_is_refused"),
    ("manifest-duplicate-path", "reviewed_handoff_archives.py", 'if path in entries:',
     'if False and path in entries:', ARCHIVES,
     "ArchiveParserTests.test_duplicate_manifest_paths_cannot_be_collapsed"),
    ("manifest-path-canonicality", "reviewed_handoff_archives.py",
     'raise ArchiveScopeError("noncanonical or escaping archive path")', 'pass', ARCHIVES,
     "ArchiveParserTests.test_manifest_paths_cannot_escape"),
    ("manifest-digest-shape", "reviewed_handoff_archives.py",
     'MANIFEST_LINE = re.compile(r"(?P<digest>[0-9a-f]{64})  (?P<path>.+)")',
     'MANIFEST_LINE = re.compile(r"(?P<digest>[^ ]+)  (?P<path>.+)")', ARCHIVES,
     "ArchiveParserTests.test_bad_manifest_digest_is_refused"),
    ("manifest-complete-lines", "reviewed_handoff_archives.py",
     'if not data or not data.endswith(b"\\n"):', 'if not data:', ARCHIVES,
     "ArchiveParserTests.test_unterminated_manifest_is_refused"),
    ("registry-duplicate-keys", "reviewed_handoff_archives.py", 'if name in result:',
     'if False and name in result:', ARCHIVES,
     "ArchiveParserTests.test_duplicate_registry_keys_are_refused"),
    ("registry-root-overlap", "reviewed_handoff_archives.py",
     'if any(root[:len(other)] == other or other[:len(root)] == root for other in seen):',
     'if False:', ARCHIVES,
     "ArchiveParserTests.test_registry_overlapping_roots_are_refused"),
    ("registry-reviewed-unit-set", "reviewed_handoff_archives.py",
     'or len(registry["units"]) != 3', 'or False', ARCHIVES,
     "ArchiveParserTests.test_registry_missing_unit_cannot_change_reviewed_scope"),
    ("registry-commitment-shape", "reviewed_handoff_archives.py",
     'if not isinstance(unit["sha256"], str) or HEX.fullmatch(unit["sha256"]) is None:',
     'if False:', ARCHIVES,
     "ArchiveParserTests.test_registry_malformed_commitment_is_refused"),
    ("seal-file-regularity", "reviewed_handoff_archives.py", 'if not stat.S_ISREG(os.fstat(fd).st_mode):',
     'if False:', ARCHIVES,
     "ArchiveParserTests.test_nonregular_file_cannot_supply_seal_bytes"),

)


def replay() -> dict:
    results = []
    with tempfile.TemporaryDirectory(prefix="hyg003-mutations-") as directory:
        root = Path(directory)
        (root / "scripts").mkdir()
        for source in (ROOT / "scripts").glob("*.py"):
            shutil.copyfile(source, root / "scripts" / source.name)
        shutil.copytree(ROOT / "scripts/fixtures", root / "scripts/fixtures")
        shutil.copyfile(ROOT / "scripts/stale-claims-archives.json", root / "scripts/stale-claims-archives.json")
        shutil.copyfile(ROOT / "README.md", root / "README.md")
        (root / "docs/handoffs").mkdir(parents=True)
        shutil.copyfile(ROOT / "docs/EXECUTION_BOARD.md", root / "docs/EXECUTION_BOARD.md")
        shutil.copyfile(ROOT / "docs/handoffs/2026-09-06-freeze-thaw.md",
                        root / "docs/handoffs/2026-09-06-freeze-thaw.md")
        for name, filename, before, after, script, test in MUTATIONS:
            path = root / "scripts" / filename
            original = path.read_text(encoding="utf-8")
            if after == "pattern":
                mutation = f'\n{before} = ' + ('()' if before == "HEAD_ASSERTIONS" else 're.compile(r"(?!)")') + '\n'
                changed = original.replace('\ndef prose_blocks(', mutation + '\ndef prose_blocks(', 1)
                assert changed != original
            else:
                if original.count(before) != 1:
                    raise RuntimeError(f"{name}: mutation anchor occurs {original.count(before)} times")
                changed = original.replace(before, after, 1)
            command = [sys.executable, "-B", str(root / "scripts" / script), test]
            baseline = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=30)
            if baseline.returncode != 0:
                raise RuntimeError(f"{name}: unmutated control fails\n{baseline.stderr}")
            try:
                path.write_text(changed, encoding="utf-8")
                red = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=30)
            finally:
                path.write_text(original, encoding="utf-8")
            if red.returncode != 1 or "FAILED (failures=1)" not in red.stderr or "ERROR:" in red.stderr:
                raise RuntimeError(f"{name}: mutation did not cause one assertion failure\n{red.stderr}")
            restored = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=30)
            if restored.returncode != 0:
                raise RuntimeError(f"{name}: restored control fails\n{restored.stderr}")
            results.append({"mutation": name, "source": filename, "test": test,
                            "green_exit": baseline.returncode, "red_exit": red.returncode,
                            "green_output": baseline.stderr, "red_output": red.stderr,
                            "restored_exit": restored.returncode, "restored_output": restored.stderr})
    sources = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in sorted((ROOT / "scripts").glob("*stale*")) if path.is_file()}
    for filename in (BOARD, CLOSURE, "verify-execution-board.py", "verify-ticket-closure-receipts.py",
                     "fixtures/stale-claims.json", "reviewed_handoff_archives.py", "stale-claims-archives.json"):
        path = ROOT / "scripts" / filename
        sources[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted((ROOT / "scripts/fixtures/hyg-003-owner-archives").rglob("*")):
        if path.is_file():
            sources[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"ticket": "HYG-003", "source_sha256": sources, "mutations": results}


def verify_history() -> list[dict]:
    fixtures = json.loads((ROOT / "scripts/fixtures/stale-claims.json").read_text(encoding="utf-8"))
    verified = []
    for name, fixture in fixtures.items():
        text = subprocess.check_output(["git", "show", fixture["commit"] + ":" + fixture["path"]],
                                       cwd=ROOT, text=True)
        retained = fixture["text"]
        equal = retained in text if name == "pre_count" else retained == text
        if not equal or hashlib.sha256(retained.encode()).hexdigest() != fixture["sha256"]:
            raise RuntimeError(f"{name}: historical fixture disagrees with cited source")
        verified.append({"fixture": name, "commit": fixture["commit"], "path": fixture["path"],
                         "sha256": fixture["sha256"], "kind": "excerpt" if name == "pre_count" else "full-text"})
    return verified


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify-history", action="store_true")
    args = parser.parse_args()
    result = replay()
    if args.verify_history:
        result["historical_sources"] = verify_history()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"stale-claims-mutations-ok controls={len(result['mutations'])} "
          f"historical_sources={len(result.get('historical_sources', []))}")


if __name__ == "__main__":
    main()
