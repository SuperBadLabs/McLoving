#!/usr/bin/env python3
"""Run the shipped verdict recorder against isolated GitHub/controller truth."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

RECORDER = Path(__file__).resolve().parent / "dogfood" / "verdicts.sh"
BASE_MS = 1770000000000


class VerdictTimestampTests(unittest.TestCase):
    def test_millisecond_precision_and_chronological_admission(self) -> None:
        offsets = (0, 5, 40, 74, 87, 100, 999)
        commits = [str(n) * 40 for n in range(1, len(offsets) + 1)]
        builds = [f"00000000-0000-0000-0000-{n:012d}" for n in range(1, len(offsets) + 1)]
        truth = [
            {"build_id": build, "created_at_unix_ms": BASE_MS + offset}
            for build, offset in zip(builds, offsets)
        ]
        with TemporaryDirectory(prefix="mcloving-verdict-test-") as temporary:
            root = Path(temporary)
            lane = root / "scripts" / "dogfood"
            commands = root / "commands"
            cli_directory = root / "target" / "debug"
            state = root / "state"
            for directory in (lane, commands, cli_directory, state):
                directory.mkdir(parents=True)
            recorder = lane / "verdicts.sh"
            # Exercise the complete shipped source, including CLI selection,
            # pairing, chronological checks and the appended evidence row.
            recorder.write_bytes(RECORDER.read_bytes())
            (state / "env").write_text("MCLOVING_DOGFOOD_REPOSITORY=example/repository\n")
            (state / "deliveries.example__repository.main.tsv").write_text(
                "".join(
                    f"2026-02-02T02:40:00Z event-{n} {commit} {build} -\n"
                    for n, (commit, build) in enumerate(zip(commits, builds), 1)
                )
            )
            gh = commands / "gh"
            gh.write_text(
                "#!/usr/bin/env python3\nimport sys\n"
                f"commits = {commits!r}\n"
                "assert sys.argv[1:3] == ['run', 'list']\n"
                "commit = sys.argv[sys.argv.index('--commit') + 1]\n"
                "print(str(commits.index(commit) + 101) + ' success 2026-02-02T02:40:00Z')\n"
            )
            gh.chmod(0o700)
            cli = cli_directory / "mcloving-cli"
            cli.write_text(
                "#!/usr/bin/env python3\nimport json, sys\n"
                f"truth = {truth!r}\n"
                "assert sys.argv[1:3] == ['--output', 'json']\n"
                "if sys.argv[3] == 'status':\n"
                "    assert sys.argv[4] in [row['build_id'] for row in truth]\n"
                "    print(json.dumps({'status': 'succeeded'}))\n"
                "elif sys.argv[3] == 'builds':\n"
                "    print(json.dumps({'items': truth}))\n"
                "else: raise AssertionError(sys.argv)\n"
            )
            cli.chmod(0o700)
            evidence = root / "evidence.md"
            evidence.write_text("# Isolated verdict fixture\n")
            environment = dict(os.environ, PATH=f"{commands}:{os.environ['PATH']}")
            for commit in commits:
                result = subprocess.run(
                    ["bash", str(recorder), str(state), commit, str(evidence)],
                    env=environment, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            rows = [line for line in evidence.read_text().splitlines() if line.startswith("| ")]
            self.assertEqual(len(rows), len(offsets))
            for index, (row, commit, build, offset) in enumerate(zip(rows, commits, builds, offsets), 1):
                cells = [cell.strip() for cell in row.strip("|").split("|")]
                self.assertEqual(cells, [
                    str(index), f"`{commit[:12]}`", f"2026-02-02T02:40:00.{offset:03d}Z",
                    str(index + 100), "success", f"`{build}`", "succeeded", "yes",
                ])
            # A true out-of-order build must still be refused and leave the
            # existing table intact; timestamp padding must not weaken that gate.
            evidence.write_text(rows[-1] + "\n")
            before = evidence.read_bytes()
            result = subprocess.run(
                ["bash", str(recorder), str(state), commits[1], str(evidence)],
                env=environment, capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("was not created after the last recorded row", result.stderr)
            self.assertEqual(evidence.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
