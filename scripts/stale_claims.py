"""Small, deliberately bounded checks for claims that outlive their evidence.

These checks recognize assertions, not every mention of a commit or date. A
dated observation remains useful after main moves; a present-tense statement
that a particular commit is *the* current head does not.
"""

from __future__ import annotations

import ast
import io
import hashlib
import os
import re
import tokenize
from datetime import date, datetime
from pathlib import Path

from reviewed_handoff_archives import archive_scope, directory_fd, regular_bytes


COMMIT = r"(?:`)?[0-9a-f]{7,40}(?:`)?"
MAIN_SUBJECT = r"(?<![\w-])(?:protected[- ]main|main)(?![\w-])"
HEAD_ASSERTIONS = (
    re.compile(
        rf"\b(?:current|present|latest|now)\s+(?:protected[- ]main\s+)?"
        rf"(?:head|commit)\s+(?:is\s+|at\s+)?{COMMIT}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"{MAIN_SUBJECT}\s+(?:head\s+)?(?:is|remains)\s+"
        rf"(?:currently\s+|now\s+)?(?:at\s+|commit\s+)?{COMMIT}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{COMMIT}\s+(?:is|remains|has been)\s+"
        r"(?:(?:now|currently)\s+)?(?:the\s+)?"
        r"(?:(?:current|present|latest)(?:\s+(?:(?:protected[- ]main|main)\s+)?"
        r"(?:head|commit))?|(?:(?:protected[- ]main|main)\s+)?head|verified|green)\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:protected[- ]main|successor)\s+head\s+{COMMIT}\s+"
        r"(?:is|has been)\s+(?:now\s+)?(?:verified|green|current)\b",
        re.IGNORECASE,
    ),
)
# The retained thaw audit uses present-tense wording within a dated finding.
# Exempt only its head-mention span, never the rest of that paragraph/sentence.
# An added assertion (even about the same SHA) is checked independently.
AUDIT_HEAD_OBSERVATION = re.compile(
    rf"(?:^|(?<=\s))Gap found, and it predates the thaw\.\s+"
    rf"The (?P<head>current protected-main head\s+{COMMIT})\s+"
    r"has no Foundation run, no Windows run"
    r"(?:, and consequently no Release Builder run at all| at the audit)\.",
    re.IGNORECASE,
)
TIMED_HEAD_OBSERVATION = re.compile(
    rf"\b(?:On|At)\s+(?P<time>\d{{4}}-\d{{2}}-\d{{2}}(?:T[0-9:]+Z)?)[,]?\s+"
    rf"(?:the\s+)?(?P<head>(?:current|present|latest)\s+"
    rf"(?:protected[- ]main\s+)?(?:head|commit)\s+{COMMIT})\s+"
    r"was (?:observed|audited|found)\s+(?:as\s+)?(?:verified|green|unverified)\b",
    re.IGNORECASE,
)

LIVE_GATE = re.compile(
    r"\b(?:gate|condition|verification)\b[^|]{0,80}?\b(?:is|has been)\s+"
    r"(?:now\s+)?(?:discharged|satisfied|complete|verified)\b",
    re.IGNORECASE,
)
STARTABLE = re.compile(r"\bis\s+now\s+startable\b", re.IGNORECASE)
SHA = re.compile(rf"\b{COMMIT}\b")
FENCE = re.compile(r"^\s*(```|~~~)")
GOVERNED_THROUGH = re.compile(
    r"\b(?:is|remains)\s+governed\s+by\b.*?\bthrough\s+"
    r"(?P<end>\d{4}-\d{2}-\d{2})\b",
    re.IGNORECASE | re.DOTALL,
)
COUNT = (
    r"(?:\d+|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|"
    r"thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|"
    r"(?:twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)"
    r"(?:[- ](?:one|two|three|four|five|six|seven|eight|nine))?|hundred|thousand)"
)
COMMENT_COUNT = re.compile(
    rf"\b{COUNT}\b(?:\s+\w+){{0,3}}\s+"
    r"(?:tables?|row\s+formats?|entries|formats?)\b|"
    rf"\bonly\s+the\s+{COUNT}\s+whose\s+first\s+header\b|"
    rf"\b(?:EXPECTED_TABLES|(?:table\s+)?count|tables?|entries|row\s+formats?)\s+"
    rf"(?:is|are|has|have|equals?)\s+{COUNT}\b",
    re.IGNORECASE,
)


def prose_blocks(text: str) -> list[tuple[int, str]]:
    """Return prose paragraphs and individual table rows, omitting code fences."""
    blocks: list[tuple[int, str]] = []
    pending: list[str] = []
    start = 0
    fence: str | None = None

    def flush() -> None:
        nonlocal pending
        if pending:
            blocks.append((start, " ".join(pending)))
            pending = []

    for number, line in enumerate(text.splitlines(), 1):
        marker = FENCE.match(line)
        if marker:
            flush()
            kind = marker.group(1)[0]
            fence = None if fence == kind else kind
            continue
        if fence:
            continue
        if not line.strip() or line.startswith("# ") or line.startswith("## "):
            flush()
            continue
        if line.startswith("|"):
            flush()
            blocks.append((number, line))
            continue
        if not pending:
            start = number
        pending.append(line.strip())
    flush()
    return blocks


def normalize_prose(text: str) -> str:
    """Remove supported Markdown emphasis, preserving identifier underscores.

    Emphasis delimiters must surround non-whitespace text and sit outside word
    characters. Repeating the substitution also handles nested emphasis. Code
    ticks already delimit ordinary mentions rather than changing their wording.
    """
    text = text.replace("`", "")
    emphasis = re.compile(r"(?<!\w)(\*{1,3}|_{1,3})(?=\S)(.*?\S)\1(?!\w)")
    while True:
        normalized = emphasis.sub(lambda match: match.group(2), text)
        if normalized == text:
            return text
        text = normalized


def valid_observation_time(value: str) -> bool:
    """Validate the stated time's syntax, without certifying the observation."""
    try:
        if "T" in value:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            date.fromisoformat(value)
    except ValueError:
        return False
    return True


def head_claim_defects(path: Path, text: str) -> list[str]:
    defects: list[str] = []
    filename_date = re.match(r"\d{4}-\d{2}-\d{2}", path.name)
    dated_handoff = filename_date is not None and valid_observation_time(filename_date.group())
    for line, block in prose_blocks(text):
        plain = normalize_prose(block)
        observed_spans = [
            match.span("head")
            for pattern in (
                (AUDIT_HEAD_OBSERVATION, TIMED_HEAD_OBSERVATION)
                if dated_handoff else (TIMED_HEAD_OBSERVATION,)
            )
            for match in pattern.finditer(plain)
            if pattern is AUDIT_HEAD_OBSERVATION or valid_observation_time(match.group("time"))
        ]
        assertions = [
            match
            for pattern in HEAD_ASSERTIONS
            for match in pattern.finditer(plain)
            if not any(start <= match.start() and match.end() <= end
                       for start, end in observed_spans)
        ]
        if assertions:
            defects.append(
                f"{path}:{line}: asserts that a named commit is the current "
                "head; record a dated observation and recheck the live head"
            )
        elif (
            LIVE_GATE.search(plain)
            and (SHA.search(plain) or path.name == "CURRENT.md")
        ):
            defects.append(
                f"{path}:{line}: declares a head-dependent gate discharged "
                "as a standing fact; the next merge changes the head"
            )
        elif path.name == "CURRENT.md" and STARTABLE.search(plain):
            defects.append(
                f"{path}:{line}: declares work startable without a live "
                "successor-head check"
            )
    return defects


def governance_defects(
    current: Path, thaw: Path, today: date | None = None, *, content: str | None = None
) -> list[str]:
    """Check explicit present-tense governance windows in a document.

    An early lift is knowable from the retained thaw record. Other unrecorded
    owner decisions cannot honestly be inferred by a repository-only check.
    """
    if content is None and not current.exists():
        return []
    if current.is_symlink():
        return [f"{current}: live governance handoff must be a regular file"]
    today = today or date.today()
    text = content if content is not None else current.read_text(encoding="utf-8")
    defects: list[str] = []
    for line, block in prose_blocks(text):
        for match in GOVERNED_THROUGH.finditer(normalize_prose(block)):
            try:
                end = date.fromisoformat(match.group("end"))
            except ValueError:
                defects.append(f"{current}:{line}: governance window has an invalid end date")
                continue
            if end < today:
                defects.append(f"{current}:{line}: asserts a governance window that has ended")
            elif (
                "SEPTEMBER_2026_CODE_FREEZE.md" in match.group()
                and thaw.is_file()
                and not thaw.is_symlink()
                and re.search(
                    r"\bowner\b.{0,40}\blifted\b",
                    thaw.read_text(encoding="utf-8"),
                    re.IGNORECASE | re.DOTALL,
                )
            ):
                defects.append(
                    f"{current}:{line}: asserts the September freeze still governs "
                    "after its recorded early lift"
                )
    return defects


def expected_tables_comment_defects(source: str) -> list[str]:
    """Check comments around/between the header and count declarations.

    AST statement bounds include multiline dictionaries; tokenize keeps values
    and strings out of the prose check. Blank lines do not detach a comment.
    Dated ratchet history may describe increments, rather than restating a
    standing total. It stays readable under the same count-pattern check.
    """
    try:
        statements = ast.parse(source).body
    except SyntaxError:
        return ["closure verifier source cannot be parsed for table-count comments"]
    declarations = {
        target.id: node
        for node in statements if isinstance(node, ast.Assign)
        for target in node.targets if isinstance(target, ast.Name)
        if target.id in {"TICKET_TABLE_HEADER", "EXPECTED_TABLES"}
    }
    if declarations.keys() != {"TICKET_TABLE_HEADER", "EXPECTED_TABLES"}:
        return ["closure verifier lacks its table-count declarations"]
    lines = source.splitlines()
    start = min(node.lineno for node in declarations.values()) - 1
    end = max(node.end_lineno or node.lineno for node in declarations.values())
    while start and (not lines[start - 1].strip() or lines[start - 1].lstrip().startswith("#")):
        start -= 1
    while end < len(lines) and (not lines[end].strip() or lines[end].lstrip().startswith("#")):
        end += 1
    comments = [
        token.string.removeprefix("#").strip()
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
        if token.type == tokenize.COMMENT and start < token.start[0] <= end
    ]
    if COMMENT_COUNT.search(normalize_prose(" ".join(comments))):
        return [
            "comment beside EXPECTED_TABLES restates a table or format count; "
            "keep the count only in the constant and dated ratchet history"
        ]
    return []


def document_defects(
    repository: Path, board_text: str, today: date | None = None
) -> list[str]:
    defects = head_claim_defects(Path("docs/EXECUTION_BOARD.md"), board_text)
    handoffs = repository / "docs" / "handoffs"
    defects += governance_defects(
        repository / "docs" / "EXECUTION_BOARD.md",
        handoffs / "2026-09-06-freeze-thaw.md", today=today, content=board_text,
    )
    archive_digests, archive_defects = archive_scope(repository)
    defects += archive_defects
    try:
        with directory_fd(repository, ("docs", "handoffs")):
            pass
    except FileNotFoundError:
        return defects
    except OSError as error:
        return defects + [f"docs/handoffs: cannot scan handoff ancestors without symlinks: {error}"]

    def walk_error(error: OSError) -> None:
        defects.append(f"docs/handoffs: cannot enumerate handoff prose: {error}")

    for folder, directories, files in os.walk(handoffs, followlinks=False, onerror=walk_error):
        for name in sorted(directories[:]):
            path = Path(folder) / name
            if path.is_symlink():
                directories.remove(name)
                relative = path.relative_to(repository)
                defects.append(f"{relative}: handoff directory symlink cannot be checked as repository prose")
        for name in sorted(files):
            path = Path(folder) / name
            if path.suffix.lower() != ".md":
                continue
            relative = path.relative_to(repository)
            if path.is_symlink():
                defects.append(f"{relative}: handoff symlink cannot be checked as repository prose")
                continue
            try:
                data = regular_bytes(repository, relative.as_posix())
                content = data.decode("utf-8")
            except (OSError, ValueError, UnicodeError) as error:
                defects.append(f"{relative}: cannot read handoff without symlink ancestors: {error}")
                continue
            expected = archive_digests.get(relative.as_posix())
            if expected is not None:
                if hashlib.sha256(data).hexdigest() != expected:
                    defects.append(f"{relative}: archive scope Markdown digest differs from sealed manifest")
                else:
                    # The exact bytes just opened, hashed and classified are
                    # the historical payload; there is no second path read.
                    continue
            defects += head_claim_defects(relative, content)
            defects += governance_defects(
                path, handoffs / "2026-09-06-freeze-thaw.md", today=today, content=content
            )
    return defects
