"""Small, deliberately bounded checks for claims that outlive their evidence.

These checks recognize assertions, not every mention of a commit or date. A
dated observation remains useful after main moves; a present-tense statement
that a particular commit is *the* current head does not.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path


COMMIT = r"(?:`)?[0-9a-f]{7,40}(?:`)?"
HEAD_ASSERTIONS = (
    re.compile(
        rf"\b(?:current|present|latest|now)\s+(?:protected[- ]main\s+)?"
        rf"(?:head|commit)\s+(?:is\s+|at\s+)?{COMMIT}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:protected[- ]main|main)\s+(?:head\s+)?(?:is|remains)\s+"
        rf"(?:at\s+|commit\s+)?{COMMIT}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{COMMIT}\s+(?:is|remains)\s+(?:the\s+)?"
        r"(?:current|present|latest)\s+(?:protected[- ]main\s+)?head\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b(?:protected[- ]main|successor)\s+head\s+{COMMIT}\s+"
        r"(?:is|has been)\s+(?:now\s+)?(?:verified|green|current)\b",
        re.IGNORECASE,
    ),
)
LIVE_GATE = re.compile(
    r"\b(?:gate|condition|verification)\b.{0,80}?\b(?:is|has been)\s+"
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
COUNT = r"(?:\d+|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve)"
COMMENT_COUNT = re.compile(
    rf"\b{COUNT}\b(?:\s+\w+){{0,3}}\s+"
    r"(?:tables?|row\s+formats?)\b|"
    rf"\bonly\s+the\s+{COUNT}\s+whose\s+first\s+header\b",
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


def head_claim_defects(path: Path, text: str) -> list[str]:
    defects: list[str] = []
    dated_handoff = re.match(r"\d{4}-\d{2}-\d{2}", path.name) is not None
    for line, block in prose_blocks(text):
        plain = block.replace("`", "").replace("**", "")
        if any(pattern.search(plain) for pattern in HEAD_ASSERTIONS):
            if dated_handoff and re.search(
                r"\b(?:found|observed|audited|at the time)\b", plain, re.IGNORECASE
            ):
                # The filename dates the observation and the prose reports it
                # as an audit finding. It makes no live-head instruction.
                continue
            defects.append(
                f"{path}:{line}: asserts that a named commit is the current "
                "head; record a dated observation and recheck the live head"
            )
        elif (
            not block.startswith("|")
            and LIVE_GATE.search(plain)
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


def governance_defects(current: Path, thaw: Path, today: date | None = None) -> list[str]:
    """Check only the live handoff's explicit governance window.

    An early lift is knowable from the retained thaw record. Other unrecorded
    owner decisions cannot honestly be inferred by a repository-only check.
    """
    if not current.exists():
        return []
    if current.is_symlink():
        return [f"{current}: live governance handoff must be a regular file"]
    today = today or date.today()
    text = current.read_text(encoding="utf-8")
    defects: list[str] = []
    for line, block in prose_blocks(text):
        match = GOVERNED_THROUGH.search(block)
        if not match:
            continue
        try:
            end = date.fromisoformat(match.group("end"))
        except ValueError:
            defects.append(f"{current}:{line}: governance window has an invalid end date")
            continue
        if end < today:
            defects.append(f"{current}:{line}: asserts a governance window that has ended")
        elif (
            "SEPTEMBER_2026_CODE_FREEZE.md" in block
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
    """Refuse prose counts immediately beside the table-count constants."""
    lines = source.splitlines()
    declaration = next(
        (index for index, line in enumerate(lines) if line.startswith('TICKET_TABLE_HEADER = ')),
        None,
    )
    if declaration is None:
        return ["closure verifier has no TICKET_TABLE_HEADER declaration"]
    block: list[str] = []
    for line in reversed(lines[:declaration]):
        if not line.startswith("#"):
            break
        block.append(line)
    if COMMENT_COUNT.search(" ".join(reversed(block))):
        return [
            "comment beside EXPECTED_TABLES restates a table or format count; "
            "keep the count only in the constant and dated ratchet history"
        ]
    return []


def document_defects(repository: Path, board_text: str) -> list[str]:
    defects = head_claim_defects(Path("docs/EXECUTION_BOARD.md"), board_text)
    handoffs = repository / "docs" / "handoffs"
    if handoffs.exists():
        for path in sorted(handoffs.rglob("*.md")):
            relative = path.relative_to(repository)
            if path.is_symlink():
                defects.append(f"{relative}: handoff symlink cannot be checked as repository prose")
                continue
            try:
                content = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                defects.append(f"{relative}: cannot read handoff: {error}")
                continue
            defects += head_claim_defects(relative, content)
    defects += governance_defects(
        handoffs / "CURRENT.md", handoffs / "2026-09-06-freeze-thaw.md"
    )
    return defects
