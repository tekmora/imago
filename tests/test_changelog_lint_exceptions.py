# Copyright 2026 Lusoris
# SPDX-License-Identifier: EUPL-1.2
"""Check that changelog markdownlint exceptions are scoped and current."""

import re
from datetime import date
from pathlib import Path

import pytest

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
_CATEGORY_DAYS = {"A": None, "B": 3, "C": 10, "D": 120}
_RULES = r"MD[0-9]{3}(?:[ \t]+MD[0-9]{3})*"
_DATE = r"[0-9]{4}-[0-9]{2}-[0-9]{2}"
_INLINE_DIRECTIVE = re.compile(r"<!--\s*markdownlint-", re.IGNORECASE)
_NEXT_LINE = re.compile(rf"<!-- markdownlint-disable-next-line (?P<rules>{_RULES}) -->")
_EXCEPTION = re.compile(
    rf"<!-- lint-exception: rule (?P<rules>{_RULES}), category (?P<category>[A-Z]), "
    rf"entered (?P<entered>{_DATE}), expires (?P<expires>{_DATE}), "
    r"issue [1-9][0-9]*: (?P<reason>(?:(?!-->).)*) -->"
)

ENTERED = date(2026, 11, 25)
EXPIRES = date(2026, 12, 5)
VALID_REASON = (
    "<!-- lint-exception: rule MD024, category C, entered 2026-11-25, "
    "expires 2026-12-05, issue 278: Preserve the released heading -->"
)
DISABLE = "<!-- markdownlint-disable-next-line MD024 -->"


def _exception_problem(reason_line: str, rules: str, today: date) -> str | None:
    metadata = _EXCEPTION.fullmatch(reason_line)
    if metadata is None or not metadata["reason"].strip():
        return "missing or invalid lint-exception on preceding line"
    if set(metadata["rules"].split()) != set(rules.split()):
        return f"lint-exception rules do not match {rules}"

    category = metadata["category"]
    if category not in _CATEGORY_DAYS:
        return f"{rules} exception has unknown category {category}"
    try:
        entered = date.fromisoformat(metadata["entered"])
        expires = date.fromisoformat(metadata["expires"])
    except ValueError:
        return f"{rules} exception has an invalid date"

    if expires < entered:
        return f"{rules} exception expiry precedes entry"
    limit = _CATEGORY_DAYS[category]
    if limit is not None and (expires - entered).days > limit:
        return f"{rules} exception exceeds {limit} days for category {category}"
    if today > expires:
        return f"{rules} exception expired on {expires.isoformat()}"
    return None


def lint_exception_problems(text: str, today: date) -> list[str]:
    lines = text.splitlines()
    problems = []
    for index, line in enumerate(lines):
        if not _INLINE_DIRECTIVE.search(line):
            continue
        directive = _NEXT_LINE.fullmatch(line.strip())
        if directive is None:
            problems.append(f"line {index + 1}: unsupported markdownlint directive")
            continue
        reason_line = lines[index - 1].strip() if index else ""
        problem = _exception_problem(reason_line, directive["rules"], today)
        if problem is not None:
            problems.append(f"line {index + 1}: {problem}")
    return problems


def test_changelog_lint_exceptions_are_current() -> None:
    problems = lint_exception_problems(CHANGELOG.read_text(encoding="utf-8"), date.today())
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize(
    ("category", "expiry"),
    [("A", "2027-11-25"), ("B", "2026-11-28"), ("C", "2026-12-05"), ("D", "2027-03-25")],
)
def test_accepts_exception_through_expiry(category: str, expiry: str) -> None:
    reason = VALID_REASON.replace("category C", f"category {category}").replace("2026-12-05", expiry)
    assert lint_exception_problems(f"{reason}\n{DISABLE}\n### Added", date.fromisoformat(expiry)) == []


def test_expired_exception_names_rule_line_and_expiry() -> None:
    text = f"{VALID_REASON}\n{DISABLE}\n### Added"
    assert lint_exception_problems(text, date(2026, 12, 6)) == ["line 2: MD024 exception expired on 2026-12-05"]


@pytest.mark.parametrize(
    ("reason", "message"),
    [
        pytest.param("", "missing or invalid lint-exception", id="missing-reason-line"),
        pytest.param(f"{VALID_REASON}\n", "missing or invalid lint-exception", id="nonadjacent-reason-line"),
        pytest.param(VALID_REASON.replace("MD024", "MD022"), "rules do not match", id="rule-mismatch"),
        pytest.param(VALID_REASON.replace("2026-12-05", "2026-12-06"), "exceeds 10 days", id="category-c-11-days"),
        pytest.param(VALID_REASON.replace("category C", "category E"), "unknown category E", id="unknown-category"),
        pytest.param(VALID_REASON.replace("2026-12-05", "2026-11-31"), "invalid date", id="bad-date"),
        pytest.param(
            VALID_REASON.replace("2026-12-05", "2026-11-24"),
            "expiry precedes entry",
            id="reversed-dates",
        ),
        pytest.param(
            VALID_REASON.replace("Preserve the released heading", ""),
            "missing or invalid lint-exception",
            id="empty-reason",
        ),
        pytest.param(
            VALID_REASON.replace("issue 278: ", ""),
            "missing or invalid lint-exception",
            id="missing-issue",
        ),
    ],
)
def test_rejects_invalid_exception_metadata(reason: str, message: str) -> None:
    problems = lint_exception_problems(f"{reason}\n{DISABLE}\n### Added", ENTERED)
    assert len(problems) == 1
    assert message in problems[0]


def test_accepts_matching_rules_in_different_order() -> None:
    reason = VALID_REASON.replace("MD024", "MD024 MD022")
    directive = DISABLE.replace("MD024", "MD022 MD024")
    assert lint_exception_problems(f"{reason}\n{directive}\n### Added", EXPIRES) == []


@pytest.mark.parametrize(
    "directive",
    [
        "<!-- markdownlint-disable MD024 -->",
        "<!-- markdownlint-disable-file MD024 -->",
        "<!-- markdownlint-disable-line MD024 -->",
        '<!-- markdownlint-configure-file {"MD024": false} -->',
        "<!-- markdownlint-capture -->",
        "<!-- markdownlint-restore -->",
        "<!-- markdownlint-enable -->",
        "<!--markdownlint-enable-file-->",
        "### Added <!-- Markdownlint-disable-line MD024 -->",
        "<!-- markdownlint-disable-next-line -->",
    ],
)
def test_rejects_other_inline_forms(directive: str) -> None:
    assert lint_exception_problems(directive, ENTERED) == ["line 1: unsupported markdownlint directive"]
