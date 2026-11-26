# Copyright 2026 Lusoris
"""Verify Renovate pull-request metadata and package-rule release ages.

Renovate pull requests must satisfy the governance hard gates in
.github/workflows/pr-project-gate.yml:
1. Assigned active milestone (milestone > 0).
2. Tracked issue or epic reference in PR title or body (via prBodyNotes).
3. At least one 'tier/*' or 'area/*' label.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
RENOVATE_PATH = ROOT / "renovate.json"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "pr-project-gate.yml"
LABEL_AREA_TIER_PATTERN = re.compile(r"^(tier|area)/")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a dictionary from key-value pairs, refusing duplicate keys."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key in JSON: {key!r}")
        result[key] = value
    return result


def load_renovate_config(path: Path = RENOVATE_PATH) -> dict[str, Any]:
    """Load renovate.json with strict duplicate key rejection."""
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)


def parse_gate_regexes(workflow_path: Path = WORKFLOW_PATH) -> tuple[re.Pattern[str], re.Pattern[str]]:
    """Parse issue-ref and tier/area label regexes from pr-project-gate.yml.

    Translates POSIX [[:space:]] in the issue-ref pattern to Python \\s.
    """
    content = workflow_path.read_text(encoding="utf-8")

    issue_match = re.search(r"grep\s+-Eqi\s+'([^']+)'", content)
    assert issue_match is not None, "issue-ref pattern not found in pr-project-gate.yml"
    issue_posix = issue_match.group(1)
    issue_python = issue_posix.replace("[[:space:]]", r"\s")
    issue_regex = re.compile(issue_python, re.IGNORECASE)

    label_match = re.search(r"grep\s+-Eq\s+'([^']+)'", content)
    assert label_match is not None, "label pattern not found in pr-project-gate.yml"
    label_gate_regex = re.compile(label_match.group(1))

    return issue_regex, label_gate_regex


def check_renovate_config(
    config: dict[str, Any],
    issue_regex: re.Pattern[str] | None = None,
) -> list[str]:
    """Check a Renovate config against the PR metadata gate requirements.

    Returns a list of identified problems (empty when all gate requirements pass).
    """
    if issue_regex is None:
        issue_regex, _ = parse_gate_regexes()

    problems: list[str] = []

    # 1. Milestone Check: must be an int > 0
    milestone = config.get("milestone")
    if not isinstance(milestone, int) or isinstance(milestone, bool) or milestone <= 0:
        problems.append(f"milestone must be an int > 0, got {milestone!r}")

    # 2. Issue/Epic Reference Check: prBodyNotes joined must match issue-ref regex
    notes = config.get("prBodyNotes")
    if not isinstance(notes, list) or not notes:
        problems.append("missing or empty prBodyNotes with issue reference")
    else:
        joined_notes = "\n".join(str(note) for note in notes)
        if not issue_regex.search(joined_notes):
            problems.append(f"prBodyNotes joined does not match issue reference regex: {joined_notes!r}")

    # 3. Label Check: at least one label matches ^(tier|area)/
    labels = config.get("labels")
    if not isinstance(labels, list) or not any(
        isinstance(lbl, str) and LABEL_AREA_TIER_PATTERN.search(lbl) for lbl in labels
    ):
        problems.append("labels must contain at least one 'tier/*' or 'area/*' label")

    return problems


def check_package_rule_release_ages(config: dict[str, Any]) -> list[str]:
    """Check packageRules against the Semgrep minimum release age rule."""
    required_matchers = {"matchPackageNames", "matchPackagePatterns", "matchDepTypes"}
    problems: list[str] = []
    for index, rule in enumerate(config.get("packageRules", [])):
        if "minimumReleaseAge" not in rule:
            if required_matchers.intersection(rule):
                problems.append(f"packageRules[{index}] is missing minimumReleaseAge")
            continue

        age = rule["minimumReleaseAge"]
        if age is False:
            continue
        match = re.fullmatch(r"(\d+) days?", age, flags=re.ASCII) if isinstance(age, str) else None
        if match is None or int(match[1]) < 7:
            problems.append(f"packageRules[{index}].minimumReleaseAge must be false or at least 7 days, got {age!r}")
    return problems


def test_renovate_package_rule_release_ages() -> None:
    problems = check_package_rule_release_ages(load_renovate_config())
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("matcher", ["matchDepTypes", "matchPackageNames", "matchPackagePatterns"])
def test_release_age_required_for_package_matchers(matcher: str) -> None:
    config = {"packageRules": [{matcher: ["example"]}]}
    assert check_package_rule_release_ages(config) == ["packageRules[0] is missing minimumReleaseAge"]

    config["packageRules"][0]["minimumReleaseAge"] = "7 days"
    assert check_package_rule_release_ages(config) == []


@pytest.mark.parametrize(
    ("rule", "accepted"),
    [
        pytest.param({"matchDepTypes": ["golang"], "minimumReleaseAge": "3 days"}, False, id="three-days"),
        pytest.param({"matchDepTypes": ["golang"], "minimumReleaseAge": "1 week"}, False, id="week-unit"),
        pytest.param({"matchDepTypes": ["golang"], "minimumReleaseAge": "7 days"}, True, id="seven-days"),
        pytest.param({"matchDepTypes": ["golang"], "minimumReleaseAge": "1 day"}, False, id="one-day"),
        pytest.param({"matchDepTypes": ["golang"], "minimumReleaseAge": "7 day"}, True, id="singular-day-unit"),
        pytest.param({"matchDepTypes": ["golang"], "minimumReleaseAge": False}, True, id="false-opt-out"),
        pytest.param({"matchDepTypes": ["golang"], "minimumReleaseAge": True}, False, id="true"),
        pytest.param({"matchDepTypes": ["golang"], "minimumReleaseAge": None}, False, id="null"),
        pytest.param({"matchDepTypes": ["golang"], "minimumReleaseAge": 7}, False, id="number"),
        pytest.param({"matchManagers": ["gomod"]}, True, id="manager-only-without-age"),
        pytest.param({"matchDepNames": ["go"], "minimumReleaseAge": "6 days"}, False, id="short-age-on-any-rule"),
    ],
)
def test_release_age_allow_list(rule: dict[str, Any], accepted: bool) -> None:
    config = {"packageRules": [{"matchManagers": ["gomod"]}, rule]}
    problems = check_package_rule_release_ages(config)
    expected = []
    if not accepted:
        expected.append(
            f"packageRules[1].minimumReleaseAge must be false or at least 7 days, got {rule['minimumReleaseAge']!r}"
        )
    assert problems == expected


def test_renovate_pr_metadata():
    """Verify renovate.json satisfies all metadata gate requirements."""
    config = load_renovate_config()
    issue_regex, label_gate_regex = parse_gate_regexes()

    problems = check_renovate_config(config, issue_regex=issue_regex)
    assert not problems, f"renovate.json has gate compliance problems: {problems}"

    # Assert milestone is an int > 0
    milestone = config.get("milestone")
    assert isinstance(milestone, int) and not isinstance(milestone, bool)
    assert milestone > 0

    # Assert each prBodyNotes string joined matches the issue-ref regex
    notes = config.get("prBodyNotes")
    assert isinstance(notes, list) and len(notes) > 0
    joined_notes = "\n".join(notes)
    assert issue_regex.search(joined_notes) is not None

    # Assert some label matches ^(tier|area)/
    labels = config.get("labels")
    assert isinstance(labels, list)
    assert any(LABEL_AREA_TIER_PATTERN.search(label) for label in labels)

    # Assert workflow gate's raw label grep pattern matches JSON-serialized labels
    assert label_gate_regex.search(json.dumps(labels)) is not None


def _matches_literal_patterns(value: str | None, patterns: list[str]) -> bool:
    """Model the case-insensitive literals and literal negation used by this config."""
    assert all(re.fullmatch(r"!?[A-Za-z0-9_.-][A-Za-z0-9_./-]*", pattern) for pattern in patterns), (
        f"unsupported Renovate match pattern: {patterns!r}"
    )
    if value is None or not patterns:
        return False
    positive = {pattern.lower() for pattern in patterns if not pattern.startswith("!")}
    negative = {pattern[1:].lower() for pattern in patterns if pattern.startswith("!")}
    value = value.lower()
    return value not in negative and (not positive or value in positive)


def _resolve_package_rules(
    rules: list[dict[str, Any]],
    *,
    manager: str,
    dep_name: str,
    dep_type: str | None,
    datasource: str,
    file: str,
) -> dict[str, Any]:
    match_values = {
        "matchManagers": manager,
        "matchDepNames": dep_name,
        "matchDepTypes": dep_type,
        "matchDatasources": datasource,
        "matchFileNames": file,
    }
    resolved: dict[str, Any] = {}
    for index, rule in enumerate(rules):
        matchers = {key for key in rule if key.startswith("match")}
        unknown = matchers - match_values.keys()
        assert not unknown, f"packageRules[{index}] has unsupported matchers: {sorted(unknown)}"
        matches = [_matches_literal_patterns(match_values[key], rule[key]) for key in matchers]
        if all(matches):
            resolved.update({key: value for key, value in rule.items() if key not in matchers})
    return resolved


def _needs_go_manager(config: dict[str, Any]) -> dict[str, Any]:
    managers = [
        manager
        for manager in config["customManagers"]
        if manager.get("customType") == "regex"
        and any(re.search(pattern[1:-1], ".needs.yaml") for pattern in manager["managerFilePatterns"])
    ]
    assert len(managers) == 1, "One regex manager must track the .needs.yaml Go pin"
    return managers[0]


def _assert_go_toolchain_rule(file: str, settings: dict[str, Any]) -> None:
    assert settings.get("groupSlug") == "go-toolchain", f"{file} must resolve to the go-toolchain group"
    assert settings.get("groupName") == "go-toolchain", f"{file} must resolve to the go-toolchain group name"
    assert settings.get("minimumReleaseAge") == "7 days", f"{file} must resolve to minimumReleaseAge of 7 days"


def _needs_go_settings(config: dict[str, Any], manager: dict[str, Any]) -> dict[str, Any]:
    return _resolve_package_rules(
        config["packageRules"],
        manager=f"custom.{manager['customType']}",
        dep_name=manager["depNameTemplate"],
        dep_type=manager.get("depTypeTemplate"),
        datasource=manager["datasourceTemplate"],
        file=".needs.yaml",
    )


def test_renovate_updates_go_pins_together() -> None:
    config = load_renovate_config()
    rules = config["packageRules"]
    assert any(
        rule.get("matchManagers") == ["gomod"]
        and rule.get("matchDepNames") == ["go"]
        and rule.get("matchDepTypes") == ["golang"]
        and rule.get("rangeStrategy") == "bump"
        for rule in rules
    ), "Go directives need the gomod bump opt-in"
    assert any(
        rule.get("matchDepNames") == ["go"]
        and rule.get("groupName")
        and rule.get("groupSlug")
        and {key for key in rule if key.startswith("match")} == {"matchDepNames"}
        for rule in rules
    ), "All Go pins need one group across managers"
    assert any(rule.get("groupSlug") == "go-modules" and rule.get("matchDepNames") == ["!go"] for rule in rules), (
        "The go-modules group must exclude Go directives"
    )

    needs = ROOT / ".needs.yaml"
    manager = _needs_go_manager(config)
    assert manager["depNameTemplate"] == "go"
    assert manager["datasourceTemplate"] == "golang-version"
    content = needs.read_text(encoding="utf-8")
    pins = [
        match["currentValue"]
        for pattern in manager["matchStrings"]
        for match in re.finditer(pattern.replace("(?<", "(?P<"), content)
    ]
    assert len(pins) == 1, "The regex manager must capture the real go_version line"
    for file in ("go.mod", "tools/govulncheck/go.mod"):
        directive = re.search(r"^go (\S+)$", (ROOT / file).read_text(encoding="utf-8"), re.MULTILINE)
        assert directive is not None
        assert pins[0] == directive[1], f"{file} must match the .needs.yaml Go pin"
        settings = _resolve_package_rules(
            rules, manager="gomod", dep_name="go", dep_type="golang", datasource="golang-version", file=file
        )
        _assert_go_toolchain_rule(file, settings)
    _assert_go_toolchain_rule(".needs.yaml", _needs_go_settings(config, manager))


def test_needs_go_pin_requires_the_group_release_age() -> None:
    config = load_renovate_config()
    (group,) = [rule for rule in config["packageRules"] if rule.get("groupSlug") == "go-toolchain"]
    group.pop("minimumReleaseAge", None)
    with pytest.raises(AssertionError, match=r"\.needs\.yaml must resolve to minimumReleaseAge of 7 days"):
        _assert_go_toolchain_rule(".needs.yaml", _needs_go_settings(config, _needs_go_manager(config)))


def test_package_rule_resolver_refuses_unknown_matchers() -> None:
    with pytest.raises(AssertionError, match=r"unsupported matchers: \['matchPackageNames'\]"):
        _resolve_package_rules(
            [{"matchManagers": ["gomod"], "matchPackageNames": ["go"], "minimumReleaseAge": "7 days"}],
            manager="custom.regex",
            dep_name="go",
            dep_type=None,
            datasource="golang-version",
            file=".needs.yaml",
        )


def test_package_rule_resolver_applies_matching_rules_in_order() -> None:
    rules = [
        {"matchManagers": ["custom.regex"], "minimumReleaseAge": "3 days", "groupSlug": "example"},
        {"matchDepNames": ["!go"], "groupSlug": "wrong-group"},
        {"matchDepTypes": ["!golang"], "groupSlug": "unset-dep-type-is-not-a-match"},
        {"matchDatasources": ["golang-version"], "matchFileNames": [".needs.yaml"], "minimumReleaseAge": "7 days"},
        {"matchFileNames": ["go.mod"], "minimumReleaseAge": "10 days"},
    ]
    assert _resolve_package_rules(
        rules, manager="custom.regex", dep_name="GO", dep_type=None, datasource="golang-version", file=".needs.yaml"
    ) == {"minimumReleaseAge": "7 days", "groupSlug": "example"}


def test_checker_refuses_unpatched_config():
    """Verify the checker refuses a config without milestone, labels=['dependencies'], and no ref note."""
    issue_regex, _ = parse_gate_regexes()
    unpatched = {
        "labels": ["dependencies"],
    }
    problems = check_renovate_config(unpatched, issue_regex=issue_regex)
    assert len(problems) == 3
    assert any("milestone" in p for p in problems)
    assert any("labels" in p for p in problems)
    assert any("prBodyNotes" in p for p in problems)


@pytest.mark.parametrize(
    ("mutation", "expected_problem_keyword"),
    [
        ({"milestone": None}, "milestone"),
        ({"milestone": 0}, "milestone"),
        ({"milestone": -1}, "milestone"),
        ({"milestone": "1"}, "milestone"),
        ({"milestone": True}, "milestone"),
        ({"labels": ["dependencies"]}, "labels"),
        ({"labels": []}, "labels"),
        ({"labels": ["kind/chore"]}, "labels"),
        ({"prBodyNotes": []}, "prBodyNotes"),
        ({"prBodyNotes": None}, "prBodyNotes"),
        ({"prBodyNotes": ["Automated update without issue reference"]}, "prBodyNotes"),
    ],
    ids=[
        "missing-milestone",
        "zero-milestone",
        "negative-milestone",
        "string-milestone",
        "bool-milestone",
        "dependencies-label-only",
        "empty-labels",
        "kind-label-only",
        "empty-pr-body-notes",
        "none-pr-body-notes",
        "note-without-ref",
    ],
)
def test_checker_refuses_individual_defects(mutation, expected_problem_keyword):
    """Verify the checker catches each individual defect."""
    config = load_renovate_config()
    for key, value in mutation.items():
        if value is None:
            config.pop(key, None)
        else:
            config[key] = value

    problems = check_renovate_config(config)
    assert len(problems) >= 1
    assert any(expected_problem_keyword in p for p in problems)


def test_load_renovate_config_rejects_duplicate_keys():
    """Verify reject_duplicate_keys raises ValueError on duplicate JSON keys."""
    duplicate_json = '{"milestone": 1, "milestone": 2}'
    with pytest.raises(ValueError, match="duplicate key in JSON"):
        json.loads(duplicate_json, object_pairs_hook=reject_duplicate_keys)
