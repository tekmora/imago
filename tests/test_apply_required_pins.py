# Copyright 2026 Lusoris
"""Match the generated apply environment to the provisioner pipelines."""

import re
from collections.abc import Set
from functools import cache
from pathlib import Path
from typing import NamedTuple

import pytest

from tests.test_version_pins_consumed import (
    PROVISIONERS_DIR,
    REPO_ROOT,
    _command_word,
    _parse_script,
    _pins_read,
    _take_options,
    _walk_script,
    get_common_env_names,
)

GOLDEN = REPO_ROOT / "pkg" / "imageless" / "testdata" / "apply-scripts.golden.txt"
FLAVOR_EXPORTS = {"FLAVOR", "KERNEL_PROFILE", "PREHEAT_PROFILE"}


class ApplyBlock(NamedTuple):
    flavor: str
    mode: str
    exports: set[str]
    scripts: list[Path]


def _apply_blocks(golden: str) -> list[ApplyBlock]:
    blocks = []
    for section in re.split(r"(?m)^=== ", golden)[1:]:
        header, _, script = section.partition("\n")
        flavor, mode = header.split()
        if mode == "dry-run":
            continue
        env = script.split("# Environment configuration\n", 1)[1].split("\n# Execution pipeline\n", 1)[0]
        exports = set(re.findall(r"(?m)^export ([A-Za-z_][A-Za-z0-9_]*)=", env))
        scripts = [Path(name) for name in re.findall(r'(?m)^  bash "(packer/provisioners/[^"]+)"$', script)]
        assert scripts, f"{flavor} {mode} runs no provisioners"
        blocks.append(ApplyBlock(flavor, mode, exports, scripts))
    return blocks


@cache
def _script_inputs(path: Path, pins: frozenset[str]) -> tuple[tuple[str, ...], set[str], list[Path]]:
    content = path.read_text(encoding="utf-8")
    required = []
    sourced = []
    for node, kind, _, _, inert in _walk_script(_parse_script(content.encode("utf-8"), str(path))):
        if kind == "ParamExp" and not inert and node.get("Exp", {}).get("Op") in {":?", "?"}:
            required.append(node["Param"]["Value"])
        if kind == "CallExpr" and (words := node.get("Args")):
            command = _command_word(words[0])
            if command in (".", "source"):
                _, operands, _ = _take_options(command, [_command_word(word) for word in words[1:]])
                if operands and isinstance(operands[0], str):
                    sourced.append(Path(operands[0]))
    return tuple(dict.fromkeys(required)), _pins_read(content, str(path), pins), sourced


def _missing_inputs(root: Path, block: ApplyBlock, pins: frozenset[str]) -> tuple[list[str], str]:
    provisioners = root / "packer" / "provisioners"
    covered = block.exports & (pins | FLAVOR_EXPORTS)
    pending = list(reversed(block.scripts))
    seen = set()
    missing = []
    first_required = ""
    while pending:
        script = (root / pending.pop()).resolve()
        if script in seen or not script.is_relative_to(provisioners):
            continue
        seen.add(script)
        required, reads, sourced = _script_inputs(script, pins)
        prefix = f"{block.flavor} {block.mode} {script.relative_to(root)}"
        missing.extend(f"{prefix}: {name}" for name in sorted((set(required) | reads) - covered))
        if not first_required:
            first_required = next((f"{prefix}: {name}" for name in required if name not in covered), "")
        pending.extend(reversed(sourced))
    return missing, first_required


def _assert_apply_inputs(root: Path, blocks: list[ApplyBlock], pins: Set[str]) -> None:
    missing = []
    stopping = []
    for block in blocks:
        unexported, first_required = _missing_inputs(root, block, frozenset(pins))
        missing.extend(unexported)
        if first_required:
            stopping.append(first_required)
    count = len({line.split()[0] for line in stopping})
    assert not missing, "\n".join(
        [f"{count} flavors with missing required names:", *stopping, "All missing inputs:", *missing]
    )


def test_apply_pipelines_export_required_inputs() -> None:
    blocks = _apply_blocks(GOLDEN.read_text(encoding="utf-8"))
    assert {mode: sum(block.mode == mode for block in blocks) for mode in ("full", "skip-cleanup")} == {
        "full": 44,
        "skip-cleanup": 44,
    }
    assert len({(block.flavor, block.mode) for block in blocks}) == len(blocks) == 88
    _assert_apply_inputs(PROVISIONERS_DIR.parent.parent, blocks, set(get_common_env_names()))


@pytest.mark.parametrize(
    ("body", "helper", "name", "exports"),
    [
        pytest.param('echo "${UNKNOWN:?message}"', "", "UNKNOWN", {"UNKNOWN"}, id="unclassified-required"),
        pytest.param('echo "${PIN:?message}"', "", "PIN", set(), id="direct-required"),
        pytest.param('echo "$PIN"', "", "PIN", set(), id="plain-pin-read"),
        pytest.param(
            ". packer/provisioners/helpers/common", 'echo "${PIN?message}"', "PIN", set(), id="sourced-helper"
        ),
    ],
)
def test_apply_pipeline_reports_missing_inputs(
    tmp_path: Path, body: str, helper: str, name: str, exports: set[str]
) -> None:
    tree = Path("packer/provisioners")
    helper_path = tree / "helpers" / "common"
    script = tree / "main.sh"
    (tmp_path / helper_path.parent).mkdir(parents=True)
    (tmp_path / helper_path).write_text(helper, encoding="utf-8")
    (tmp_path / script).write_text(body, encoding="utf-8")
    block = ApplyBlock("sample-flavor", "full", exports, [script])
    expected_path = helper_path if helper else script
    diagnosis = re.escape(f"sample-flavor full {expected_path}: {name}")
    with pytest.raises(AssertionError, match=diagnosis):
        _assert_apply_inputs(tmp_path, [block], {"PIN"})
