# Copyright 2026 Lusoris
"""Automated verification suite for Packer build environment pin consumption.

Ensures that every environment variable exposed in local.common_env of
packer/builds.pkr.hcl is consumed by at least one shell provisioner, or has an
explicit, unexpired exception entry in EXCEPTIONS.
Also verifies build wiring for stargz-snapshotter (51) and enroot (62).
"""

import json
import re
import shutil
import subprocess
from datetime import date
from functools import cache
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILDS_HCL_PATH = REPO_ROOT / "packer" / "builds.pkr.hcl"
PROVISIONERS_DIR = REPO_ROOT / "packer" / "provisioners"

# Pins in local.common_env that no provisioner reads: name -> {reason, expires}.
EXCEPTIONS: dict[str, dict[str, str]] = {}

ENROOT_TARGETS = {
    "base-nvidia-datacenter",
    "ai-infer-nvidia",
    "ai-infer-nvidia-modern",
    "ai-infer-nvidia-bleeding",
}

_ARITHMETIC_ROOTS = {"ArithmExp", "ArithmCmd"}
_ARITHMETIC_NODES = {"BinaryArithm", "UnaryArithm", "ParenArithm"}
_ARITHMETIC_TESTS = {"-eq", "-ne", "-lt", "-le", "-gt", "-ge"}


def get_common_env_names() -> list[str]:
    hcl = BUILDS_HCL_PATH.read_text(encoding="utf-8")
    match = re.search(r"common_env\s*=\s*\[(.*?)\]", hcl, re.DOTALL)
    assert match is not None, "local.common_env definition not found in builds.pkr.hcl"
    names: list[str] = []
    for line in match.group(1).splitlines():
        clean = line.strip().strip(",").strip('"')
        if "=" in clean:
            names.append(clean.split("=")[0])
    return names


def _parse_script(content: str, filename: str) -> dict[str, Any]:
    shfmt = shutil.which("shfmt")
    if shfmt is None:
        pytest.fail("shfmt is missing from PATH; install shfmt-py from .github/requirements/test.txt")
    result = subprocess.run(
        [shfmt, "--to-json", "-ln", "bash"], input=content, capture_output=True, text=True, check=False, timeout=30
    )
    if result.returncode != 0:
        pytest.fail(f"shfmt could not parse {filename}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def _quoted_heredoc(node: dict[str, Any]) -> bool:
    # shfmt 3.14.1 can emit expansions in the body of a partly quoted <<- heredoc.
    return node.get("Op") in {"<<", "<<-"} and any(
        part["Type"] != "Lit" or "\\" in part["Value"] for part in node["Word"]["Parts"]
    )


def _ast_children(
    node: dict[str, Any], arithmetic: bool, write: bool
) -> list[tuple[dict[str, Any] | list, bool, bool]]:
    kind = node.get("Type")
    operator = node.get("Op")
    children = []
    for field, child in node.items():
        if field == "Hdoc" and _quoted_heredoc(node):
            continue
        if not isinstance(child, (dict, list)):
            continue
        # Arithmetic context follows expression edges, never into embedded shell commands.
        child_arithmetic = (
            (field == "X" and kind in _ARITHMETIC_ROOTS)
            or (arithmetic and kind in _ARITHMETIC_NODES and field in {"X", "Y"})
            or (kind == "BinaryTest" and operator in _ARITHMETIC_TESTS and field in {"X", "Y"})
            or (arithmetic and (kind, field) in {("Word", "Parts"), ("ParamExp", "Index")})
        )
        child_write = (kind == "BinaryArithm" and operator == "=" and field == "X") or (
            write and kind == "Word" and field == "Parts"
        )
        children.append((child, child_arithmetic, child_write))
    return children


def _pins_read(content: str, filename: str) -> set[str]:
    """Collect direct parameter and bare arithmetic reads from shfmt's typed Bash tree."""
    pending: list[tuple[dict[str, Any] | list, bool, bool]] = [(_parse_script(content, filename), False, False)]
    reads: set[str] = set()
    while pending:
        node, arithmetic, write = pending.pop()
        if isinstance(node, list):
            pending.extend((child, arithmetic, write) for child in node if isinstance(child, (dict, list)))
            continue
        kind = node.get("Type")
        # shfmt models a bare indexed assignment target as a ParamExp without Dollar.
        if kind == "ParamExp" and "Names" not in node and (not write or "Dollar" in node):
            reads.add(node["Param"]["Value"])
        if kind == "Word" and arithmetic and not write:
            parts = node["Parts"]
            if len(parts) == 1 and parts[0]["Type"] == "Lit":
                reads.add(parts[0]["Value"])
        pending.extend(_ast_children(node, arithmetic, write))
    return reads


@cache
def _provisioner_reads(path: Path) -> set[str]:
    return _pins_read(path.read_text(encoding="utf-8"), path.name)


def _all_provisioner_reads() -> set[str]:
    return set().union(*(_provisioner_reads(path) for path in sorted(PROVISIONERS_DIR.glob("*.sh"))))


class TestVersionPinsConsumed:
    def test_pin_reader_basics(self) -> None:
        """A pin counts as read only through a shell expansion of its exact name."""
        content = (
            'CUDA_VER="${CUDA_LEGACY:?}"\necho "$ROCM_VERSION"\n# ROCM_LEGACY_VERSION is gone\n'
            '  # echo "$CUDA_MAINSTREAM"\n'
        )
        assert _pins_read(content, "basic.sh") == {"CUDA_LEGACY", "ROCM_VERSION"}

        multiline = (
            'echo "labels:\n  # cuda $QUOTED_PIN\n"\n'
            "cat <<EOF\n# driver ${HEREDOC_PIN}\nEOF\n"
            '# echo "$COMMENTED_PIN"\n'
            "echo ready # $INLINE_COMMENT_PIN\n"
            "cat <<'EOF'\nliteral $QUOTED_HEREDOC_PIN\nEOF\n"
            "printf '%s' '$SINGLE_QUOTED_PIN' \"\\$ESCAPED_PIN\"\n"
        )
        assert _pins_read(multiline, "multiline.sh") == {"QUOTED_PIN", "HEREDOC_PIN"}

    @pytest.mark.parametrize(
        ("content", "read", "unread"),
        [
            pytest.param('echo $((1 << WIDTH))\necho "$PIN"', ("WIDTH", "PIN"), ("WID", "PIN2"), id="shift-expansion"),
            pytest.param('((n = 1 << (WIDTH + 1)))\necho "$PIN"', ("WIDTH", "PIN"), ("WID", "n"), id="shift-command"),
            pytest.param('echo "$((1 << WIDTH))"', ("WIDTH",), ("WID",), id="quoted-arithmetic"),
            pytest.param("cat <<E'OF'\n$LITERAL\nEOF\necho $PIN", ("PIN",), ("LITERAL",), id="single-quoted-delimiter"),
            pytest.param("cat <<\\EOF\n$LITERAL\nEOF\necho $PIN", ("PIN",), ("LITERAL",), id="escaped-delimiter"),
            pytest.param(
                'cat <<-"E"OF\n\t$LITERAL\n\tEOF\necho $PIN', ("PIN",), ("LITERAL",), id="quoted-tab-delimiter"
            ),
            pytest.param("cat <<EOF\n${#PIN} ${!INDIRECT}\nEOF", ("PIN", "INDIRECT"), ("PI",), id="expanding-heredoc"),
            pytest.param(
                'echo "${#PIN}" "${!OTHER_PIN}"', ("PIN", "OTHER_PIN"), ("PI", "OTHER"), id="parameter-operators"
            ),
            pytest.param("echo '${#PIN} ${!OTHER_PIN}'", (), ("PIN", "OTHER_PIN"), id="literal-parameter-operators"),
            pytest.param("echo word\\\n#$PIN # $COMMENT", ("PIN",), ("COMMENT",), id="continued-word"),
            pytest.param('echo "$PI\\\nN"', ("PIN",), ("PI",), id="continued-parameter"),
            pytest.param("echo word \\\n# $PIN", (), ("PIN",), id="continued-before-comment"),
            pytest.param('echo "${!PIN*}"', (), ("PIN",), id="prefix-names-star"),
            pytest.param('echo "${!PIN@}"', (), ("PIN",), id="prefix-names-at"),
            pytest.param('echo "${!PIN}"', ("PIN",), (), id="indirect-read"),
            pytest.param("(( PIN = 1 ))", (), ("PIN",), id="plain-assignment"),
            pytest.param("(( PIN += 1 ))", ("PIN",), (), id="compound-assignment"),
            pytest.param("(( PIN <<= 1 ))", ("PIN",), (), id="compound-shift-assignment"),
            pytest.param("(( PIN[INDEX] = VALUE ))", ("INDEX", "VALUE"), ("PIN",), id="indexed-assignment"),
            pytest.param("[[ PIN -gt 1 ]]", ("PIN",), (), id="arithmetic-test"),
            pytest.param("[[ -v PIN ]]", (), ("PIN",), id="variable-existence-test"),
            pytest.param("declare -n alias=PIN", (), ("PIN",), id="nameref"),
            pytest.param("(( n = $(echo PIN) ))", (), ("PIN", "n"), id="plain-word-inside-arithmetic-substitution"),
            pytest.param(
                "cat <<$'EOF'\n${PIN}\nEOF\necho \"$IMG_PAUSE\"",
                ("IMG_PAUSE",),
                ("PIN",),
                id="ansi-c-quoted-heredoc",
            ),
            pytest.param(
                "cat <<EOF-CONFIG\ncuda: '$CUDA_LEGACY'\nEOF-CONFIG",
                ("CUDA_LEGACY",),
                (),
                id="quotes-inside-unquoted-heredoc",
            ),
        ],
    )
    def test_pin_reader_detection(self, content: str, read: tuple[str, ...], unread: tuple[str, ...]) -> None:
        reads = _pins_read(content, "detection.sh")
        assert set(read) <= reads, f"missed reads of {set(read) - reads}"
        assert not (unexpected := set(unread) & reads), f"unexpected reads of {unexpected}"

    def test_pin_reader_reports_shfmt_parse_failure(self, tmp_path: Path) -> None:
        script = tmp_path / "broken-provisioner.sh"
        script.write_text('echo "$PIN"\nif then\n', encoding="utf-8")
        with pytest.raises(pytest.fail.Exception, match=r"shfmt could not parse broken-provisioner\.sh: 2:\d+: .+"):
            _provisioner_reads(script)

    def test_pin_reader_reports_missing_shfmt(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("PATH", str(tmp_path))
        with pytest.raises(
            (pytest.fail.Exception, pytest.skip.Exception), match=r"shfmt-py from \.github/requirements/test\.txt"
        ) as outcome:
            _pins_read('echo "$PIN"', "missing-shfmt.sh")
        assert isinstance(outcome.value, pytest.fail.Exception), "Missing shfmt must fail the check"

    def test_exceptions_validity(self) -> None:
        """Verify exceptions: unexpired, present in common_env, and not consumed (no stale entry)."""
        common_env_names = get_common_env_names()
        reads = _all_provisioner_reads()
        today = date.today()

        for name, entry in EXCEPTIONS.items():
            expires = date.fromisoformat(entry["expires"])
            assert today <= expires, f"Exception for '{name}' expired on {entry['expires']}. Reason: {entry['reason']}"
            assert name in common_env_names, (
                f"Excepted pin '{name}' is not defined in local.common_env of builds.pkr.hcl"
            )
            assert name not in reads, (
                f"Excepted pin '{name}' is now read by provisioners; stale exception must be removed"
            )

    def test_all_common_env_pins_consumed(self) -> None:
        """Verify every common_env pin is consumed by at least one provisioner script or excepted."""
        common_env_names = get_common_env_names()
        reads = _all_provisioner_reads()

        unconsumed: list[str] = []
        for name in common_env_names:
            if name in EXCEPTIONS:
                continue
            if name not in reads:
                unconsumed.append(name)

        assert not unconsumed, (
            f"The following environment pins in builds.pkr.hcl are unconsumed by provisioners: {unconsumed}"
        )

    def test_stargz_provisioner_wiring(self) -> None:
        """Verify every build listing 50-k8s-runtime or 60-ai-infer-runtime lists 51-stargz-snapshotter."""
        hcl = BUILDS_HCL_PATH.read_text(encoding="utf-8")
        build_blocks = re.findall(r"build\s*\{.*?\n\}", hcl, re.DOTALL)
        assert len(build_blocks) >= 44

        missing_51: list[str] = []
        checked = 0
        for block in build_blocks:
            name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
            if not name_m:
                continue
            build_name = name_m.group(1)
            scripts = re.findall(r'"[^"]*provisioners/([^"]+)"', block)
            needs_51 = any("50-k8s-runtime.sh" in s or "60-ai-infer-runtime.sh" in s for s in scripts)
            has_51 = any("51-stargz-snapshotter.sh" in s for s in scripts)
            checked += needs_51
            if needs_51 and not has_51:
                missing_51.append(build_name)

        assert checked >= 16, f"only {checked} builds run 50 or 60"
        assert not missing_51, f"The following builds list 50 or 60 but are missing 51: {missing_51}"

    def test_enroot_provisioner_wiring(self) -> None:
        """Verify every enroot target build lists 62-hpc-enroot.sh."""
        hcl = BUILDS_HCL_PATH.read_text(encoding="utf-8")
        build_blocks = re.findall(r"build\s*\{.*?\n\}", hcl, re.DOTALL)

        missing_62: list[str] = []
        seen: set[str] = set()
        for block in build_blocks:
            name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
            if not name_m:
                continue
            build_name = name_m.group(1)
            scripts = re.findall(r'"[^"]*provisioners/([^"]+)"', block)
            seen.add(build_name)
            if build_name in ENROOT_TARGETS:
                has_62 = any("62-hpc-enroot.sh" in s for s in scripts)
                if not has_62:
                    missing_62.append(build_name)

        assert ENROOT_TARGETS <= seen, f"enroot targets without a build: {ENROOT_TARGETS - seen}"
        assert not missing_62, f"The following enroot targets are missing 62-hpc-enroot.sh: {missing_62}"
