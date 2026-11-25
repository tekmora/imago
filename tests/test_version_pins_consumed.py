# Copyright 2026 Lusoris
"""Automated verification suite for Packer build environment pin consumption.

Ensures that every environment variable exposed in local.common_env of
packer/builds.pkr.hcl is consumed by at least one shell provisioner, or has an
explicit, unexpired exception entry in EXCEPTIONS.
Also verifies build wiring for stargz-snapshotter (51) and enroot (62).
"""

import re
from datetime import date
from pathlib import Path

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

_NAME = r"[A-Za-z_](?:(?:\\\n)*[A-Za-z_0-9])*"
_PARAMETER = rf"\$(?:\\\n)*(?:\{{(?:\\\n)*(?:[#!](?:\\\n)*)?)?(?P<parameter>{_NAME})"
_EXPANSION = re.compile(rf"\\.|(?P<arithmetic>\$\(\()|{_PARAMETER}", re.DOTALL)
_ARITHMETIC_TOKEN = re.compile(
    rf"\\.|{_PARAMETER}|(?P<bare>{_NAME})(?P<assignment>[ \t]*=(?!=))?|[0-9][A-Za-z_0-9#@]*|[()]",
    re.DOTALL,
)
_DELIMITER_PART = r"""'[^']*'|"(?:\\.|[^"\\])*"|\\.|[^\s'"\\;&|()<>]+"""
_DELIMITER_PARTS = re.compile(_DELIMITER_PART, re.DOTALL)
_DOUBLE_QUOTED_ESCAPE = re.compile(r'\\([$`"\\\n])')
_SHELL_TOKEN = re.compile(
    rf"""
    (?P<newline>\n)
    | (?P<hash>\#)
    | (?P<arithmetic>\$?\(\()
    | (?<!<)<<(?P<tabs>-?)[ \t]*(?P<delimiter>(?:{_DELIMITER_PART})++)(?=[\s;&|()<>]|$)
    | \$'(?:\\.|[^'\\])*' | '[^']*'
    | (?P<quoted>"(?:\\.|[^"\\])*")
    | {_PARAMETER}
    | (?P<continuation>\\\n) | \\.
    | (?P<boundary>[ \t;&|()<>])
    | [^\s'"\\$\#;&|()<>]+ | .
    """,
    re.DOTALL | re.VERBOSE,
)


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


def get_all_provisioner_content() -> str:
    scripts = sorted(PROVISIONERS_DIR.glob("*.sh"))
    return "\n".join(s.read_text(encoding="utf-8") for s in scripts)


def _arithmetic_read(name: str, text: str, start: int) -> tuple[int, bool]:
    depth = 2
    reads = False
    for token in _ARITHMETIC_TOKEN.finditer(text, start):
        if token[0] == "(":
            depth += 1
        elif token[0] == ")":
            depth -= 1
            if depth == 0:
                return token.end(), reads
        else:
            variable = token["parameter"] or (token["bare"] if token["assignment"] is None else None)
            if variable and variable.replace("\\\n", "") == name:
                reads = True
    return start, False


def _expansion_reads(name: str, text: str) -> bool:
    position = 0
    for _ in range(len(text)):
        token = _EXPANSION.search(text, position)
        if token is None:
            break
        position = token.end()
        if token["arithmetic"]:
            position, reads = _arithmetic_read(name, text, position)
            if reads:
                return True
        elif token["parameter"] and token["parameter"].replace("\\\n", "") == name:
            return True
    return False


def _heredoc(word: str, strip_tabs: bool) -> tuple[re.Pattern[str], bool]:
    parts = []
    expands = True
    for match in _DELIMITER_PARTS.finditer(word):
        part = match[0]
        if part == "\\\n":
            continue
        if part.startswith('"'):
            part = _DOUBLE_QUOTED_ESCAPE.sub(lambda escape: escape[1].removesuffix("\n"), part[1:-1])
        elif part.startswith("'"):
            part = part[1:-1]
        elif part.startswith("\\"):
            part = part[1:]
        else:
            parts.append(part)
            continue
        expands = False
        parts.append(part)
    tabs = r"\t*" if strip_tabs else ""
    terminator = re.compile(rf"^{tabs}{re.escape(''.join(parts))}$", re.MULTILINE)
    return terminator, expands


def _read_heredocs(
    name: str, text: str, position: int, heredocs: list[tuple[re.Pattern[str], bool]]
) -> tuple[int, bool]:
    # Bash reads pending heredocs in redirect order once the command line ends.
    for terminator, expands in heredocs:
        end = terminator.search(text, position)
        assert end is not None, f"Missing heredoc terminator {terminator.pattern}"
        if expands and _expansion_reads(name, text[position : end.start()]):
            return end.end(), True
        position = end.end()
    return position, False


def _token_reads(name: str, token: re.Match[str]) -> bool:
    if token["quoted"]:
        return _expansion_reads(name, token["quoted"][1:-1])
    return bool(token["parameter"] and token["parameter"].replace("\\\n", "") == name)


def is_pin_read_by_provisioners(name: str, provisioner_content: str) -> bool:
    """Find an exact pin expansion in shell text, including multiline strings and heredocs."""
    position = 0
    at_word_start = True
    heredocs: list[tuple[re.Pattern[str], bool]] = []
    for _ in range(len(provisioner_content)):
        token = _SHELL_TOKEN.match(provisioner_content, position)
        if token is None:
            break
        position = token.end()
        if token["continuation"]:
            continue
        if token["hash"] and at_word_start:
            position = provisioner_content.find("\n", position)
            if position == -1:
                break
            continue
        reads = False
        if token["arithmetic"]:
            position, reads = _arithmetic_read(name, provisioner_content, position)
        elif token["delimiter"]:
            heredocs.append(_heredoc(token["delimiter"], bool(token["tabs"])))
        elif token["newline"]:
            position, reads = _read_heredocs(name, provisioner_content, position, heredocs)
            heredocs.clear()
        else:
            reads = _token_reads(name, token)
        if reads:
            return True
        at_word_start = bool(token["boundary"] or token["newline"])
    return False


class TestVersionPinsConsumed:
    def test_pin_reader_basics(self) -> None:
        """A pin counts as read only through a shell expansion of its exact name."""
        content = (
            'CUDA_VER="${CUDA_LEGACY:?}"\necho "$ROCM_VERSION"\n# ROCM_LEGACY_VERSION is gone\n'
            '  # echo "$CUDA_MAINSTREAM"\n'
        )
        assert is_pin_read_by_provisioners("CUDA_LEGACY", content)
        assert is_pin_read_by_provisioners("ROCM_VERSION", content)
        assert not is_pin_read_by_provisioners("ROCM_LEGACY_VERSION", content)
        assert not is_pin_read_by_provisioners("CUDA_MAINSTREAM", content)
        assert not is_pin_read_by_provisioners("CUDA_LEGACY_EXTRA", content)
        assert not is_pin_read_by_provisioners("CUDA", content)

        multiline = (
            'echo "labels:\n  # cuda $QUOTED_PIN\n"\n'
            "cat <<EOF\n# driver ${HEREDOC_PIN}\nEOF\n"
            '# echo "$COMMENTED_PIN"\n'
            "echo ready # $INLINE_COMMENT_PIN\n"
            "cat <<'EOF'\nliteral $QUOTED_HEREDOC_PIN\nEOF\n"
            "printf '%s' '$SINGLE_QUOTED_PIN' \"\\$ESCAPED_PIN\"\n"
        )
        candidates = [
            "QUOTED_PIN",
            "HEREDOC_PIN",
            "COMMENTED_PIN",
            "INLINE_COMMENT_PIN",
            "QUOTED_HEREDOC_PIN",
            "SINGLE_QUOTED_PIN",
            "ESCAPED_PIN",
        ]
        assert [name for name in candidates if is_pin_read_by_provisioners(name, multiline)] == [
            "QUOTED_PIN",
            "HEREDOC_PIN",
        ]

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
        ],
    )
    def test_pin_reader_detection(self, content: str, read: tuple[str, ...], unread: tuple[str, ...]) -> None:
        for name in read:
            assert is_pin_read_by_provisioners(name, content), f"missed read of {name}"
        for name in unread:
            assert not is_pin_read_by_provisioners(name, content), f"unexpected read of {name}"

    def test_exceptions_validity(self) -> None:
        """Verify exceptions: unexpired, present in common_env, and not consumed (no stale entry)."""
        common_env_names = get_common_env_names()
        provisioner_content = get_all_provisioner_content()
        today = date.today()

        for name, entry in EXCEPTIONS.items():
            expires = date.fromisoformat(entry["expires"])
            assert today <= expires, f"Exception for '{name}' expired on {entry['expires']}. Reason: {entry['reason']}"
            assert name in common_env_names, (
                f"Excepted pin '{name}' is not defined in local.common_env of builds.pkr.hcl"
            )
            assert not is_pin_read_by_provisioners(name, provisioner_content), (
                f"Excepted pin '{name}' is now read by provisioners; stale exception must be removed"
            )

    def test_all_common_env_pins_consumed(self) -> None:
        """Verify every common_env pin is consumed by at least one provisioner script or excepted."""
        common_env_names = get_common_env_names()
        provisioner_content = get_all_provisioner_content()

        unconsumed: list[str] = []
        for name in common_env_names:
            if name in EXCEPTIONS:
                continue
            if not is_pin_read_by_provisioners(name, provisioner_content):
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
