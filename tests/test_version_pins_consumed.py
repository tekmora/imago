# Copyright 2026 Lusoris
"""Automated verification suite for Packer build environment pin consumption.

Ensures that every environment variable exposed in local.common_env of
packer/builds.pkr.hcl is consumed by at least one shell provisioner, or has an
explicit, unexpired exception entry in EXCEPTIONS.
Also verifies build wiring for stargz-snapshotter (51) and enroot (62).

A read is an allow-listed expansion Bash performs whenever its statement
executes. Statement selection (branches, command-level &&, function calls)
is out of scope. Expression-level conditions (including || and && inside
[[ ]] or arithmetic, and the word of another expansion) are refused.
Provisioners must stay shfmt-parseable. Scripts shfmt cannot parse fail
closed by filename and parser diagnostic.
"""

import json
import re
import shutil
import subprocess
from collections.abc import Iterator, Set
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

_PIN_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ERROR_OPERATORS = {":?", "?"}
_WORD_OPERATORS = _ERROR_OPERATORS | {":-", "-"}
_STRING_TEST_OPERATORS = {"==", "=", "!=", "=~", "<", ">"}
_UNARY_STRING_TEST_OPERATORS = {"-n", "-z"}
_PARAMETER_METADATA = {"Type", "Pos", "End", "Rbrace", "Param"}

type Edge = tuple[str, str]
type Node = dict[str, Any]
type Visit = tuple[Node, tuple[Edge, ...], bool, bool]

# shfmt omits Type when the concrete child type is already known to its encoder.
_UNTYPED_KINDS = {
    **dict.fromkeys(("Stmts", "Cond", "Then", "Do", "Body", "X", "Y"), "Stmt"),
    "Else": "IfClause",
    "Assigns": "Assign",
    "Args": "Assign",  # CallExpr argument words have Parts.
    "Items": "CaseItem",  # WordIter item words have Parts.
    "Redirs": "Redirect",
    "Exp": "Expansion",
}


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


def _parse_script(content: str, filename: str) -> Node:
    shfmt = shutil.which("shfmt")
    if shfmt is None:
        pytest.fail(f"shfmt is missing from PATH for {filename}; install shfmt-py from .github/requirements/test.txt")
    result = subprocess.run(
        [shfmt, "--to-json", "-ln", "bash"], input=content, capture_output=True, text=True, check=False, timeout=30
    )
    if result.returncode != 0:
        pytest.fail(f"shfmt could not parse {filename}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def _unquoted_heredoc(node: Node) -> bool:
    # shfmt 3.14.1 can emit expansions in the body of a partly quoted <<- heredoc.
    return node["Op"] in {"<<", "<<-"} and all(
        part["Type"] == "Lit" and "\\" not in part["Value"] for part in node["Word"]["Parts"]
    )


_READ_EDGES = {
    # Each contained statement has its own execution point.
    ("File", "Stmts"): None,
    ("Stmt", "Cmd"): None,
    ("Block", "Stmts"): None,
    ("Subshell", "Stmts"): None,
    ("CmdSubst", "Stmts"): None,
    ("IfClause", "Cond"): None,
    ("IfClause", "Then"): None,
    ("IfClause", "Else"): None,
    ("WhileClause", "Cond"): None,
    ("WhileClause", "Do"): None,
    ("ForClause", "Do"): None,
    ("CaseClause", "Items"): None,
    ("CaseItem", "Stmts"): None,
    ("FuncDecl", "Body"): None,
    ("BinaryCmd", "X"): None,
    ("BinaryCmd", "Y"): None,
    # Bash expands these arguments, values and word parts when the statement executes.
    ("CallExpr", "Args"): None,
    ("CallExpr", "Assigns"): None,
    ("DeclClause", "Args"): None,
    ("Assign", "Value"): None,
    ("Word", "Parts"): None,
    ("DblQuoted", "Parts"): None,
    ("CaseClause", "Word"): None,
    # Bash expands the word list on loop entry, or evaluates C-style arithmetic separately.
    ("ForClause", "Loop"): lambda node, child: child.get("Type") == "WordIter",
    ("WordIter", "Items"): None,
    # Redirection operands expand, and heredoc bodies expand only with an unquoted delimiter.
    ("Stmt", "Redirs"): None,
    ("Redirect", "Word"): None,
    ("Redirect", "Hdoc"): lambda node, child: _unquoted_heredoc(node),
    # Both binary string operands and the unary string operand are always expanded.
    ("TestClause", "X"): None,
    ("BinaryTest", "X"): lambda node, child: node["Op"] in _STRING_TEST_OPERATORS,
    ("BinaryTest", "Y"): lambda node, child: node["Op"] in _STRING_TEST_OPERATORS,
    ("UnaryTest", "X"): lambda node, child: node["Op"] in _UNARY_STRING_TEST_OPERATORS,
}


def _node_kind(node: Node, chain: tuple[Edge, ...]) -> str:
    if "Type" in node:
        return node["Type"]
    if "Parts" in node:
        return "Word"
    if isinstance(node.get("Value"), str):
        return "Lit"
    return _UNTYPED_KINDS.get(chain[-1][1], "Unknown")


def _literal_error_word(node: Node) -> bool:
    if node["Op"] not in _ERROR_OPERATORS:
        return False
    return all(
        part["Type"] in {"Lit", "SglQuoted"}
        or (part["Type"] == "DblQuoted" and all(quoted["Type"] == "Lit" for quoted in part.get("Parts", ())))
        for part in node.get("Word", {}).get("Parts", ())
    )


def _walk_script(root: Node) -> Iterator[tuple[Node, str, tuple[Edge, ...], bool, bool]]:
    pending: list[Visit] = [(root, (), True, False)]
    while pending:
        node, chain, allowed, inert = pending.pop()
        kind = _node_kind(node, chain)
        yield node, kind, chain, allowed, inert
        for field, value in reversed(node.items()):
            # Comments are inert. ParamExp itself accounts for the name in its Param child.
            if field in {"Comments", "Last"} or (kind == "ParamExp" and field == "Param"):
                continue
            edge = (kind, field)
            guard = _READ_EDGES.get(edge)
            inert_child = inert or (edge == ("Expansion", "Word") and _literal_error_word(node))
            children = value if isinstance(value, list) else [value]
            for child in reversed(children):
                if isinstance(child, dict):
                    allowed_child = allowed and edge in _READ_EDGES and (guard is None or guard(node, child))
                    pending.append((child, (*chain, edge), allowed_child, inert_child))


def _supported_parameter(node: Node) -> bool:
    fields = node.keys() - _PARAMETER_METADATA
    return fields in ({"Dollar"}, {"Dollar", "Short"}, {"Dollar", "Length"}) or (
        fields == {"Dollar", "Exp"} and node["Exp"]["Op"] in _WORD_OPERATORS
    )


class PinRefusal(ValueError):
    """A script mentions pins outside the supported read forms."""


def _pins_read(content: str, filename: str, pins: Set[str]) -> set[str]:
    """Collect allow-listed reads or raise one error with every unsupported pin mention."""
    reads: set[str] = set()
    refusals: list[str] = []
    for node, kind, chain, allowed, inert in _walk_script(_parse_script(content, filename)):
        if kind == "ParamExp" and (name := node["Param"]["Value"]) in pins:
            if allowed and _supported_parameter(node):
                reads.add(name)
                continue
            modifiers = sorted(node.keys() - _PARAMETER_METADATA - {"Dollar"})
            operator = node.get("Exp", {}).get("Op")
            shape = f"parameter expansion ({', '.join(modifiers) or 'plain'})"
            if operator is not None:
                shape += f" with operator {operator!r}"
            mentions = [(name, node["Pos"]["Line"], shape)]
        elif kind in {"Lit", "SglQuoted"} and not inert:
            value = node.get("Value", "")
            start_line = node.get("ValuePos", node["Pos"])["Line"]
            mentions = [
                (match[0], start_line + value.count("\n", 0, match.start()), "literal")
                for match in _PIN_NAME.finditer(value)
                if match[0] in pins
            ]
        else:
            continue
        if mentions:
            route = " > ".join(f"{parent}.{field}" for parent, field in chain)
            refusals.extend(f"{filename}:{line}: {name}: {shape} at {route}" for name, line, shape in mentions)
    if refusals:
        raise PinRefusal("\n".join(refusals))
    return reads


@cache
def _provisioner_reads(path: Path, pins: frozenset[str]) -> set[str]:
    return _pins_read(path.read_text(encoding="utf-8"), path.name, pins)


def _all_provisioner_reads() -> set[str]:
    pins = frozenset(get_common_env_names())
    reads: set[str] = set()
    refusals: list[str] = []
    for path in sorted(PROVISIONERS_DIR.glob("*.sh")):
        try:
            reads.update(_provisioner_reads(path, pins))
        except PinRefusal as error:
            refusals.append(str(error))
    if refusals:
        pytest.fail("\n".join(refusals), pytrace=False)
    return reads


class TestVersionPinsConsumed:
    def test_pin_reader_basics(self) -> None:
        content = (
            'CUDA_VER="${CUDA_LEGACY:?}"\necho "$ROCM_VERSION"\n# ROCM_LEGACY_VERSION is gone\n'
            '  # echo "$CUDA_MAINSTREAM"\n'
        )
        reads = {"CUDA_LEGACY", "ROCM_VERSION"}
        assert _pins_read(content, "basic.sh", reads | {"ROCM_LEGACY_VERSION", "CUDA_MAINSTREAM"}) == reads

        multiline = (
            'echo "labels:\n  # cuda $QUOTED_PIN\n"\n'
            "cat <<EOF\n# driver ${HEREDOC_PIN}\nEOF\n"
            '# echo "$COMMENTED_PIN"\n'
            "echo ready # $INLINE_COMMENT_PIN\n"
            "cat <<'EOF'\nliteral $QUOTED_HEREDOC_PIN\nEOF\n"
            "printf '%s' '$SINGLE_QUOTED_PIN' \"\\$ESCAPED_PIN\"\n"
        )
        reads = {"QUOTED_PIN", "HEREDOC_PIN"}
        pins = reads | {"COMMENTED_PIN", "INLINE_COMMENT_PIN"}
        assert _pins_read(multiline, "multiline.sh", pins) == reads
        with pytest.raises(PinRefusal) as error:
            _pins_read(multiline, "multiline.sh", pins | {"QUOTED_HEREDOC_PIN", "SINGLE_QUOTED_PIN", "ESCAPED_PIN"})
        assert str(error.value).splitlines() == [
            "multiline.sh:10: QUOTED_HEREDOC_PIN: literal at File.Stmts > Stmt.Redirs > Redirect.Hdoc > Word.Parts",
            "multiline.sh:12: SINGLE_QUOTED_PIN: literal at File.Stmts > Stmt.Cmd > CallExpr.Args > Word.Parts",
            "multiline.sh:12: ESCAPED_PIN: literal at File.Stmts > Stmt.Cmd > CallExpr.Args > Word.Parts > DblQuoted.Parts",
        ]

    @pytest.mark.parametrize(
        ("content", "read", "refused", "unread"),
        [
            pytest.param('echo $((1 << WIDTH))\necho "$PIN"', "PIN", "WIDTH", "WID PIN2", id="shift-expansion"),
            pytest.param('((n = 1 << (WIDTH + 1)))\necho "$PIN"', "PIN", "WIDTH n", "WID", id="shift-command"),
            pytest.param('echo "$((1 << WIDTH))"', "", "WIDTH", "WID", id="quoted-arithmetic"),
            pytest.param("cat <<E'OF'\n$LITERAL\nEOF\necho $PIN", "PIN", "LITERAL", "", id="single-quoted-delimiter"),
            pytest.param("cat <<\\EOF\n$LITERAL\nEOF\necho $PIN", "PIN", "LITERAL", "", id="escaped-delimiter"),
            pytest.param('cat <<-"E"OF\n\t$LITERAL\n\tEOF\necho $PIN', "PIN", "LITERAL", "", id="quoted-tab-delimiter"),
            pytest.param("cat <<EOF\n${#PIN} ${!INDIRECT}\nEOF", "PIN", "INDIRECT", "PI", id="expanding-heredoc"),
            pytest.param('echo "${#PIN}" "${!OTHER_PIN}"', "PIN", "OTHER_PIN", "PI OTHER", id="parameter-operators"),
            pytest.param("echo '${#PIN} ${!OTHER_PIN}'", "", "PIN OTHER_PIN", "", id="literal-parameter-operators"),
            pytest.param("echo word\\\n#$PIN # $COMMENT", "PIN", "", "COMMENT", id="continued-word"),
            pytest.param('echo "$PI\\\nN"', "PIN", "", "PI", id="continued-parameter"),
            pytest.param("echo word \\\n# $PIN", "", "", "PIN", id="continued-before-comment"),
            pytest.param('echo "${!PIN*}"', "", "PIN", "", id="prefix-names-star"),
            pytest.param('echo "${!PIN@}"', "", "PIN", "", id="prefix-names-at"),
            pytest.param('echo "${!PIN}"', "", "PIN", "", id="indirect-read"),
            pytest.param("(( PIN = 1 ))", "", "PIN", "", id="plain-assignment"),
            pytest.param("(( PIN += 1 ))", "", "PIN", "", id="compound-assignment"),
            pytest.param("(( PIN <<= 1 ))", "", "PIN", "", id="compound-shift-assignment"),
            pytest.param("(( PIN[INDEX] = VALUE ))", "", "PIN INDEX VALUE", "", id="indexed-assignment"),
            pytest.param("[[ PIN -gt 1 ]]", "", "PIN", "", id="arithmetic-test"),
            pytest.param("[[ -v PIN ]]", "", "PIN", "", id="variable-existence-test"),
            pytest.param("declare -n alias=PIN", "", "PIN", "", id="nameref"),
            pytest.param("(( n = $(echo PIN) ))", "", "PIN n", "", id="plain-word-inside-arithmetic-substitution"),
            pytest.param(
                "cat <<$'EOF'\n${PIN}\nEOF\necho \"$IMG_PAUSE\"", "IMG_PAUSE", "PIN", "", id="ansi-c-quoted-heredoc"
            ),
            pytest.param(
                "cat <<EOF-CONFIG\ncuda: '$CUDA_LEGACY'\nEOF-CONFIG",
                "CUDA_LEGACY",
                "",
                "",
                id="quotes-inside-unquoted-heredoc",
            ),
            pytest.param('let "n = PIN + 1"', "", "PIN", "", id="let-quoted-arithmetic"),
            pytest.param('arr=(zero one two); echo "${arr[PIN]}"', "", "PIN", "", id="indexed-read"),
            pytest.param('arr=(zero one two); arr[PIN]=x; echo "${arr[@]}"', "", "PIN", "", id="indexed-write"),
            pytest.param('for ((n=PIN; n<3; n++)); do echo "$n"; done', "", "PIN", "", id="c-style-for"),
            pytest.param('[[ "PIN" -gt 1 ]]', "", "PIN", "", id="quoted-arithmetic-test"),
            pytest.param('echo "$(( $(echo PIN) + 1 ))"', "", "PIN", "", id="arithmetic-command-substitution"),
            pytest.param('NAME=PIN; echo "${!NAME}"', "", "PIN", "", id="indirect-name"),
            pytest.param('declare -n alias=PIN; echo "$alias"', "", "PIN", "", id="nameref-read"),
            pytest.param(
                "declare -A map=([PIN]=7); (( map[PIN] ))", "", "PIN PIN", "", id="associative-arithmetic-read"
            ),
            pytest.param("declare -A map; (( map[PIN] = 2 ))", "", "PIN", "", id="associative-arithmetic-write"),
            pytest.param("(( 1 || PIN ))", "", "PIN", "", id="arithmetic-short-circuit"),
            pytest.param('PARAM=set; echo "${PARAM:-$PIN}"', "", "PIN", "", id="unused-default-expansion"),
            pytest.param("[[ x || $PIN ]]", "", "PIN", "", id="test-short-circuit"),
            pytest.param('echo "$(( $PIN + 1 ))"', "", "PIN", "", id="explicit-arithmetic-expansion"),
            pytest.param("PIN=4; echo assigned", "", "PIN", "", id="assignment-name"),
            pytest.param("echo 'PIN'", "", "PIN", "", id="single-quoted-name"),
            pytest.param('unset X; echo "${X:-PIN}"', "", "PIN", "", id="literal-default-word"),
            pytest.param('X=set; echo "${X:?PIN $PIN}"', "", "PIN PIN", "", id="nonliteral-error-word"),
            pytest.param('echo "${PIN[0]}"', "", "PIN", "", id="parameter-index"),
            pytest.param('echo "${PIN:1}"', "", "PIN", "", id="parameter-slice"),
            pytest.param('echo "${PIN/2/replaced}"', "", "PIN", "", id="parameter-replacement"),
            pytest.param('echo "${PIN^}"', "", "PIN", "", id="parameter-case-operator"),
            pytest.param('echo "${PIN:+alternate}"', "", "PIN", "", id="parameter-alternate-operator"),
            pytest.param('arr=(zero one two); echo "${arr[$PIN]}"', "", "PIN", "", id="expansion-in-index"),
            pytest.param('WORD=abc; echo "${WORD:$PIN}"', "", "PIN", "", id="expansion-in-slice"),
            pytest.param('WORD=abc; echo "${WORD/a/$PIN}"', "", "PIN", "", id="expansion-in-replacement"),
            pytest.param('echo "${#PIN}"', "PIN", "", "", id="length-expansion"),
            pytest.param('echo "${PIN?m}"', "PIN", "", "", id="required-expansion"),
            pytest.param('echo "${PIN-d}"', "PIN", "", "", id="default-expansion"),
            pytest.param('case "$PIN" in *) :;; esac', "PIN", "", "", id="case-subject"),
            pytest.param('for x in "$PIN"; do echo "$x"; done', "PIN", "", "", id="word-iteration"),
            pytest.param('echo "$(printf %s "$PIN")"', "PIN", "", "", id="command-substitution"),
            pytest.param('[[ "2" == "$PIN" ]]', "PIN", "", "", id="binary-string-test"),
            pytest.param('[[ -n "$PIN" ]]', "PIN", "", "", id="unary-string-test"),
            pytest.param("# PIN in a comment", "", "", "PIN", id="literal-comment"),
            pytest.param('echo "${OTHER:?PIN must be set}"', "OTHER", "", "PIN", id="literal-error-word"),
        ],
    )
    def test_pin_reader_detection(self, content: str, read: str, refused: str, unread: str) -> None:
        expected = set(read.split())
        pins = expected | set(refused.split()) | set(unread.split())
        if refused:
            with pytest.raises(PinRefusal) as error:
                _pins_read(content, "detection.sh", pins)
            reported = re.findall(r"^detection\.sh:\d+: (\w+): .+", str(error.value), re.MULTILINE)
            assert sorted(reported) == sorted(refused.split())
        else:
            assert _pins_read(content, "detection.sh", pins) == expected

    @pytest.mark.parametrize(
        ("content", "filename", "diagnostic"),
        [
            pytest.param('echo "$PIN"\nif then\n', "broken-provisioner.sh", r"2:\d+: .+", id="invalid-bash"),
            pytest.param("(( $PIN = 4 ))", "expanded-target.sh", r"1:9: `=` must follow a name", id="expanded-target"),
            pytest.param(
                "cat <<$DELIM\nbody\n$DELIM\n",
                "literal-dollar-delimiter.sh",
                "1:7: expansions not allowed in heredoc words",
                id="literal-dollar-delimiter",
            ),
        ],
    )
    def test_pin_reader_reports_shfmt_parse_failure(self, content: str, filename: str, diagnostic: str) -> None:
        with pytest.raises(pytest.fail.Exception, match=rf"shfmt could not parse {re.escape(filename)}: {diagnostic}"):
            _pins_read(content, filename, {"PIN"})

    def test_pin_reader_reports_missing_shfmt(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setenv("PATH", str(tmp_path))
        with pytest.raises(
            (pytest.fail.Exception, pytest.skip.Exception),
            match=r"missing-shfmt\.sh; install shfmt-py from \.github/requirements/test\.txt",
        ) as outcome:
            _pins_read('echo "$PIN"', "missing-shfmt.sh", {"PIN"})
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
