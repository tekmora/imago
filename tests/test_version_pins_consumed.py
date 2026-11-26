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
Statements execute only if all redirections succeed; a redirection failure is out-of-scope statement selection.
Provisioners must stay shfmt-parseable. Scripts shfmt cannot parse fail
closed by filename and parser diagnostic (see expanded-target and literal-dollar-delimiter).
"""

import json
import re
import shutil
import subprocess
from collections.abc import Iterator, Set
from datetime import date
from functools import cache
from pathlib import Path
from typing import Any, NamedTuple

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


class DynamicWord(NamedTuple):
    prefix: str


type Argument = str | DynamicWord
type Violation = tuple[str, str]

_ANSI_ESCAPE = re.compile(
    r"""\\(x[0-9a-fA-F]{1,2}|[0-7]{1,3}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|c(?:\\\\|[^\\\n])|[abefnrtvE\\'"?])"""
)
_ANSI_LETTERS = dict(zip("abefnrtvE", "\a\b\x1b\f\n\r\t\v\x1b", strict=True))
_UNQUOTED_ESCAPE = re.compile(r"\\([\s\S])")
_QUOTED_ESCAPE = re.compile(r"""\\([$"\x60\\\n])""")
_WORD_EXPANSION = re.compile(r"""\\[\s\S]|[*?~]|\[[^]]+\]|\{[^{}]*(?:,|\.\.)[^{}]*\}""")
_ASSIGNMENT_START = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\+?=")

_CONSTRUCT_REFUSALS = {
    "arithmetic": "arithmetic can recursively evaluate variable names",
    "indirect": "indirection can resolve a variable name at runtime",
    "dynamic name": "the variable name must be one plain literal name",
    "dynamic code": "the code word must be fully literal",
}
_DECLARATIONS = {"declare", "local", "typeset", "readonly", "export"}
_REFERENCE_DECLARATIONS = {"declare", "local", "typeset"}
_ARITHMETIC_TESTS = {"-eq", "-ne", "-lt", "-le", "-gt", "-ge"}
_NAME_TESTS = {"-v", "-R"}
_MAPFILE_OPTIONS = set("dnOsuCc")
_NAME_COMMANDS = {"[", "test", "printf", "getopts", "read", "mapfile", "readarray", "unset", "printenv"}
_CODE_COMMANDS = {"eval", "trap", ".", "source", "bash", "sh", "mapfile", "readarray"}
_PREFIX_OPTIONS = {
    "sudo": set("aCcDghpRrtTu")
    | {
        "auth-type",
        "chdir",
        "close-from",
        "group",
        "host",
        "prompt",
        "user",
        "chroot",
        "role",
        "type",
        "command-timeout",
    },
    "env": {"a", "C", "S", "u", "argv0", "chdir", "split-string", "unset", "env0-from"},
    "exec": {"a"},
    "command": set(),
    "builtin": set(),
    "nohup": set(),
    "timeout": {"k", "s", "kill-after", "signal"},
}

# shfmt omits Type when the concrete child type is already known to its encoder.
_UNTYPED_KINDS = {
    **dict.fromkeys(("Stmts", "Cond", "Then", "Do", "Body", "X", "Y"), "Stmt"),
    "Else": "IfClause",
    "Assigns": "Assign",
    "Args": "Assign",  # CallExpr argument words have Parts.
    "Items": "CaseItem",  # WordIter item words have Parts.
    "Elems": "ArrayElem",
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


def _escaped_character(match: re.Match[str]) -> str:
    return match[1].removesuffix("\n")


def _ansi_character(match: re.Match[str]) -> str:
    escape = match[1]
    if escape[0] in "xuU":
        codepoint = int(escape[1:], 16)
        return chr(codepoint) if codepoint <= 0x10FFFF else "\ufffd"
    if escape[0] in "01234567":
        return chr(int(escape, 8) % 256)
    if escape[0] == "c":
        return "\x7f" if escape[1] == "?" else chr(ord(escape[1]) & 31)
    return _ANSI_LETTERS.get(escape, escape)


def _literal_sections(part: Node, quoted: bool, heredoc: bool) -> Iterator[tuple[str, int]]:
    value = part.get("Value", "")
    line = part.get("ValuePos", part["Pos"])["Line"]
    for raw in re.findall(r"[^\n]*\n|[^\n]+$", value):
        if part.get("Dollar"):
            decoded, nul, _ = _ANSI_ESCAPE.sub(_ansi_character, raw).partition("\0")
            yield decoded, line
            if nul:
                break
        elif part["Type"] == "Lit" and not heredoc:
            escapes = _QUOTED_ESCAPE if quoted else _UNQUOTED_ESCAPE
            yield escapes.sub(_escaped_character, raw), line
        else:
            yield raw, line
        line += 1


def _word_sections(word: Node, *, static: bool = False, heredoc: bool = False) -> Iterator[tuple[str | None, int]]:
    for part in word.get("Parts", ()):
        kind = part["Type"]
        if kind == "DblQuoted" and not (static and part.get("Dollar")):
            for quoted in part.get("Parts", ()):
                if quoted["Type"] == "Lit":
                    yield from _literal_sections(quoted, quoted=True, heredoc=heredoc)
                else:
                    yield None, quoted["Pos"]["Line"]
        elif kind in {"SglQuoted", "Lit"}:
            if static and kind == "Lit":
                expansion = next(
                    (match for match in _WORD_EXPANSION.finditer(part.get("Value", "")) if match[0][0] != "\\"), None
                )
                if expansion:
                    yield from _literal_sections({**part, "Value": part["Value"][: expansion.start()]}, False, False)
                    yield None, part["Pos"]["Line"]
                    continue
            yield from _literal_sections(part, quoted=False, heredoc=heredoc)
        else:
            yield None, part["Pos"]["Line"]


def _literal_runs(word: Node, *, heredoc: bool = False) -> Iterator[tuple[str, list[int]]]:
    fragments: list[str] = []
    lines: list[int] = []
    for value, line in _word_sections(word, heredoc=heredoc):
        if value is None:
            yield "".join(fragments), lines
            fragments, lines = [], []
        else:
            fragments.append(value)
            lines.extend([line] * len(value))
    yield "".join(fragments), lines


def _command_word(word: Node) -> Argument:
    fragments: list[str] = []
    for value, _ in _word_sections(word, static=True):
        if value is None:
            return DynamicWord("".join(fragments))
        fragments.append(value)
    return "".join(fragments)


def _option_fields(word: str) -> Iterator[tuple[str, str | None]]:
    if word.startswith("--"):
        flag, equals, value = word[2:].partition("=")
        yield flag, value if equals else None
    else:
        for position, character in enumerate(word[1:], start=1):
            key = "+" + character if word.startswith("+") else character
            yield key, word[position + 1 :] or None


def _take_options(args: list[Argument], takes_value: Set[str]) -> tuple[dict[str, Argument | None], list[Argument]]:
    options: dict[str, Argument | None] = {}
    index = 0
    while index < len(args):
        argument = args[index]
        dynamic = isinstance(argument, DynamicWord)
        word = argument.prefix if dynamic else argument
        if (
            not word
            or word in {"-", "+"}
            or word[0] not in "-+"
            or (dynamic and word.startswith("--") and "=" not in word)
        ):
            break
        index += 1
        if word == "--":
            break
        for flag, attached in _option_fields(word):
            if flag not in takes_value:
                options[flag] = None
                continue
            value: Argument | None = DynamicWord(attached or "") if dynamic else attached
            if value is None and index < len(args):
                value = args[index]
                index += 1
            options[flag] = value
            break
    return options, args[index:]


def _invoked_command(words: list[Node]) -> tuple[str, list[Node]]:
    while words:
        name = _command_word(words[0])
        command = name.rsplit("/", 1)[-1] if isinstance(name, str) else ""
        words = words[1:]
        if command not in _PREFIX_OPTIONS:
            return command, words
        values = [_command_word(word) for word in words]
        options, remaining = _take_options(values, _PREFIX_OPTIONS[command])
        if command == "command" and options.keys() & {"v", "V"}:
            break
        skipped = len(words) - len(remaining)
        if command in {"env", "sudo"}:
            for value in remaining:
                if (command == "env" and value == "-") or _assignment_name(value):
                    skipped += 1
                else:
                    break
        words = words[skipped + (command == "timeout") :]
    return "", []


def _plain_name(value: Argument | None) -> bool:
    return isinstance(value, str) and _PIN_NAME.fullmatch(value) is not None


def _assignment_name(operand: Argument) -> str | None:
    literal = operand.prefix if isinstance(operand, DynamicWord) else operand
    assignment = _ASSIGNMENT_START.match(literal)
    return assignment[1] if assignment else None


def _declaration_violations(command: str, args: list[Argument]) -> Iterator[Violation]:
    flags, names = _take_options(args, set())
    if "i" in flags:
        yield "arithmetic", f"{command} -i"
    if "n" in flags and command in _REFERENCE_DECLARATIONS:
        yield "indirect", f"{command} -n"
    if any(not _plain_name(_assignment_name(operand) or operand) for operand in names):
        yield "dynamic name", f"{command} -p" if "p" in flags else command


def _name_operands(command: str, args: list[Argument]) -> Iterator[Argument | None]:
    if command in {"[", "test"}:
        operands = args[:-1] if command == "[" and args[-1:] == ["]"] else args
        for operator, operand in zip(operands, operands[1:], strict=False):
            if operator in _NAME_TESTS:
                yield operand
    elif command == "printf":
        flags, operands = _take_options(args, {"v"})
        if "v" in flags:
            yield flags["v"]
        elif operands and isinstance(operands[0], DynamicWord) and not operands[0].prefix:
            yield operands[0]
    elif command == "getopts":
        _, operands = _take_options(args, set())
        yield from operands[1:2]
    elif command in {"read", "mapfile", "readarray", "unset", "printenv"}:
        value_options = {"read": set("adinNptu"), "mapfile": _MAPFILE_OPTIONS, "readarray": _MAPFILE_OPTIONS}
        flags, operands = _take_options(args, value_options.get(command, set()))
        if command == "read" and "a" in flags:
            yield flags["a"]
        yield from operands


def _code_operands(command: str, args: list[Argument]) -> list[Argument | None]:
    if command == "eval":
        return args
    if command == "trap":
        flags, operands = _take_options(args, set())
        return operands[:1] if not flags.keys() & {"l", "P", "p"} else []
    if command in {".", "source"}:
        flags, operands = _take_options(args, {"p"})
        return ([flags["p"]] if "p" in flags else []) + operands[:1]
    if command in {"bash", "sh"}:
        flags, operands = _take_options(args, {"O", "o", "init-file", "rcfile"})
        return operands[:1] if "c" in flags else []
    if command in {"mapfile", "readarray"}:
        flags, _ = _take_options(args, _MAPFILE_OPTIONS)
        return [flags["C"]] if "C" in flags else []
    return []


def _call_violations(node: Node) -> Iterator[Violation]:
    command, words = _invoked_command(node.get("Args", []))
    if command == "let":
        yield "arithmetic", "let"
    if command in _DECLARATIONS | _NAME_COMMANDS | _CODE_COMMANDS:
        args = [_command_word(word) for word in words]
        if command in _DECLARATIONS:
            yield from _declaration_violations(command, args)
        if any(not _plain_name(name) for name in _name_operands(command, args)):
            yield "dynamic name", command
        if any(not isinstance(code, str) for code in _code_operands(command, args)):
            yield "dynamic code", f"{command} -c" if command in {"bash", "sh"} else command


def _ast_violations(node: Node, kind: str) -> Iterator[Violation]:
    if kind in {"ArithmCmd", "ArithmExp", "LetClause", "CStyleLoop"}:
        yield "arithmetic", kind
    if kind == "BinaryTest" and node["Op"] in _ARITHMETIC_TESTS:
        yield "arithmetic", f"[[ {node['Op']} ]]"
    if kind in {"ParamExp", "Assign", "ArrayElem"}:
        for field in ("Index", "Slice"):
            if field in node:
                yield "arithmetic", f"{kind}.{field}"
    if kind == "ParamExp" and node.get("Excl"):
        yield "indirect", "ParamExp.Excl"
    if kind == "UnaryTest" and node["Op"] in _NAME_TESTS and not _plain_name(_command_word(node["X"])):
        yield "dynamic name", f"[[ {node['Op']} ]]"
    if kind == "DeclClause":
        args = [arg["Name"]["Value"] if "Name" in arg else _command_word(arg["Value"]) for arg in node.get("Args", ())]
        yield from _declaration_violations(node["Variant"]["Value"], args)
    if kind == "CallExpr":
        yield from _call_violations(node)


def _pin_mentions(node: Node, kind: str, chain: tuple[Edge, ...], pins: Set[str]) -> Iterator[tuple[str, int, str]]:
    if kind == "ParamExp" and (name := node["Param"]["Value"]) in pins:
        modifiers = sorted(node.keys() - _PARAMETER_METADATA - {"Dollar"})
        operator = node.get("Exp", {}).get("Op")
        shape = f"parameter expansion ({', '.join(modifiers) or 'plain'})"
        if operator is not None:
            shape += f" with operator {operator!r}"
        yield name, node["Pos"]["Line"], shape
    if kind == "Word":
        for value, lines in _literal_runs(node, heredoc=chain[-1] == ("Redirect", "Hdoc")):
            for match in _PIN_NAME.finditer(value):
                if match[0] in pins:
                    yield match[0], lines[match.start()], "literal word"
    # Bare Lit fields include assignment, loop and function names, declaration variants, redirect descriptors and extglob patterns.
    if kind == "Lit" and chain[-1][0] not in {"Word", "DblQuoted"}:
        value = node.get("Value", "")
        line = node.get("ValuePos", node["Pos"])["Line"]
        for match in _PIN_NAME.finditer(value):
            if match[0] in pins:
                yield match[0], line + value.count("\n", 0, match.start()), "literal"


class PinRefusal(ValueError):
    """A script uses an unsupported construct or mentions pins outside supported read forms."""


def _pins_read(content: str, filename: str, pins: Set[str]) -> set[str]:
    """Collect allow-listed reads or raise one error with all refusals."""
    reads: set[str] = set()
    refusals: list[str] = []
    for node, kind, chain, allowed, inert in _walk_script(_parse_script(content, filename)):
        route = " > ".join(f"{parent}.{field}" for parent, field in chain)
        for group, construct in _ast_violations(node, kind):
            line = node["Pos"]["Line"]
            refusals.append(f"{filename}:{line}: [{group}] {construct} at {route}: {_CONSTRUCT_REFUSALS[group]}")
        if kind == "ParamExp" and allowed and _supported_parameter(node):
            if (name := node["Param"]["Value"]) in pins:
                reads.add(name)
        elif not inert:
            refusals.extend(
                f"{filename}:{line}: {name}: {shape} at {route}"
                for name, line, shape in _pin_mentions(node, kind, chain, pins)
            )
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
            "multiline.sh:10: QUOTED_HEREDOC_PIN: literal word at File.Stmts > Stmt.Redirs > Redirect.Hdoc",
            "multiline.sh:12: SINGLE_QUOTED_PIN: literal word at File.Stmts > Stmt.Cmd > CallExpr.Args",
            "multiline.sh:12: ESCAPED_PIN: literal word at File.Stmts > Stmt.Cmd > CallExpr.Args",
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
        ("content", "expected"),
        [
            pytest.param("declare n=P'IN'", "literal word", id="declaration-value"),
            pytest.param("echo P'IN'", "literal word", id="single-quoted-part"),
            pytest.param("echo P''IN", "literal word", id="empty-quoted-part"),
            pytest.param('echo "P"IN', "literal word", id="double-quoted-part"),
            pytest.param(r"echo P\IN", "literal word", id="unquoted-escape"),
            pytest.param(r"echo $'P\x49N'", "literal word", id="ansi-hex"),
            pytest.param(r"echo $'P\111N'", "literal word", id="ansi-octal"),
            pytest.param(r"echo $'P\u0049N'", "literal word", id="ansi-unicode"),
            pytest.param(r"echo $'P\U00000049N'", "literal word", id="ansi-long-unicode"),
            pytest.param(r"echo $'\cAPIN'", "literal word", id="ansi-control-boundary"),
            pytest.param(r"echo $'\tPIN'", "literal word", id="ansi-letter-boundary"),
            pytest.param(r"echo $'P\x00ignored'IN", "literal word", id="ansi-nul"),
            pytest.param(r'echo "P\IN"', "", id="double-quoted-literal-backslash"),
            pytest.param('echo P"$E"IN', "", id="expansion-between-literal-runs"),
            pytest.param("X=P'IN'", "literal word", id="assignment-value"),
            pytest.param("cat <<P'IN'\nbody\nPIN\n", "literal word", id="here-delimiter"),
            pytest.param("[[ x == P'IN' ]]", "literal word", id="test-operand"),
            pytest.param("declare -i n=P'IN'", "arithmetic", id="integer-declaration"),
            pytest.param("let P'IN'", "arithmetic", id="let-split"),
            pytest.param("NAME=P'IN'; printf '%s' \"${!NAME}\"", "indirect", id="split-indirect-name"),
            pytest.param("declare -n alias=P'IN'", "indirect", id="split-nameref"),
            pytest.param("n=$(printf P)IN; (( n ))", "arithmetic", id="recursive-arithmetic"),
            pytest.param('printenv "$(printf P)IN"', "dynamic name", id="printenv"),
            pytest.param("[[ -v $NAME ]]", "dynamic name", id="variable-test"),
            pytest.param('printf -v "$NAME" x', "dynamic name", id="printf-name"),
            pytest.param('read -r "$NAME"', "dynamic name", id="read-name"),
            pytest.param(r'eval "echo \$$NAME"', "dynamic code", id="eval"),
            pytest.param('trap "$CODE" EXIT', "dynamic code", id="trap"),
            pytest.param('sudo bash -c "$CODE"', "dynamic code", id="sudo-shell"),
            pytest.param('. "$FILE"', "dynamic code", id="dot-source"),
            pytest.param("[[ 1 -eq 1 ]]", "arithmetic", id="arithmetic-test-without-pin"),
            pytest.param('echo "$((1))"', "arithmetic", id="arithmetic-expansion-without-pin"),
            pytest.param("for ((n=0; n<1; n++)); do :; done", "arithmetic", id="arithmetic-loop-without-pin"),
            pytest.param('arr=(x); echo "${arr[0]}"', "arithmetic", id="parameter-index-without-pin"),
            pytest.param('value=abc; echo "${value:1}"', "arithmetic", id="parameter-slice-without-pin"),
            pytest.param("arr[0]=x", "arithmetic", id="assignment-index-without-pin"),
            pytest.param('arr=(x); echo "${!arr[@]}"', "indirect", id="indirect-index-list"),
            pytest.param('echo "${!N*}" "${!N@}"', "indirect", id="indirect-prefix-list"),
            pytest.param('declare -p "$NAME"', "dynamic name", id="declare-query"),
            pytest.param('export "${NAME}=x"', "dynamic name", id="export-name"),
            pytest.param('readonly "$NAME"', "dynamic name", id="readonly-name"),
            pytest.param('test -v "$NAME"', "dynamic name", id="test-name"),
            pytest.param('[ -v "$NAME" ]', "dynamic name", id="bracket-name"),
            pytest.param('printf -v"$NAME" x', "dynamic name", id="printf-attached-name"),
            pytest.param('read -a"$NAME"', "dynamic name", id="read-array-option"),
            pytest.param('mapfile -t "$NAME"', "dynamic name", id="mapfile-name"),
            pytest.param('readarray "$NAME"', "dynamic name", id="readarray-name"),
            pytest.param('getopts a "$NAME" -a', "dynamic name", id="getopts-name"),
            pytest.param('unset -v "$NAME"', "dynamic name", id="unset-name"),
            pytest.param('mapfile -C"$CODE" -c1', "dynamic code", id="mapfile-callback"),
            pytest.param('command -- eval "$CODE"', "dynamic code", id="command-eval"),
            pytest.param('builtin source -- "$FILE"', "dynamic code", id="builtin-source"),
            pytest.param(
                'env MARK="$VALUE" nohup timeout -k 1 1 /usr/bin/bash -uc "$CODE"', "dynamic code", id="nested-wrappers"
            ),
            pytest.param('exec -a runner /usr/bin/bash -uc "$CODE"', "dynamic code", id="exec-shell"),
            pytest.param('timeout 1 sh -uc "$CODE"', "dynamic code", id="timeout-shell"),
            pytest.param("""trap 'echo $PIN' EXIT""", "literal word", id="literal-trap-pin"),
            pytest.param('[ "$#" -ne 2 ]', "", id="bracket-numeric-test"),
            pytest.param('export HF_HOME="/var/lib/models/huggingface"', "", id="export-assignment"),
            pytest.param("""trap 'rm -rf "${tmpdir}"' EXIT""", "", id="literal-trap"),
            pytest.param("local tmpdir", "", id="literal-local"),
            pytest.param(". /lib/dracut-lib.sh", "", id="literal-source"),
            pytest.param('exec /sbin/x "$@"', "", id="ordinary-exec"),
            pytest.param('echo "$PIN"', "read", id="ordinary-read"),
        ],
    )
    def test_pin_reader_round_eight(self, content: str, expected: str) -> None:
        if expected in {"", "read"}:
            assert _pins_read(content, "round-eight.sh", {"PIN"}) == ({"PIN"} if expected == "read" else set())
            return
        with pytest.raises(PinRefusal) as error:
            _pins_read(content, "round-eight.sh", {"PIN"})
        detail = "PIN: literal word" if expected == "literal word" else rf"\[{expected}\] .+"
        assert re.search(rf"^round-eight\.sh:\d+: {detail} at File\.Stmts", str(error.value), re.MULTILINE)

    def test_pin_reader_redirect_scope(self) -> None:
        contents = (
            ': >/dev/null <<<"$PIN"',
            # The docstring puts failed redirections under statement selection.
            ': >/dev/null/not-a-directory <<<"$PIN"',
        )
        assert tuple(_pins_read(content, "redirect.sh", {"PIN"}) for content in contents) == ({"PIN"}, {"PIN"})

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
