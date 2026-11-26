# Copyright 2026 Lusoris
"""Regression tests for build defects fixed in September 2026, each failing on the old code.

- #41, #42: the build account is sealed by the shutdown command and nowhere earlier; the
  seal runs before the power-off and a failed seal stops it.
- #44: a preheated image that cannot be pulled fails the build; precache requires every
  image to be injected by the build with no fallback pins.
- Provisioners require their injected pins without shell defaults or default assignments.
- #40: the QEMU accelerator is a validated variable, and the release build emulates.
- #43: the compress step reads the directory Packer writes the flavor's image to.
- #39: the release build installs an ISO authoring tool before Packer writes the seed.

Whether a pinned image tag exists in its registry needs the registry and is not tested here.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Collection
from pathlib import Path

import pytest
import yaml

from tests.harness.live import skip_or_fail
from tests.harness.mock_runner import GIT_BASH, MockSandbox
from tests.test_apply_required_pins import GOLDEN, _apply_blocks
from tests.test_provisioners_execution import check_bash
from tests.test_version_pins_consumed import PIN_ENV_PATH, get_common_env_names, manifest_pin_values

ROOT = Path(__file__).resolve().parent.parent
PACKER = ROOT / "packer"
PROVISIONERS = PACKER / "provisioners"
PRECACHE = PROVISIONERS / "55-k8s-precache.sh"
RELEASE = ROOT / ".github" / "workflows" / "release-build.yml"
BUILD_PASSWORD = "build-pass"
COMMAND_TIMEOUT_S = 60
SEALED = ["sudo", "rm -f /etc/sudoers.d/90-cloud-init-users", "passwd -l ubuntu", "shutdown -P now"]
EARLY_SEAL = re.compile(r"passwd\s+(-l|--lock)|usermod\s+(-L|--lock)|90-cloud-init-users")
ISO_AUTHORS = {"xorriso", "genisoimage", "mkisofs"}


@pytest.fixture
def require_bash() -> None:
    check_bash(GIT_BASH)


def qemu_source() -> str:
    text = (PACKER / "sources.pkr.hcl").read_text(encoding="utf-8")
    match = re.search(r'^source "qemu" "image" \{\n(.*?)^\}', text, re.S | re.M)
    assert match, 'packer/sources.pkr.hcl has no source "qemu" "image" block'
    return match[1]


def hcl_attribute(block: str, name: str) -> str:
    match = re.search(rf"^\s*{name}\s*=\s*(.+?)\s*$", block, re.M)
    assert match, f"no {name} attribute"
    return match[1]


def variable_default(name: str) -> str:
    text = (PACKER / "variables.pkr.hcl").read_text(encoding="utf-8")
    match = re.search(rf'^variable "{name}" \{{\n(.*?)^\}}', text, re.S | re.M)
    assert match, f"variable {name} is not declared"
    return json.loads(hcl_attribute(match[1], "default"))


def build_steps() -> list[dict]:
    with RELEASE.open(encoding="utf-8") as handle:
        workflow = yaml.safe_load(handle)
    return workflow["jobs"]["build-matrix"]["steps"]


def step_running(steps: list[dict], needle: str) -> tuple[int, dict]:
    found = [(i, s) for i, s in enumerate(steps) if needle in s.get("run", "")]
    assert len(found) == 1, f"{len(found)} build-matrix steps run {needle!r}"
    return found[0]


# --- #41, #42: the build account is sealed last ---------------------------------------


def write_stub(directory: Path, name: str, body: str) -> None:
    stub = directory / name
    stub.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    stub.chmod(0o700)


def run_shutdown_command(tmp_path: Path, fail: str = "") -> tuple[int, list[str]]:
    """Run the builder's shutdown command through bash with sudo and the seal steps stubbed."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    write_stub(
        bin_dir,
        "sudo",
        '[ "$1" = "-S" ] || exit 2\nshift\nread -r password\n'
        '[ "$password" = "$BUILD_PASSWORD" ] || exit 1\necho sudo >> "$LOG"\nexec "$@"\n',
    )
    for name in ("rm", "passwd", "shutdown"):
        write_stub(bin_dir, name, f'echo "{name} $*" >> "$LOG"\ncase " $FAIL " in *" {name} "*) exit 1 ;; esac\n')
    command = json.loads(hcl_attribute(qemu_source(), "shutdown_command"))
    command = command.replace("${var.ssh_password}", BUILD_PASSWORD)
    env = {
        "PATH": f"{bin_dir}{os.pathsep}/usr/bin:/bin",
        "LOG": str(log),
        "FAIL": fail,
        "BUILD_PASSWORD": BUILD_PASSWORD,
    }
    result = subprocess.run(
        [str(GIT_BASH), "-c", command], env=env, timeout=COMMAND_TIMEOUT_S, check=False, capture_output=True
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result.returncode, calls


def test_shutdown_command_seals_the_account_then_powers_off(tmp_path: Path, require_bash) -> None:
    status, calls = run_shutdown_command(tmp_path)
    assert status == 0
    assert calls == SEALED


@pytest.mark.parametrize("failing", ["rm", "passwd"])
def test_a_failed_seal_never_powers_off(tmp_path: Path, require_bash, failing: str) -> None:
    status, calls = run_shutdown_command(tmp_path, fail=failing)
    assert status != 0
    assert not any(call.startswith("shutdown") for call in calls), calls


def test_no_provisioner_seals_the_build_account_early() -> None:
    """Every provisioner runs before the shutdown command, and every one of them uses sudo."""
    offending = [
        f"{script.name}:{number}: {line.strip()}"
        for script in sorted(PROVISIONERS.glob("*.sh"))
        for number, line in enumerate(script.read_text(encoding="utf-8").splitlines(), 1)
        if not line.lstrip().startswith("#") and EARLY_SEAL.search(line)
    ]
    assert offending == []


# --- #44: a preheated image that cannot be pulled fails the build ------------------------


def precache_image_pins() -> dict[str, str]:
    return {name: value for name, value in manifest_pin_values().items() if name.startswith("IMG_")}


def run_precache(
    tmp_path: Path,
    profile: str,
    flavor: str,
    failing_image: str = "",
    extra_env: dict[str, str] | None = None,
):
    env = {
        **precache_image_pins(),
        "PREHEAT_PROFILE": profile,
        "FLAVOR": flavor,
        "MOCK_FAIL_IMAGE": failing_image,
    }
    if extra_env:
        env.update(extra_env)
    return MockSandbox(tmp_path).run_script(PRECACHE, env_vars=env)


def pulled(result) -> list[str]:
    return [c.split()[-1] for c in result.find_commands("ctr") if " images pull " in c]


def test_precache_pulls_every_image_of_the_profile(tmp_path: Path, require_bash) -> None:
    pins = precache_image_pins()
    result = run_precache(tmp_path, "flannel", "k8s-node-amd")
    assert result.returncode == 0, result.stderr
    assert pulled(result) == [
        pins["IMG_PAUSE"],
        pins["IMG_COREDNS"],
        pins["IMG_FLANNEL"],
        pins["IMG_FLANNEL_CNI"],
        pins["IMG_KUBE_VIP"],
        pins["IMG_NODE_EXPORTER"],
        pins["IMG_AMD_PLUGIN"],
    ]


def test_lean_profile_pulls_only_the_pause_image(tmp_path: Path, require_bash) -> None:
    result = run_precache(tmp_path, "lean", "k8s-node-generic")
    assert result.returncode == 0, result.stderr
    assert pulled(result) == [precache_image_pins()["IMG_PAUSE"]]


@pytest.mark.parametrize(
    ("profile", "flavor", "image"),
    [
        ("lean", "k8s-node-generic", precache_image_pins()["IMG_PAUSE"]),
        ("flannel", "k8s-node-flannel", precache_image_pins()["IMG_FLANNEL"]),
        ("cilium", "k8s-node-cilium", precache_image_pins()["IMG_CILIUM_OPERATOR"]),
        ("lean", "k8s-node-amd", precache_image_pins()["IMG_AMD_PLUGIN"]),
        ("lean", "k8s-node-nvidia", precache_image_pins()["IMG_NVIDIA_PLUGIN"]),
    ],
)
def test_precache_fails_when_an_image_cannot_be_pulled(
    tmp_path: Path, require_bash, profile: str, flavor: str, image: str
) -> None:
    result = run_precache(tmp_path, profile, flavor, failing_image=image)
    assert result.returncode != 0, f"{flavor} built without {image}"
    assert pulled(result)[-1] == image
    assert "Complete" not in result.stdout


_SHELL_NAME = r"[A-Za-z_][A-Za-z0-9_]*"
_PIN_DEFAULT = re.compile(rf"\$\{{({_SHELL_NAME}):?[-=]")
_ALIAS_ASSIGNMENT = re.compile(
    rf'(?:^|[\s;|&()])(?P<target>{_SHELL_NAME})=(?P<quote>"?)'
    rf"\$(?:\{{(?P<braced>{_SHELL_NAME})\}}|(?P<bare>{_SHELL_NAME}))"
    r"(?P=quote)(?=$|[\s;|&()<>])"
)


def _pins_and_aliases(content: str, pins: Collection[str]) -> set[str]:
    code = "".join(line for line in content.splitlines(keepends=True) if not line.lstrip().startswith("#"))
    assignments = [(match["target"], match["bare"] or match["braced"]) for match in _ALIAS_ASSIGNMENT.finditer(code)]
    names = set(pins)
    for _ in assignments:
        aliases = {target for target, source in assignments if source in names} - names
        if not aliases:
            break
        names.update(aliases)
    return names


def _pin_fallbacks(provisioners: Path, pins: Collection[str]) -> list[str]:
    findings = []
    for script in sorted(provisioners.rglob("*")):
        if script.is_symlink() or not script.is_file():
            continue
        content = script.read_text(encoding="utf-8", errors="replace")
        names = _pins_and_aliases(content, pins)
        findings.extend(
            f"{script.relative_to(provisioners).as_posix()}:{number}: {line.strip()}"
            for number, line in enumerate(content.splitlines(), 1)
            if any(match[1] in names for match in _PIN_DEFAULT.finditer(line))
        )
    return findings


def test_provisioners_hold_no_direct_pin_fallbacks(tmp_path: Path) -> None:
    precache = tmp_path / PRECACHE.name
    precache.write_text('echo "${IMG_PIN:-value}"\n', encoding="utf-8")
    script = tmp_path / "52-k3s-runtime.sh"
    cases = [
        'echo "${PIN:-value}"',
        'echo "${PIN-value}"',
        'echo "${PIN:=value}"',
        'echo "${PIN=value}"',
        'echo "${PIN:?msg}"',
        'echo "${PIN}"',
        'echo "${K3S_ROLE:-agent}"',
    ]
    script.write_text("\n".join(cases), encoding="utf-8")
    assert _pin_fallbacks(tmp_path, {"PIN", "IMG_PIN"}) == [
        *(f"{script.name}:{i}: {line}" for i, line in enumerate(cases[:4], 1)),
        f'{precache.name}:1: echo "${{IMG_PIN:-value}}"',
    ]


@pytest.mark.parametrize(
    ("path", "assignment", "fallback", "refused"),
    [
        pytest.param("helper", "", 'echo "${PIN:-value}"', True, id="extensionless"),
        pytest.param("helper.bash", "", 'echo "${PIN:-value}"', True, id="bash-extension"),
        pytest.param("nested/helper.sh", "", 'echo "${PIN:-value}"', True, id="nested"),
        pytest.param("helper.sh", 'alias_pin="$PIN"; ', 'x="${alias_pin:-value}"', True, id="quoted-alias"),
        pytest.param("helper.sh", 'local a="${PIN}"\n', 'echo "${a:=value}"', True, id="local-alias"),
        pytest.param("helper.sh", "readonly a=$PIN\nexport b=$a\n", 'echo "${b-value}"', True, id="alias-chain"),
        pytest.param("helper.sh", 'declare a="${PIN}"\n', 'echo "${a=value}"', True, id="declare-alias"),
        pytest.param("helper.sh", 'x="$OTHER"; ', 'echo "${x:-value}"', False, id="non-pin-alias"),
        pytest.param("helper.sh", 'x="${PIN:?message}"\n', 'echo "${x}"', False, id="required-read"),
        pytest.param("helper.sh", '# a="$PIN"\n', 'echo "${a:-value}"', False, id="full-line-comment"),
        pytest.param("helper.sh", '  # a="$PIN"\n', 'echo "${a:-value}"', False, id="indented-comment"),
        pytest.param("helper.sh", 'a="$PIN" # note\n', 'echo "${a:-value}"', True, id="inline-comment"),
        pytest.param("helper.sh", "#!/usr/bin/env bash\n", 'echo "${a:-value}"', False, id="shebang"),
    ],
)
def test_provisioners_hold_no_pin_fallbacks(
    tmp_path: Path, path: str, assignment: str, fallback: str, refused: bool
) -> None:
    script = tmp_path / path
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text(assignment + fallback + "\n", encoding="utf-8")
    line = assignment.count("\n") + 1
    last_line = assignment.rpartition("\n")[2] + fallback
    expected = [f"{path}:{line}: {last_line}"] if refused else []
    assert _pin_fallbacks(tmp_path, {"PIN"}) == expected


@pytest.mark.parametrize("entry", ["directory", "symlink"])
def test_pin_fallback_scan_skips_nonregular_entries(tmp_path: Path, entry: str) -> None:
    provisioners = tmp_path / "provisioners"
    provisioners.mkdir()
    path = provisioners / "helper.sh"
    if entry == "directory":
        path.mkdir()
    else:
        target = tmp_path / "outside.sh"
        target.write_text('echo "${PIN:-value}"\n', encoding="utf-8")
        try:
            path.symlink_to(target)
        except (NotImplementedError, OSError) as error:
            pytest.skip(f"Cannot create fixture symlink: {error}")
    assert _pin_fallbacks(provisioners, {"PIN"}) == []


def test_real_provisioners_hold_no_pin_fallbacks() -> None:
    fallbacks = _pin_fallbacks(PROVISIONERS, set(get_common_env_names()))
    assert not fallbacks, "Provisioner pin fallbacks:\n" + "\n".join(fallbacks)


def packer_common_env(tmp_path: Path, manifest: dict) -> subprocess.CompletedProcess[str]:
    packer = shutil.which("packer")
    if not packer:
        skip_or_fail("packer is required to evaluate common_env", os.environ)
    template = tmp_path / "packer"
    template.mkdir()
    builds = (PACKER / "builds.pkr.hcl").read_text(encoding="utf-8")
    locals_blocks = re.findall(r"(?ms)^locals\s*\{\n.*?^\}", builds)
    assert locals_blocks, "packer/builds.pkr.hcl has no locals blocks"
    (template / "locals.pkr.hcl").write_text("\n\n".join(locals_blocks) + "\n", encoding="utf-8")
    (tmp_path / "versions.json").write_text(json.dumps(manifest), encoding="utf-8")
    shutil.copyfile(PIN_ENV_PATH, template / PIN_ENV_PATH.name)
    return subprocess.run(
        [packer, "console", str(template)],
        input="jsonencode(local.common_env)\n",
        text=True,
        capture_output=True,
        timeout=COMMAND_TIMEOUT_S,
        check=False,
    )


def test_packer_common_env_matches_manifest_pins(tmp_path: Path) -> None:
    manifest = json.loads((ROOT / "versions.json").read_text(encoding="utf-8"))
    result = packer_common_env(tmp_path, manifest)
    assert result.returncode == 0, result.stderr
    expected = sorted(f"{name}={value}" for name, value in manifest_pin_values().items())
    assert sorted(json.loads(result.stdout)) == expected


def test_packer_common_env_refuses_missing_manifest_pin(tmp_path: Path) -> None:
    manifest = json.loads((ROOT / "versions.json").read_text(encoding="utf-8"))
    del manifest["k3s"]["version"]
    result = packer_common_env(tmp_path, manifest)
    assert result.returncode != 0, result.stdout
    assert "common_env" in result.stdout + result.stderr


_HCL_OPAQUE = re.compile(r'"(?:\\[^\n]|[^"\\\n])*"|#[^\n]*|//[^\n]*|/\*.*?\*/|(?P<unreadable>"|/\*|<<)', re.S)
_COMMON_ENV = re.compile(r"(?<![\w.-])local\s*\.\s*common_env(?![\w-])")


def _hcl_layout(content: str) -> str:
    def mask(token: re.Match[str]) -> str:
        assert not token["unreadable"], f"unreadable HCL at offset {token.start()}: {token[0]!r}"
        return re.sub(r"[^\n]", " ", token[0])

    return _HCL_OPAQUE.sub(mask, content)


def _hcl_blocks(content: str, header: str) -> list[str]:
    depth = 0
    start = None
    blocks = []
    for brace in re.finditer(r"[{}]", _hcl_layout(content)):
        if brace[0] == "{":
            if depth == 0:
                line_start = content.rfind("\n", 0, brace.start()) + 1
                label = content[line_start : brace.start()].strip()
                start = brace.end() if re.fullmatch(header, label) else None
            depth += 1
        else:
            depth -= 1
            assert depth >= 0, f"unmatched HCL closing brace at offset {brace.start()}"
            if depth == 0 and start is not None:
                blocks.append(content[start : brace.start()])
    assert depth == 0, f"unclosed HCL block while reading {header}"
    return blocks


def _hcl_environment_expression(shell: str) -> str:
    layout = _hcl_layout(shell)
    assert (attribute := re.search(r"(?m)^[ \t]*environment_vars[ \t]*=[ \t]*", layout)), (
        "no environment_vars attribute"
    )
    expression = layout[attribute.end() :]
    depth = 0
    for token in re.finditer(r"[({\[)}\]\n]", expression):
        if token[0] in "([{":
            depth += 1
        elif token[0] in ")]}":
            depth -= 1
        elif depth == 0:
            return expression[: token.start()]
        assert depth >= 0, "unbalanced environment_vars expression"
    assert depth == 0, "unbalanced environment_vars expression"
    return expression


def _assert_build_common_env(content: str) -> set[str]:
    names = set()
    for build in _hcl_blocks(content, r"build"):
        name = json.loads(hcl_attribute(build, "name"))
        assert isinstance(name, str) and name and name not in names, f"invalid or duplicate build name: {name!r}"
        names.add(name)
        shells = _hcl_blocks(build, r'provisioner[ \t]+"shell"')
        assert shells, f"{name}: no shell provisioner"
        for index, shell in enumerate(shells, 1):
            try:
                assert _COMMON_ENV.search(_hcl_environment_expression(shell)), "environment_vars omits local.common_env"
            except AssertionError as error:
                raise AssertionError(f"{name}: shell provisioner {index}: {error}") from error
    return names


def test_every_packer_build_wires_common_env() -> None:
    actual = _assert_build_common_env((PACKER / "builds.pkr.hcl").read_text(encoding="utf-8"))
    expected = {block.flavor for block in _apply_blocks(GOLDEN.read_text(encoding="utf-8"))}
    assert len(expected) == 44
    assert actual == expected


@pytest.mark.parametrize(
    ("body", "diagnostic"),
    [
        pytest.param(
            'provisioner "shell" {\n    environment_vars = ["local.common_env"] # local.common_env\n  }',
            "planted: shell provisioner 1: environment_vars omits local.common_env",
            id="missing-common-env",
        ),
        pytest.param('provisioner "file" {}', "planted: no shell provisioner", id="no-shell"),
        pytest.param(
            'provisioner "shell" {\n    environment_vars = local.common_env',
            "unclosed HCL block",
            id="unclosed-block",
        ),
    ],
)
def test_build_common_env_refuses_bad_wiring(body: str, diagnostic: str) -> None:
    with pytest.raises(AssertionError, match=re.escape(diagnostic)):
        _assert_build_common_env(f'build {{\n  name = "planted"\n  {body}\n}}\n')


def test_every_image_read_by_precache_is_passed_by_build() -> None:
    script_vars = set(re.findall(r"\$\{?(IMG_[A-Z0-9_]+)", PRECACHE.read_text(encoding="utf-8")))
    passed_vars = set(precache_image_pins().keys())
    assert script_vars, "precache script reads no IMG_* variables"
    assert script_vars <= passed_vars, f"precache reads variables not passed by builds: {script_vars - passed_vars}"


def test_precache_with_unset_image_exits_nonzero_and_pulls_nothing(
    tmp_path: Path, require_bash, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("IMG_PAUSE", raising=False)
    env = {k: v for k, v in precache_image_pins().items() if k != "IMG_PAUSE"}
    env.update({"PREHEAT_PROFILE": "lean", "FLAVOR": "k8s-node-generic"})
    result = MockSandbox(tmp_path).run_script(PRECACHE, env_vars=env)
    assert result.returncode != 0
    assert "IMG_PAUSE" in result.stderr
    assert pulled(result) == []


# --- #40: the accelerator is a validated variable, and CI emulates -----------------------


def test_qemu_source_takes_the_accelerator_variable() -> None:
    assert hcl_attribute(qemu_source(), "accelerator") == "var.accelerator"
    assert variable_default("accelerator") == "kvm"


def test_release_build_emulates() -> None:
    _, step = step_running(build_steps(), "make build")
    assert step.get("env", {}).get("PKR_VAR_accelerator") == "tcg"


@pytest.mark.parametrize(("value", "accepted"), [("tcg", True), ("kvm", True), ("bogus", False), ("", False)])
def test_packer_validates_the_accelerator(value: str, accepted: bool) -> None:
    packer = shutil.which("packer")
    if not packer:
        skip_or_fail("packer is required to validate the accelerator variable", os.environ)
    result = subprocess.run(
        [packer, "validate", f"-var=accelerator={value}", "."],
        cwd=PACKER,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_S,
        check=False,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0 and "Unsupported Packer Core version" in output:
        skip_or_fail(f"installed packer does not satisfy required_version: {output.strip()}", os.environ)
    assert (result.returncode == 0) is accepted, output
    if not accepted:
        assert "accelerator must be one of" in output


# --- #43: the compress step reads the directory Packer writes ----------------------------


def test_compress_step_reads_the_flavor_output_directory() -> None:
    assert hcl_attribute(qemu_source(), "output_directory") == '"${var.output_dir}/${var.flavor}"'
    steps = build_steps()
    _, build = step_running(steps, "make build")
    assert "make build" in build["run"]
    assert build.get("env", {}).get("PKR_VAR_flavor") == "${{ matrix.flavor }}"
    _, compress = step_running(steps, "zstd ")
    script = compress["run"]
    flavor = compress.get("env", {}).get("FLAVOR")
    if flavor:
        script = script.replace("${FLAVOR}", flavor)
    expected = f'cd "packer/{variable_default("output_dir")}/${{{{ matrix.flavor }}}}"'
    assert script.lstrip().startswith(expected + "\n"), script


# --- #39: the seed ISO has an authoring tool ---------------------------------------------


def test_release_build_installs_an_iso_author_before_packer() -> None:
    assert "cd_files" in qemu_source()
    steps = build_steps()
    install_at, install = step_running(steps, "apt-get install")
    build_at, _ = step_running(steps, "make build")
    packages = set(install["run"].split("apt-get install", 1)[1].split())
    assert packages & ISO_AUTHORS, packages
    assert install_at < build_at
