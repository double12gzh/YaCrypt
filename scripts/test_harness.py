#!/usr/bin/env python3
"""Harness contract checks: toolchain parity, gate wiring, rule identity.

Every check below encodes one recorded failure mode from the weekly RSI review
(docs/harness/). The fixtures feed the old, broken shape and must be rejected;
the `Current*` cases assert the shipping checkout satisfies the same contract.

No network, no Cargo, no real keys: this suite only reads version-controlled text.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
WORKFLOWS = ROOT / ".github/workflows"

EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
FLOATING_CHANNELS = {"stable", "beta", "nightly"}

# 折叠 CI/local 漂移（H-01）：CI 曾经浮动到 Rust 1.99.0，而本机是 1.92.0，
# 新的 `clippy::unnecessary_sort_by` 只在 CI 触发，本地门禁全绿。
STEP_REF = re.compile(r"^[ \t]*uses:[ \t]*dtolnay/rust-toolchain@(\S+)[ \t]*$", re.MULTILINE)
STEP_START = re.compile(r"^[ \t]*-[ \t]", re.MULTILINE)
PIN_INPUT = re.compile(r"^[ \t]*toolchain:[ \t]*(.+?)[ \t]*$", re.MULTILINE)
WORKFLOW_PIN = re.compile(r"^[ \t]+RUST_TOOLCHAIN:[ \t]*[\"']?([^\"'\s]+)[\"']?[ \t]*$", re.MULTILINE)
UNRESOLVED_PIN = re.compile(r"\$\{\{\s*env\.([A-Za-z0-9_]+)\s*\}\}")


def toolchain_channel(text):
    """Return the `channel` declared under [toolchain], or None."""
    section = re.search(r"^\[toolchain\][ \t]*$", text, re.MULTILINE)
    if not section:
        return None
    for line in text[section.end():].splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            break
        match = re.match(r"^channel[ \t]*=[ \t]*[\"']?([^\"'\s#]+)[\"']?", stripped)
        if match:
            return match.group(1)
    return None


def crate_minimum_rust(text):
    """Return (major, minor) from Cargo.toml `rust-version`, or None."""
    match = re.search(r"^rust-version[ \t]*=[ \t]*[\"'](\d+)\.(\d+)", text, re.MULTILINE)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def toolchain_violations(channel, workflows, cargo_toml):
    """Reject floating channels, unpinned steps and CI/local version drift."""
    problems = []
    if channel is None:
        problems.append("rust-toolchain.toml: no [toolchain] channel declared")
        return problems
    if not EXACT_VERSION.match(channel):
        problems.append(
            f"rust-toolchain.toml: channel {channel!r} is not an exact version; "
            "a floating channel cannot prove CI parity")
    if workflows and not any("dtolnay/rust-toolchain" in text for text in workflows.values()):
        problems.append("no workflow installs a Rust toolchain; CI parity is unverifiable")
    for name, text in sorted(workflows.items()):
        workflow_pin = WORKFLOW_PIN.search(text)
        if workflow_pin and workflow_pin.group(1) != channel:
            problems.append(
                f"{name}: workflow env RUST_TOOLCHAIN={workflow_pin.group(1)!r} "
                f"differs from rust-toolchain.toml channel {channel!r}")
        for step in STEP_REF.finditer(text):
            ref = step.group(1)
            window = text[step.end():]
            boundary = STEP_START.search(window)
            window = window[:boundary.start()] if boundary else window
            pin = PIN_INPUT.search(window)
            if ref in FLOATING_CHANNELS:
                problems.append(
                    f"{name}: `dtolnay/rust-toolchain@{ref}` is a floating channel; "
                    f"pin an exact version equal to {channel!r}")
                continue
            if ref != "master" and pin:
                problems.append(
                    f"{name}: `dtolnay/rust-toolchain@{ref}` ignores a `toolchain:` input; "
                    "use @master with an explicit version")
                continue
            if not pin:
                problems.append(f"{name}: toolchain step does not declare `toolchain:`")
                continue
            value = pin.group(1).strip("'\"")
            unresolved = UNRESOLVED_PIN.search(value)
            if unresolved:
                key = unresolved.group(1)
                declared = re.search(
                    rf"^[ \t]+{key}:[ \t]*[\"']?([^\"'\s]+)[\"']?[ \t]*$", text, re.MULTILINE)
                if not declared:
                    problems.append(f"{name}: toolchain pins ${{{{ env.{key} }}}} but env.{key} is not declared")
                    continue
                value = declared.group(1)
            if value != channel:
                problems.append(
                    f"{name}: toolchain {value!r} differs from rust-toolchain.toml channel {channel!r}")
    minimum = crate_minimum_rust(cargo_toml)
    if minimum and EXACT_VERSION.match(channel):
        pinned = tuple(int(part) for part in channel.split(".")[:2])
        if pinned < minimum:
            problems.append(
                f"Cargo.toml rust-version {minimum[0]}.{minimum[1]} is newer than "
                f"the pinned toolchain {channel}")
    return problems


def clippy_msrv_violations(channel, clippy_toml):
    """Reject a clippy MSRV that drifts from the pinned toolchain (H-01)."""
    match = re.search(r"^msrv[ \t]*=[ \t]*[\"'](\d+)\.(\d+)", clippy_toml, re.MULTILINE)
    if not match or not EXACT_VERSION.match(channel or ""):
        return []
    pinned = tuple(int(part) for part in channel.split(".")[:2])
    declared = (int(match.group(1)), int(match.group(2)))
    if declared != pinned:
        return [f".clippy.toml msrv {declared[0]}.{declared[1]} differs from the pinned "
                f"toolchain {channel}: clippy would suggest APIs outside the gated version"]
    return []


def gate_violations(verify_text, available_scripts):
    """Reject a regression script that exists but never runs in the single entry."""
    invoked = set(re.findall(r"python3\s+scripts/(test_[A-Za-z0-9_]+\.py)", verify_text))
    problems = []
    for name in sorted(available_scripts):
        if name not in invoked:
            problems.append(
                f"scripts/{name} exists but scripts/verify.sh never runs it: "
                "an unwired regression cannot block anything")
    if not invoked:
        problems.append("scripts/verify.sh runs no Python regression at all")
    return problems


def agents_violations(text):
    """Reject section-number collisions/gaps and duplicate rule IDs."""
    human = text.split("\n# Multica Agent Runtime", 1)[0]
    problems = []

    top = [int(match.group(1)) for match in re.finditer(r"^##[ \t]+(\d+)\.[ \t]", human, re.MULTILINE)]
    for index, number in enumerate(top, start=1):
        if number != index:
            problems.append(f"AGENTS.md: top-level sections are not 1..N (found {top}); "
                            "parallel branches renumbering each other causes merge collisions")
            break
    subsections = {}
    for match in re.finditer(r"^###[ \t]+(\d+)\.(\d+)[ \t]", human, re.MULTILINE):
        subsections.setdefault(int(match.group(1)), []).append(int(match.group(2)))
    for parent, numbers in sorted(subsections.items()):
        if len(set(numbers)) != len(numbers):
            problems.append(f"AGENTS.md: duplicate subsection number under section {parent}: {numbers}")
        expected = list(range(1, len(numbers) + 1))
        if sorted(set(numbers)) != expected:
            problems.append(
                f"AGENTS.md: subsections under section {parent} are not contiguous "
                f"1..{len(numbers)}: {numbers}")
    rule_ids = re.findall(r"^\|[ \t]*`?(H-\d{2})`?[ \t]*\|", human, re.MULTILINE)
    if not rule_ids:
        problems.append("AGENTS.md: no H-xx rule IDs; rule identity must survive merging/renumbering")
    seen = set()
    for rule in rule_ids:
        if rule in seen:
            problems.append(f"AGENTS.md: duplicate rule ID {rule}")
        seen.add(rule)
    for match in re.finditer(r"\.agents/skills/([A-Za-z0-9_-]+)/SKILL\.md", human):
        skill = ROOT / ".agents/skills" / match.group(1) / "SKILL.md"
        if not skill.is_file():
            problems.append(f"AGENTS.md references missing skill {skill.relative_to(ROOT)}")
    return problems


def check_skill_violations(text):
    """Reject a gate checklist that drifts into a second, weaker gate entry."""
    problems = []
    if "scripts/verify.sh" not in text:
        problems.append(".agents/skills/check/SKILL.md must delegate to scripts/verify.sh")
    stray = re.search(r"\bcargo[ \t]+(test|clippy|fmt|build|deny)\b", text)
    if stray:
        problems.append(
            f".agents/skills/check/SKILL.md restates `cargo {stray.group(1)}`; "
            "a second command list drifts from the real gate")
    for state in ("PASS", "FAIL", "BLOCKED"):
        if state not in text:
            problems.append(f".agents/skills/check/SKILL.md does not define the {state} state")
    return problems


class ToolchainContractTests(unittest.TestCase):
    def test_current_checkout_is_pinned(self):
        channel = toolchain_channel((ROOT / "rust-toolchain.toml").read_text())
        workflows = {path.name: path.read_text() for path in WORKFLOWS.glob("*.yml")}
        problems = toolchain_violations(channel, workflows, (ROOT / "Cargo.toml").read_text())
        problems += clippy_msrv_violations(channel, (ROOT / ".clippy.toml").read_text())
        self.assertEqual(problems, [], "\n".join(problems))
        self.assertIsNotNone(channel)

    def test_clippy_msrv_drift_is_rejected(self):
        problems = clippy_msrv_violations("1.92.0", 'msrv = "1.80"\n')
        self.assertTrue(any("differs from the pinned toolchain" in problem for problem in problems), problems)
        self.assertEqual(clippy_msrv_violations("1.92.0", 'msrv = "1.92"\n'), [])

    def test_floating_workflow_channel_is_rejected(self):
        # The shape that broke PR #3: CI floats, the lockfile pin is local-only.
        legacy = (
            "name: ci\nenv:\n  CARGO_TERM_COLOR: always\n"
            "jobs:\n  check:\n    steps:\n"
            "      - name: Install Rust toolchain\n"
            "        uses: dtolnay/rust-toolchain@stable\n"
            "        with:\n          components: clippy, rustfmt\n")
        problems = toolchain_violations("1.92.0", {"cicd.yml": legacy}, '')
        self.assertTrue(any("floating channel" in problem for problem in problems), problems)
        # A pin that lags the declared file is the same drift in the other direction.
        stale = legacy.replace("@stable", "@master").replace(
            "components: clippy, rustfmt", 'toolchain: "1.99.0"')
        problems = toolchain_violations("1.92.0", {"cicd.yml": stale}, '')
        self.assertTrue(any("differs from rust-toolchain.toml" in problem for problem in problems), problems)
        # And an unpinned step is drift waiting to happen.
        unpinned = legacy.replace("@stable", "@master")
        problems = toolchain_violations("1.92.0", {"cicd.yml": unpinned}, '')
        self.assertTrue(any("does not declare" in problem for problem in problems), problems)

    def test_floating_toolchain_file_is_rejected(self):
        problems = toolchain_violations("stable", {}, '')
        self.assertTrue(any("not an exact version" in problem for problem in problems), problems)
        self.assertTrue(any("no [toolchain] channel" in problem for problem in toolchain_violations(None, {}, '')))

    def test_release_test_drift_is_rejected(self):
        problems = toolchain_violations("1.90.0", {}, 'rust-version = "1.92"\n')
        self.assertTrue(any("newer than" in problem for problem in problems), problems)


class GateWiringTests(unittest.TestCase):
    def test_every_test_script_is_wired_into_the_gate(self):
        problems = gate_violations(
            (SCRIPTS / "verify.sh").read_text(),
            {path.name for path in SCRIPTS.glob("test_*.py")})
        self.assertEqual(problems, [], "\n".join(problems))

    def test_unwired_regression_is_rejected(self):
        verify = "run python3 scripts/test_verify.py\n"
        problems = gate_violations(verify, {"test_verify.py", "test_harness.py"})
        self.assertTrue(any("test_harness.py" in problem for problem in problems), problems)


class AgentsDocTests(unittest.TestCase):
    def test_shipping_agents_md_has_stable_identity(self):
        problems = agents_violations((ROOT / "AGENTS.md").read_text())
        self.assertEqual(problems, [], "\n".join(problems))

    def test_duplicate_or_gapped_sections_are_rejected(self):
        duplicate = "## 1. A\n### 1.7 X\n### 1.7 Y\n| H-01 | rule |\n"
        problems = agents_violations(duplicate)
        self.assertTrue(any("duplicate subsection" in problem for problem in problems), problems)
        gap = "## 1. A\n### 1.7 X\n### 1.9 Y\n| H-01 | rule |\n"
        problems = agents_violations(gap)
        self.assertTrue(any("not contiguous" in problem for problem in problems), problems)

    def test_duplicate_rule_id_is_rejected(self):
        text = "## 1. A\n### 1.7 X\n| H-01 | first |\n| H-01 | second |\n"
        problems = agents_violations(text)
        self.assertTrue(any("duplicate rule ID H-01" in problem for problem in problems), problems)

    def test_missing_skill_reference_is_rejected(self):
        text = "## 1. A\n### 1.7 X\n| H-01 | rule |\n见 `.agents/skills/nope/SKILL.md`。\n"
        problems = agents_violations(text)
        self.assertTrue(any("missing skill" in problem for problem in problems), problems)


class CheckSkillTests(unittest.TestCase):
    def test_tracked_skill_documents_one_gate_and_three_states(self):
        problems = check_skill_violations((ROOT / ".agents/skills/check/SKILL.md").read_text())
        self.assertEqual(problems, [], "\n".join(problems))

    def test_private_gate_command_list_is_rejected(self):
        weaker = "# Gate\nRun `cargo clippy --all-targets -- -D warnings`\nThen `cargo test`\n"
        problems = check_skill_violations(weaker)
        self.assertTrue(any("drifts from the real gate" in problem for problem in problems), problems)
        self.assertTrue(any("does not define" in problem for problem in problems), problems)


if __name__ == "__main__":
    unittest.main(verbosity=2)
