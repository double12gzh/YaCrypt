#!/usr/bin/env python3
"""Offline gate regression tests; fixtures never touch real keys or user hooks."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
REAL_CARGO = shutil.which("cargo")


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="yacrypt-verify-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo with spaces"
        (self.root / "scripts").mkdir(parents=True)
        shutil.copy(ROOT / "scripts/verify.sh", self.root / "scripts/verify.sh")
        # Avoid recursively running this suite in the fixture gate.
        (self.root / "scripts/test_verify.py").write_text("pass\n")
        (self.root / "scripts/test_agentctl.py").write_text("pass\n")
        (self.root / "scripts/test_agy_runner.py").write_text("pass\n")
        self.bin = Path(self.temp.name) / "bin"
        self.bin.mkdir()
        self.log = Path(self.temp.name) / "calls"
        # Hooks export repository-local GIT_* variables; user config can redirect hooks.
        # Keep Cargo/rustup locations while isolating Git config and HOME in the fixture.
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        home = Path(self.temp.name) / "home"
        home.mkdir()
        self.env.update(PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        HOME=str(home), GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                        CARGO_HOME=os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")),
                        RUSTUP_HOME=os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")),
                        VERIFY_CALLS=str(self.log), VERIFY_FAIL="",
                        CARGO_TARGET_DIR=str(self.root / "target"))
        self.env.pop("VERIFY_REAL_CARGO", None)
        (self.bin / "cargo").write_text(r'''#!/usr/bin/env bash
set -eu
printf '%s
' "$*" >> "$VERIFY_CALLS"
if [[ "$1" == "${VERIFY_FAIL:-}" ]]; then exit 23; fi
if [[ "$1" == test && -n "${VERIFY_REAL_CARGO:-}" ]]; then
    exec "$VERIFY_REAL_CARGO" "$@" --offline
fi
''')
        (self.bin / "cargo").chmod(0o755)

    def gate(self):
        return subprocess.run(["bash", str(self.root / "scripts/verify.sh")],
                              cwd=self.temp.name, env=self.env,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def test_failure_stops_later_stages(self):
        for stage in ("fmt", "clippy", "test", "build", "deny"):
            with self.subTest(stage=stage):
                self.log.unlink(missing_ok=True)
                self.env["VERIFY_FAIL"] = stage
                result = self.gate()
                self.assertEqual(result.returncode, 23, result.stdout)
                self.assertNotIn("VERIFY PASS", result.stdout)
                self.assertEqual(self.log.read_text().splitlines()[-1].split()[0], stage)

    def test_member_failure_is_not_hidden_by_root_package(self):
        self.assertIsNotNone(REAL_CARGO, "Cargo is required for the workspace behavior probe")
        (self.root / "src").mkdir()
        (self.root / "member/src").mkdir(parents=True)
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nmembers=["member"]\n[package]\nname="gate-root"\nversion="0.1.0"\nedition="2021"\n')
        (self.root / "member/Cargo.toml").write_text(
            '[package]\nname="gate-member"\nversion="0.1.0"\nedition="2021"\n')
        (self.root / "src/lib.rs").write_text("")
        member = self.root / "member/src/lib.rs"
        member.write_text('#[test] fn member_contract() { assert!(false, "member contract broken"); }\n')
        old = subprocess.run([REAL_CARGO, "test", "--offline"], cwd=self.root,
                             env=self.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(old.returncode, 0, old.stdout)
        self.env["VERIFY_REAL_CARGO"] = REAL_CARGO
        broken = self.gate()
        self.assertNotEqual(broken.returncode, 0, broken.stdout)
        self.assertIn("member contract broken", broken.stdout)
        self.assertIn("FAILED", broken.stdout)
        member.write_text('#[test] fn member_contract() { assert_eq!(2 + 2, 4); }\n')
        fixed = self.gate()
        self.assertEqual(fixed.returncode, 0, fixed.stdout)
        self.assertIn("VERIFY PASS", fixed.stdout)
        print("workspace probe: legacy root-only=0; broken member=FAIL; restored member=PASS")

    def test_full_entry_points_delegate(self):
        for path in (".githooks/pre-commit", ".pre-commit-config.yaml",
                     ".github/workflows/cicd.yml", ".agents/skills/check/SKILL.md",
                     ".agents/skills/release/SKILL.md", "Makefile"):
            with self.subTest(path=path):
                text = (ROOT / path).read_text()
                self.assertIn("scripts/verify.sh", text)
                if path != "Makefile":
                    self.assertNotIn("cargo test", text)
                    self.assertNotIn("cargo clippy", text)

    def test_outer_git_configuration_and_hook_environment_are_ignored(self):
        external_hooks = Path(self.temp.name) / "outside-hooks"
        external_hooks.mkdir()
        sentinel = external_hooks / "pre-commit"
        sentinel.write_text("user hook must survive\n")
        config = Path(self.temp.name) / "user.gitconfig"
        config.write_text(f'[core]\n hooksPath = "{external_hooks}"\n')
        outer = dict(os.environ, GIT_CONFIG_GLOBAL=str(config),
                     GIT_DIR=str(Path(self.temp.name) / "unrelated.git"),
                     GIT_INDEX_FILE=str(Path(self.temp.name) / "unrelated.index"))
        result = subprocess.run(
            ["python3", str(ROOT / "scripts/test_verify.py"),
             "VerificationTests.test_hook_in_linked_worktree_and_existing_hook_preserved"],
            env=outer, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(sentinel.read_text(), "user hook must survive\n")
        self.assertEqual(sorted(p.name for p in external_hooks.iterdir()), ["pre-commit"])

    def test_hook_in_linked_worktree_and_existing_hook_preserved(self):
        def git(*args, cwd=None):
            return subprocess.run(["git", *args], cwd=cwd or self.root, env=self.env,
                                  text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
        git("init")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-m", "fixture")
        linked = Path(self.temp.name) / "linked"
        git("worktree", "add", "-b", "fixture", str(linked))
        (linked / "scripts").mkdir()
        (linked / ".githooks").mkdir()
        shutil.copy(ROOT / "scripts/install-hook.sh", linked / "scripts/install-hook.sh")
        shutil.copy(ROOT / ".githooks/pre-commit", linked / ".githooks/pre-commit")
        (linked / "scripts/verify.sh").write_text('#!/usr/bin/env bash\nprintf "hook delegated\\n"\n')
        install = ["bash", str(linked / "scripts/install-hook.sh")]
        first = subprocess.run(install, cwd=self.temp.name, env=self.env, capture_output=True, text=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        hook = Path(git("rev-parse", "--git-path", "hooks/pre-commit", cwd=linked).stdout.strip())
        if not hook.is_absolute():
            hook = linked / hook
        self.assertTrue(hook.resolve().is_relative_to(Path(self.temp.name).resolve()))
        run = subprocess.run([str(hook)], cwd=linked, env=self.env, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("hook delegated", run.stdout)
        hook.chmod(0o644)
        second = subprocess.run(install, env=self.env, capture_output=True)
        self.assertEqual(second.returncode, 0)
        self.assertTrue(os.access(hook, os.X_OK))
        hook.write_text("#!/bin/sh\necho user-hook\n")
        refused = subprocess.run(install, env=self.env, capture_output=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("user-hook", hook.read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
