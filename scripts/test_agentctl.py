#!/usr/bin/env python3
"""Real Git/SQLite tests with isolated fixtures; no model or network calls."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from agentctl import Error, Ledger, git

SCRIPT = Path(__file__).with_name('agentctl.py')


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='yacrypt-ledger-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'repo with spaces'
        self.root.mkdir()
        home = Path(self.tmp.name) / 'home'; home.mkdir()
        env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        env.update(HOME=str(home), GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
        self.envpatch = patch.dict(os.environ, env, clear=True)
        self.envpatch.start(); self.addCleanup(self.envpatch.stop)
        git(self.root, 'init', '-b', 'main')
        git(self.root, 'config', 'user.name', 'Fixture')
        git(self.root, 'config', 'user.email', 'fixture@example.invalid')
        git(self.root, 'config', 'core.hooksPath', os.devnull)
        (self.root / '.gitignore').write_text('.worktrees/\n')
        (self.root / 'docs').mkdir()
        (self.root / 'docs/start.md').write_text('base\n')
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-m', 'fixture')
        self.ledger = Ledger(self.root, initialize=True)
        self.addCleanup(self.ledger.db.close)
        self.report = Path(self.tmp.name) / 'report.txt'
        self.report.write_text('Checked the change and its acceptance criteria.\n')

    def add(self, name='one', **extra):
        spec = dict(id=name, goal='Write a useful doc', source='test', non_goals='No product changes',
                    acceptance=['Doc exists'], allowed_paths=['docs/'])
        spec.update(extra)
        return self.ledger.add(spec)

    def claim(self, name='one'):
        return self.ledger.claim(name, 'author', 'codex', 'main', 3600)

    def commit(self, task, path='docs/result.md', content='result\n'):
        wt = Path(task['worktree'])
        p = wt / path; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(content)
        git(wt, 'add', path); git(wt, 'commit', '-m', 'fixture change')
        return git(wt, 'rev-parse', 'HEAD')

    def approved(self, name='one'):
        self.add(name); task = self.claim(name); head = self.commit(task)
        self.ledger.submit(name, task['token'], head, self.report)
        self.ledger.review(name, 'reviewer', head, 'PASS', self.report)
        return task, head

    def cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), '--repo', str(self.root), *args],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_state_and_evidence_survive_new_process(self):
        task, head = self.approved()
        self.report.write_text('changed after submission')
        result = self.cli('show', 'one')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data['head'], head)
        self.assertEqual(data['state'], 'approved')
        self.assertNotIn('changed after', data['submission']['text'])
        self.assertNotIn('token', data)
        self.assertEqual([e['kind'] for e in data['events']],
                         ['added', 'claim_reserved', 'claimed', 'submitted', 'reviewed'])
        linked = Ledger(task['worktree'])
        self.addCleanup(linked.db.close)
        self.assertEqual(linked.dbpath, self.ledger.dbpath)

    def test_concurrent_claim_has_one_winner(self):
        self.add()
        args = [sys.executable, str(SCRIPT), '--repo', str(self.root), 'claim', 'one',
                '--owner', 'author', '--harness', 'pi']
        processes = [subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                     for _ in range(2)]
        for p in processes:
            p.communicate(timeout=20)
        self.assertEqual(sorted(p.returncode for p in processes), [0, 1])
        self.assertEqual(self.ledger.task('one')['attempt'], 1)

    def test_expiry_requires_stopped_recovery_and_fences_old_token(self):
        self.add(); old = self.claim()
        (Path(old['worktree']) / 'docs/draft.md').write_text('preserve me')
        with patch('agentctl.time.time', return_value=old['expires'] + 1):
            with self.assertRaisesRegex(Error, 'Lease expired'):
                self.ledger.renew('one', old['token'], 3600)
            with self.assertRaises(Error): self.claim()
        with self.assertRaises(Error): self.ledger.recover('one', False, 'not stopped')
        self.ledger.recover('one', True, 'old session stopped')
        new = self.claim()
        self.assertEqual(new['attempt'], 2)
        self.assertNotEqual(new['worktree'], old['worktree'])
        self.assertEqual((Path(old['worktree']) / 'docs/draft.md').read_text(), 'preserve me')
        with self.assertRaisesRegex(Error, 'Stale'):
            self.ledger.submit('one', old['token'], old['base'], self.report)

    def test_provisioning_failure_is_recoverable_and_preserves_reservation(self):
        self.add()
        real = git
        def broken(repo, *args):
            if args[:2] == ('worktree', 'add'): raise Error('injected provisioning interruption')
            return real(repo, *args)
        with patch('agentctl.git', side_effect=broken):
            with self.assertRaisesRegex(Error, 'injected'): self.claim()
        self.assertEqual(self.ledger.task('one')['state'], 'provisioning')
        self.ledger.recover('one', True, 'provisioning process exited')
        self.assertEqual(self.claim()['attempt'], 2)

    def test_scope_dirty_worktree_and_self_review_rejected(self):
        self.add(); task = self.claim(); head = self.commit(task, 'outside.md')
        with self.assertRaisesRegex(Error, 'Out-of-scope'):
            self.ledger.submit('one', task['token'], head, self.report)
        self.add('two'); other = self.claim('two'); head = self.commit(other)
        (Path(other['worktree']) / 'docs/dirty.md').write_text('dirty')
        with self.assertRaisesRegex(Error, 'dirty'):
            self.ledger.submit('two', other['token'], head, self.report)
        (Path(other['worktree']) / 'docs/dirty.md').unlink()
        self.ledger.submit('two', other['token'], head, self.report)
        with self.assertRaisesRegex(Error, 'Independent'):
            self.ledger.review('two', 'author', head, 'PASS', self.report)

    def test_new_commit_invalidates_approval_and_resubmit_clears_it(self):
        task, head = self.approved()
        newer = self.commit(task, content='new version')
        self.assertFalse(self.ledger.queue()[0]['eligible'])
        with self.assertRaises(Error): self.ledger.reserve('one', 'main', 'integrator')
        self.ledger.submit('one', task['token'], newer, self.report)
        self.assertNotIn('review', self.ledger.task('one'))
        with self.assertRaisesRegex(Error, 'stale'):
            self.ledger.review('one', 'reviewer', head, 'PASS', self.report)
        self.ledger.review('one', 'reviewer', newer, 'PASS', self.report)
        self.assertTrue(self.ledger.queue()[0]['eligible'])

    def test_integration_serializes_and_requires_exact_target_and_gate(self):
        task, head = self.approved()
        slot = self.ledger.reserve('one', 'main', 'integrator')
        with self.assertRaisesRegex(Error, 'occupied'): self.ledger.reserve('one', 'main', 'other')
        with self.assertRaises(Error): self.ledger.recover('one', True, 'stop')
        gate = Path(self.tmp.name) / 'gate.json'
        gate.write_text(json.dumps(dict(head=head, command='bash scripts/verify.sh', exit_code=0, log='fixture', worktree=str(self.root))))
        with self.assertRaisesRegex(Error, 'target branch'): self.ledger.finish(slot['token'], head, gate)
        git(self.root, 'merge', '--ff-only', head)
        gate.write_text(json.dumps(dict(head=head, command='bash scripts/verify.sh', exit_code=1, log='fixture', worktree=str(self.root))))
        with self.assertRaisesRegex(Error, 'Gate evidence'): self.ledger.finish(slot['token'], head, gate)
        gate.write_text(json.dumps(dict(head=head, command='bash scripts/verify.sh', exit_code=0, log='fixture', worktree=str(self.root))))
        self.assertEqual(self.ledger.finish(slot['token'], head, gate)['state'], 'integrated')
        with self.assertRaises(Error): self.ledger.finish(slot['token'], head, gate)

    def test_dependencies_require_integrated_commit_in_base_and_attempt_budget(self):
        self.add(); self.add('two', depends_on=['one'])
        with self.assertRaisesRegex(Error, 'Dependency'): self.claim('two')
        task = self.claim()
        for n in (2, 3):
            self.ledger.recover('one', True, 'stopped')
            self.assertEqual(self.claim()['attempt'], n)
        self.ledger.recover('one', True, 'stopped')
        with self.assertRaisesRegex(Error, 'budget'): self.claim()

    def test_integration_release_survives_restart(self):
        task, head = self.approved()
        slot = self.ledger.reserve('one', 'main', 'integrator')
        with self.assertRaises(Error): self.ledger.release('bad token', 'no')
        result = self.cli('release', '--token', slot['token'], '--reason', 'operator stopped integration')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.ledger.reserve('one', 'main', 'next integrator')

    def test_leading_space_path_cannot_bypass_scope(self):
        self.add(); task = self.claim()
        head = self.commit(task, ' docs/result.md')
        with self.assertRaisesRegex(Error, 'Out-of-scope'):
            self.ledger.submit('one', task['token'], head, self.report)

    def test_project_dotfiles_are_valid_but_git_metadata_is_not(self):
        self.add(allowed_paths=['.github/', '.gitignore', '.githooks/'])
        with self.assertRaises(Error): self.add('two', allowed_paths=['.git/config'])

    def test_dirty_target_cannot_be_recorded_as_verified(self):
        task, head = self.approved()
        slot = self.ledger.reserve('one', 'main', 'integrator')
        git(self.root, 'merge', '--ff-only', head)
        (self.root / 'docs/result.md').write_text('uncommitted behavior')
        gate = Path(self.tmp.name) / 'gate.json'
        gate.write_text(json.dumps(dict(head=head, command='bash scripts/verify.sh', exit_code=0,
                                       log='fixture', worktree=str(self.root))))
        with self.assertRaisesRegex(Error, 'dirty'):
            self.ledger.finish(slot['token'], head, gate)
        self.assertEqual(self.ledger.task('one')['state'], 'approved')

    def test_invalid_spec_and_duplicate_do_not_change_state(self):
        with self.assertRaises(Error): self.add('../escape')
        with self.assertRaises(Error): self.add(allowed_paths=['../escape'])
        self.add()
        with self.assertRaisesRegex(Error, 'Duplicate'): self.add()
        self.assertEqual(self.ledger.task('one')['state'], 'ready')


if __name__ == '__main__':
    unittest.main(verbosity=2)
