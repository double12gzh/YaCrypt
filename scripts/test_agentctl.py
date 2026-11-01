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

    def test_review_verdicts_blocked_state_and_stopped_recovery(self):
        self.add()
        old = self.claim()
        head1 = self.commit(old, 'docs/result.md', 'draft 1\n')
        self.ledger.submit('one', old['token'], head1, self.report)
        with self.assertRaisesRegex(Error, 'Invalid review verdict'):
            self.ledger.review('one', 'reviewer', head1, 'UNKNOWN', self.report)

        issues_report = Path(self.tmp.name) / 'issues.txt'
        issues_report.write_text('Needs edge-case coverage before approval.\n')
        issues = self.ledger.review('one', 'reviewer', head1, 'ISSUES', issues_report)
        self.assertEqual(issues['state'], 'running')
        self.assertEqual(issues['review']['verdict'], 'ISSUES')
        self.assertEqual(issues['review']['evidence']['text'], 'Needs edge-case coverage before approval.\n')
        self.assertEqual(self.ledger.renew('one', old['token'], 3600)['state'], 'running')

        head2 = self.commit(old, 'docs/result.md', 'draft 2\n')
        self.ledger.submit('one', old['token'], head2, self.report)
        blocked_report = Path(self.tmp.name) / 'blocked.txt'
        blocked_report.write_text('Blocked: requires coordinator recovery.\n')
        res = self.cli('review', 'one', '--reviewer', 'reviewer', '--head', head2,
                       '--verdict', 'BLOCKED', '--evidence', str(blocked_report))
        self.assertEqual(res.returncode, 0, res.stderr)
        blocked = json.loads(res.stdout)
        self.assertEqual(blocked['state'], 'blocked')
        self.assertEqual(blocked['review']['verdict'], 'BLOCKED')
        self.assertEqual(blocked['review']['head'], head2)
        self.assertEqual(blocked['review']['evidence']['text'], 'Blocked: requires coordinator recovery.\n')
        blocked_report.write_text('mutated after review\n')

        self.assertEqual(self.ledger.task('one')['state'], 'blocked')
        self.assertEqual(self.ledger.queue(), [])
        with self.assertRaisesRegex(Error, 'Only a running task can renew'):
            self.ledger.renew('one', old['token'], 3600)
        with self.assertRaisesRegex(Error, 'Task cannot submit'):
            self.ledger.submit('one', old['token'], head2, self.report)
        head3 = self.commit(old, 'docs/result.md', 'draft 3 while blocked\n')
        with self.assertRaisesRegex(Error, 'Task cannot submit'):
            self.ledger.submit('one', old['token'], head3, self.report)
        with self.assertRaisesRegex(Error, 'Handoff requires running task'):
            self.ledger.handoff('one')
        with self.assertRaisesRegex(Error, 'Approval stale or absent'):
            self.ledger.reserve('one', 'main', 'integrator')
        with self.assertRaisesRegex(Error, 'Task is not ready'):
            self.claim()
        with self.assertRaisesRegex(Error, 'Confirm old session stopped'):
            self.ledger.recover('one', False, 'still running')
        with self.assertRaisesRegex(Error, 'Confirm old session stopped'):
            self.ledger.recover('one', True, '   ')

        recovered = self.ledger.recover('one', True, 'old session stopped after blocker')
        self.assertEqual(recovered['state'], 'ready')
        for key in ('token', 'expires', 'head', 'submission', 'review', 'execution_run'):
            self.assertNotIn(key, self.ledger.task('one'))
        with self.assertRaisesRegex(Error, 'Stale or incorrect attempt token'):
            self.ledger.renew('one', old['token'], 3600)
        with self.assertRaisesRegex(Error, 'Stale or incorrect attempt token'):
            self.ledger.submit('one', old['token'], head3, self.report)

        new = self.claim()
        self.assertEqual(new['state'], 'running')
        self.assertEqual(new['attempt'], 2)
        self.assertNotEqual(new['token'], old['token'])
        self.assertNotEqual(new['worktree'], old['worktree'])
        self.assertTrue(Path(old['worktree']).exists())
        self.assertEqual(self.ledger.renew('one', new['token'], 3600)['attempt'], 2)

        head_new = self.commit(new, 'docs/result.md', 'clean attempt 2\n')
        self.ledger.submit('one', new['token'], head_new, self.report)
        approved = self.ledger.review('one', 'reviewer', head_new, 'PASS', self.report)
        self.assertEqual(approved['state'], 'approved')
        self.assertEqual(approved['review']['verdict'], 'PASS')
        self.assertTrue(self.ledger.queue()[0]['eligible'])

        shown = json.loads(self.cli('show', 'one').stdout)
        reviewed_events = [json.loads(e['body']) for e in shown['events'] if e['kind'] == 'reviewed']
        self.assertEqual([e['state'] for e in reviewed_events], ['running', 'blocked', 'approved'])
        self.assertEqual([e['review']['verdict'] for e in reviewed_events], ['ISSUES', 'BLOCKED', 'PASS'])
        self.assertEqual(reviewed_events[1]['review']['head'], head2)
        self.assertEqual(reviewed_events[1]['review']['evidence']['text'],
                         'Blocked: requires coordinator recovery.\n')

    def test_blocked_agy_task_rejects_execute_until_recovered(self):
        from agy_runner import execute
        bindir = Path(self.tmp.name) / 'bin'; bindir.mkdir()
        fake_agy = bindir / 'agy'
        fake_agy.write_text('#!' + sys.executable + '\n' + r'''
import json, subprocess, sys
from pathlib import Path
args = sys.argv[1:]
if args == ['models']:
    print('gemini-test-high\tGemini test')
    print('claude-test-medium\tClaude test')
    sys.exit(0)
mode = args[args.index('--mode') + 1]
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
if mode == 'accept-edits':
    Path('docs/result.md').write_text('implemented by fake agy\n')
    response = 'done'
else:
    response = json.dumps(dict(head=head, verdict='BLOCKED',
                               findings=['blocked on architecture decision'], checks=['unit']))
print(json.dumps(dict(status='SUCCESS', conversation_id='conv-1', response=response,
                     usage=dict(input_tokens=1, output_tokens=1))))
''')
        fake_agy.chmod(0o755)
        with patch.dict(os.environ, {'PATH': str(bindir) + os.pathsep + os.environ['PATH']}):
            self.add('agy-one')
            claim1 = self.ledger.claim('agy-one', 'author', 'agy', 'main', 3600)
            exec1 = execute(self.ledger, 'agy-one', 'execute', 'gemini-test-high', 'author', claim1['token'], 10)
            self.assertEqual(exec1['state'], 'succeeded')
            wt = claim1['worktree']
            git(wt, 'add', 'docs/result.md'); git(wt, 'commit', '-m', 'agy attempt 1')
            head1 = git(wt, 'rev-parse', 'HEAD')
            self.ledger.submit('agy-one', claim1['token'], head1, self.report)
            rev_run = execute(self.ledger, 'agy-one', 'review', 'claude-test-medium', 'reviewer', None, 10)
            self.assertEqual(rev_run['state'], 'succeeded')
            proof = Path(rev_run['directory']) / 'response.txt'
            reviewed = self.ledger.review('agy-one', 'reviewer', head1, 'BLOCKED', proof)
            self.assertEqual(reviewed['state'], 'blocked')

            with self.assertRaisesRegex(Error, 'Execution requires a running agy claim'):
                execute(self.ledger, 'agy-one', 'execute', 'gemini-test-high', 'author', claim1['token'], 10)
            with self.assertRaisesRegex(Error, 'Only a running task can renew'):
                self.ledger.renew('agy-one', claim1['token'], 3600)
            with self.assertRaisesRegex(Error, 'Task cannot submit'):
                self.ledger.submit('agy-one', claim1['token'], head1, self.report)

            self.ledger.recover('agy-one', True, 'stopped blocked agy attempt')
            claim2 = self.ledger.claim('agy-one', 'author', 'agy', 'main', 3600)
            self.assertEqual(claim2['attempt'], 2)
            self.assertNotEqual(claim2['token'], claim1['token'])
            with self.assertRaisesRegex(Error, 'Stale or incorrect attempt token'):
                execute(self.ledger, 'agy-one', 'execute', 'gemini-test-high', 'author', claim1['token'], 10)
            exec2 = execute(self.ledger, 'agy-one', 'execute', 'gemini-test-high', 'author', claim2['token'], 10)
            self.assertEqual(exec2['state'], 'succeeded')


if __name__ == '__main__':
    unittest.main(verbosity=2)
