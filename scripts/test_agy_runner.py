#!/usr/bin/env python3
import json
import os
from pathlib import Path
import signal
import sys
import unittest

import test_agentctl as fixtures
from agentctl import Error, git
from agy_runner import execute


class RunnerTests(unittest.TestCase):
    setUpFixture = fixtures.LedgerTests.setUp
    add = fixtures.LedgerTests.add
    commit = fixtures.LedgerTests.commit

    def setUp(self):
        self.setUpFixture()
        self.bin = Path(self.tmp.name) / 'bin'; self.bin.mkdir()
        script = self.bin / 'agy'
        script.write_text('#!' + sys.executable + '\n' + r'''
import json, os, subprocess, sys, time
from pathlib import Path
args = sys.argv[1:]
if args == ['models']:
    print('gemini-test-high\tGemini test')
    print('gemini-test-low\tGemini test')
    print('claude-test-medium\tClaude test')
    sys.exit(0)
if '--disable-slash-commands' in args:
    sys.exit('mode would be disabled')
settings = json.loads(args[args.index('--settings') + 1])
assert settings == {'permissions': {'allow': ['command(python3 scripts/test_agentctl.py)', 'command(python3 scripts/test_agy_runner.py)']}}
kind = os.environ.get('FAKE_AGY', 'success')
if kind == 'hang':
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    Path(os.environ['CHILD_PID']).write_text(str(child.pid))
    time.sleep(30)
if kind == 'bad':
    print('not-json'); sys.exit(0)
mode = args[args.index('--mode') + 1]
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
if mode == 'accept-edits':
    Path('docs/result.md').write_text('implemented by fake fixture\n')
    response = 'Implementation complete; fixture only'
else:
    if kind == 'mutate': Path('docs/result.md').write_text('changed during review')
    response = json.dumps(dict(head=head, verdict='PASS', findings=[], checks=['fixture']))
print(json.dumps(dict(status='SUCCESS', conversation_id='fake-conversation', response=response,
                     usage=dict(input_tokens=1, output_tokens=1))))
''')
        script.chmod(0o755)
        os.environ['PATH'] = str(self.bin) + os.pathsep + os.environ['PATH']
        os.environ.pop('FAKE_AGY', None)
        self.add()
        self.task = self.ledger.claim('one', 'author', 'agy', 'main', 3600)

    def run_author(self, seconds=10):
        return execute(self.ledger, 'one', 'execute', 'gemini-test-high', 'author', self.task['token'], seconds)

    def submit_author(self):
        record = self.run_author()
        wt = self.task['worktree']
        git(wt, 'add', 'docs/result.md'); git(wt, 'commit', '-m', 'fixture result')
        head = git(wt, 'rev-parse', 'HEAD')
        self.ledger.submit('one', self.task['token'], head, self.report)
        return record, head

    def test_real_process_and_different_model_review_receipts(self):
        author, head = self.submit_author()
        review = execute(self.ledger, 'one', 'review', 'claude-test-medium', 'reviewer', None, 10)
        self.assertEqual(author['state'], 'succeeded')
        self.assertEqual(review['state'], 'succeeded')
        self.assertEqual(review['review']['head'], head)
        self.assertEqual(review['requested_model'], 'claude-test-medium')
        self.assertEqual(review['conversation_id'], 'fake-conversation')
        self.assertNotIn('active_run', self.ledger.task('one'))
        self.assertEqual(self.ledger.task('one')['state'], 'review')  # no automatic approval
        self.assertTrue((Path(review['directory']) / 'receipt.json').exists())

    def test_arbitrary_review_cannot_bypass_receipt(self):
        author, head = self.submit_author()
        with self.assertRaisesRegex(Error, 'runtime evidence'):
            self.ledger.review('one', 'reviewer', head, 'PASS', self.report)
        receipt = execute(self.ledger, 'one', 'review', 'claude-test-medium', 'reviewer', None, 10)
        proof = Path(receipt['directory']) / 'response.txt'
        result = self.ledger.review('one', 'reviewer', head, 'PASS', proof)
        self.assertEqual(result['review']['run']['id'], receipt['id'])

    def test_submit_rejects_changes_after_model_execution(self):
        self.run_author()
        head = self.commit(self.task, content='coordinator silently changed result')
        with self.assertRaisesRegex(Error, 'snapshot'):
            self.ledger.submit('one', self.task['token'], head, self.report)

    def test_same_model_other_effort_is_not_cross_review(self):
        self.submit_author()
        with self.assertRaisesRegex(Error, 'different model'):
            execute(self.ledger, 'one', 'review', 'gemini-test-low', 'reviewer', None, 10)

    def test_unknown_model_and_short_lease_do_not_launch(self):
        with self.assertRaisesRegex(Error, 'catalog'):
            execute(self.ledger, 'one', 'execute', 'unknown', 'author', self.task['token'], 10)
        with self.ledger.transaction():
            task = self.ledger.task('one'); task['expires'] = 0
            self.ledger.save(task, 'fixture_expired')
        with self.assertRaisesRegex(Error, 'expired'): self.run_author()
        self.assertNotIn('runs', self.ledger.task('one'))

    def test_malformed_output_is_failed_and_kept(self):
        os.environ['FAKE_AGY'] = 'bad'
        record = self.run_author()
        self.assertEqual(record['state'], 'failed')
        self.assertEqual((Path(record['directory']) / 'stdout.json').read_text().strip(), 'not-json')
        self.assertNotIn('active_run', self.ledger.task('one'))

    def test_timeout_stops_process_group(self):
        os.environ['FAKE_AGY'] = 'hang'
        pidfile = Path(self.tmp.name) / 'child.pid'; os.environ['CHILD_PID'] = str(pidfile)
        record = self.run_author(1)
        self.assertEqual(record['state'], 'timed_out')
        self.assertNotIn('active_run', self.ledger.task('one'))
        # A just-killed orphan may briefly be a zombie; it must not still be running.
        import subprocess
        state = subprocess.run(['ps', '-o', 'stat=', '-p', pidfile.read_text()], text=True, capture_output=True).stdout.strip()
        self.assertTrue(not state or state.startswith('Z'), state)

    def test_review_mutation_fails_and_preserves_diff(self):
        self.submit_author(); os.environ['FAKE_AGY'] = 'mutate'
        record = execute(self.ledger, 'one', 'review', 'claude-test-medium', 'reviewer', None, 10)
        self.assertEqual(record['state'], 'failed')
        self.assertIn('dirty', record['error'])
        self.assertTrue(git(self.task['worktree'], 'status', '--porcelain'))

    def test_active_run_blocks_submit_and_requires_stopped_recovery(self):
        with self.ledger.transaction():
            task = self.ledger.task('one'); task['active_run'] = 'lost'
            task['runs'] = [{'id': 'lost', 'state': 'running'}]
            self.ledger.save(task, 'fixture_lost_supervisor')
        with self.assertRaisesRegex(Error, 'active run'):
            self.ledger.submit('one', self.task['token'], self.task['base'], self.report)
        with self.assertRaises(Error): self.ledger.recover('one', False, 'not stopped')
        self.ledger.recover('one', True, 'operator confirmed process group stopped')
        task = self.ledger.task('one')
        self.assertNotIn('active_run', task)
        self.assertEqual(task['runs'][0]['state'], 'abandoned')


if __name__ == '__main__':
    unittest.main(verbosity=2)
