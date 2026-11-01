#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_agentctl as fixtures
import test_runtime_adapters as adapters
from agentctl import Error, git
from evolution import Evolution
from test_evolution import POLICY
import quality_intake as quality


class QualityTests(unittest.TestCase):
    def setUp(self):
        fixtures.LedgerTests.setUp(self)
        (self.root/'src').mkdir()
        (self.root/'src/cli.rs').write_text('original fixture')
        (self.root/'scripts').mkdir()
        (self.root/'scripts/verify.sh').write_text('''#!/bin/sh
echo '>>> fixture gate'
if [ "$DIRTY_GATE" = 1 ]; then echo changed >> src/cli.rs; fi
if [ "$FAIL_GATE" = 1 ]; then echo 'test concrete_behavior ... FAILED'; exit 1; fi
if [ "$FAIL_GATE" = env ]; then echo 'cargo: command not found'; exit 127; fi
echo 'VERIFY PASS'
''')
        git(self.root,'add','.');git(self.root,'commit','-m','quality fixture')
        self.flow=Evolution(self.ledger)
        self.backlog=Path(self.tmp.name)/'backlog.json'
        self.spec=dict(title='Concrete UI regression',goal='Fix the demonstrated behavior and add a regression.',
                       allowed_paths=['src/cli.rs'],acceptance=['Original reproduction passes','Meaningful regression added'],
                       reproduction=['Inspect the deterministic fixture'],evidence='Reproduced by operator in isolated fixture')
        self.backlog.write_text(json.dumps(self.spec))

    def test_diagnostics_real_gate_exit_and_dedup_without_dispatch(self):
        passed=quality.diagnose(self.flow,self.root,30)
        self.assertEqual(passed['status'],'passed')
        with self.assertRaisesRegex(Error,'passing gate'):
            quality.propose(self.flow,self.root,passed['id'])
        with patch.dict(os.environ,{'FAIL_GATE':'1'}):
            first=quality.diagnose(self.flow,self.root,30)
            second=quality.diagnose(self.flow,self.root,30)
        self.assertEqual(first['status'],'failed');self.assertEqual(first['category'],'verification')
        self.assertEqual(first['fingerprint'],second['fingerprint'])
        one=quality.propose(self.flow,self.root,first['id'])
        self.assertEqual(one['id'],quality.propose(self.flow,self.root,second['id'])['id'])
        self.assertEqual(one['payload']['risk'],'report_only')
        self.assertEqual(self.ledger.db.execute('SELECT count(*) FROM tasks').fetchone()[0],0)
        with self.assertRaisesRegex(Error,'Report-only'):
            quality.approve(self.flow,self.root,one['id'],'operator','reviewed')

    def test_environment_dirty_gate_and_tampered_log_are_not_authorization(self):
        with patch.dict(os.environ,{'FAIL_GATE':'env'}):
            report=quality.diagnose(self.flow,self.root,30)
        proposal=quality.propose(self.flow,self.root,report['id'],self.backlog)
        self.assertEqual(proposal['payload']['risk'],'report_only')
        Path(report['log']).write_text('replaced')
        with self.assertRaisesRegex(Error,'log changed'):
            quality.propose(self.flow,self.root,report['id'],self.backlog)
        with patch.dict(os.environ,{'DIRTY_GATE':'1'}):
            changed=quality.diagnose(self.flow,self.root,30)
        self.assertEqual(changed['status'],'invalid')
        self.assertEqual(changed['category'],'source_changed')

    def test_pending_and_approved_backlog_real_runtime_cycle(self):
        proposal=quality.propose(self.flow,self.root,backlog=self.backlog)
        before=git(self.root,'rev-parse','HEAD')
        policy=dict(POLICY,author=dict(harness='pi',model='magpie/test-gemini'),reviewer=dict(harness='omp',model='magpie/test-claude'))
        with patch('evolution.snapshot_probe',return_value={'stable':True}),patch('evolution.execute') as run,patch('evolution.coauthor',return_value='Co-Authored-By: GPT <noreply@openai.com>'):
            self.assertEqual(self.flow.tick(self.root,policy)['state'],'idle');run.assert_not_called()
        with self.assertRaisesRegex(Error,'approver'):
            quality.approve(self.flow,self.root,proposal['id'],'','')
        quality.approve(self.flow,self.root,proposal['id'],'operator','approved exact regression scope')
        self.assertEqual(quality.propose(self.flow,self.root,backlog=self.backlog)['state'],'approved')
        with self.assertRaisesRegex(Error,'already approved'):
            quality.approve(self.flow,self.root,proposal['id'],'operator','repeat')
        adapters.AdapterTests.fake_tools(self)
        for name in ('pi','omp'):
            p=Path(self.tmp.name)/'bin'/name
            p.write_text(p.read_text().replace("Path('docs/result.md')","Path('src/cli.rs')"))
        with patch('evolution.snapshot_probe',return_value={'stable':True}),patch('evolution.coauthor',return_value='Co-Authored-By: GPT <noreply@openai.com>'):
            result=self.flow.tick(self.root,policy)
            self.assertEqual(result['state'],'complete',result)
            self.assertEqual(self.flow.tick(Path(result['integration']),policy)['state'],'idle')
        self.assertEqual(git(self.root,'rev-parse','HEAD'),before)
        lesson=(Path(result['integration'])/'LESSONS.md').read_text()
        self.assertIn('经显式批准',lesson);self.assertNotIn('探针 approved_backlog',lesson)

    def test_stale_approval_and_dispatch_fail_before_any_model(self):
        proposal=quality.propose(self.flow,self.root,backlog=self.backlog)
        quality.approve(self.flow,self.root,proposal['id'],'operator','reviewed')
        (self.root/'docs/start.md').write_text('new head')
        git(self.root,'add','.');git(self.root,'commit','-m','new baseline')
        with patch('evolution.snapshot_probe',return_value={'stable':True}),patch('evolution.execute') as run:
            result=self.flow.tick(self.root,POLICY)
            self.assertEqual(result['state'],'idle')
            self.assertEqual(result['stale_proposals'],[proposal['id']])
            run.assert_not_called()
        other=quality.propose(self.flow,self.root,backlog=self.backlog)
        self.assertNotEqual(other['id'],proposal['id'])
        (self.root/'docs/start.md').write_text('another head')
        git(self.root,'add','.');git(self.root,'commit','-m','another baseline')
        with self.assertRaisesRegex(Error,'stale'):
            quality.approve(self.flow,self.root,other['id'],'operator','reviewed')

    def test_sensitive_traversal_directory_and_symlink_paths_are_report_only(self):
        for name in ['crates/yacrypt-core/src/crypto.rs','Cargo.toml','scripts/verify.sh','AGENTS.md','src','tests/../src/cli.rs','/tmp/x.rs']:
            with self.subTest(name=name):
                self.backlog.write_text(json.dumps(dict(self.spec,allowed_paths=[name])))
                proposal=quality.propose(self.flow,self.root,backlog=self.backlog)
                self.assertEqual(proposal['payload']['risk'],'report_only')
        (self.root/'tests').mkdir();(self.root/'tests/link.rs').symlink_to('../src/cli.rs')
        git(self.root,'add','.');git(self.root,'commit','-m','symlink fixture')
        self.assertFalse(quality.allowed_path(self.root,'tests/link.rs'))

    def test_mutated_candidate_cannot_expand_approved_scope(self):
        proposal=quality.propose(self.flow,self.root,backlog=self.backlog)
        quality.approve(self.flow,self.root,proposal['id'],'operator','reviewed')
        candidate=self.flow.candidates()[0];candidate['allowed_paths'].append('src/tui/app.rs')
        with self.assertRaisesRegex(Error,'approved scope'):
            quality.authorize_candidate(self.flow,self.root,candidate)

    def test_real_cli_failed_diagnosis_returns_json_and_nonzero(self):
        with patch.dict(os.environ,{'FAIL_GATE':'1'}):
            result=subprocess.run([sys.executable,str(Path(__file__).with_name('evolution.py')),'--repo',str(self.root),'diagnose','--seconds','30'],capture_output=True,text=True)
        self.assertEqual(result.returncode,1,result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'],'failed')


if __name__=='__main__':unittest.main(verbosity=2)
