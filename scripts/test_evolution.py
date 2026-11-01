#!/usr/bin/env python3
import json
import os
import test_runtime_adapters as adapters
from pathlib import Path
import unittest
from unittest.mock import patch

import test_agentctl as fixtures
from agentctl import Error, git
from evolution import Evolution, detect, validate_policy, KINDS

POLICY=dict(automatic_kinds=list(KINDS),author=dict(harness='pi',model='magpie/agentrouter/gpt-6.1-sol'),
            reviewer=dict(harness='omp',model='magpie/amd/DeepSeek-V4.1-Flash'),run_seconds=300,gate_seconds=600)


class EvolutionTests(unittest.TestCase):
    setUp=fixtures.LedgerTests.setUp

    def prepare(self):
        p=self.root/'docs/start.md';p.write_text('[missing](absent.md)\n')
        git(self.root,'add','.');git(self.root,'commit','-m','broken link fixture')
        return Evolution(self.ledger)

    def test_discovery_deduplicates_and_does_not_invent_tasks(self):
        flow=self.prepare()
        with patch('evolution.snapshot_probe',return_value={'stable':True}):
            self.assertEqual(len(flow.scan(self.root)),1)
            flow.scan(self.root);self.assertEqual(len(flow.candidates()),1)
            self.assertEqual(self.ledger.db.execute('SELECT count(*) FROM tasks').fetchone()[0],0)
            (self.root/'docs/absent.md').write_text('resolved\n')
            git(self.root,'add','.');git(self.root,'commit','-m','resolve link')
            flow.scan(self.root)
            self.assertEqual(flow.candidates()[0]['state'],'resolved')
            with patch('evolution.execute',side_effect=AssertionError('must not call models')):
                self.assertEqual(flow.tick(self.root,POLICY),dict(state='idle',agent_runs=0))

    def test_queued_failure_never_relaunches_on_repeat_scan(self):
        flow=self.prepare()
        with patch('evolution.snapshot_probe',return_value={'stable':True}),patch('evolution.execute',return_value={'state':'failed'}) as run:
            result=flow.tick(self.root,POLICY)
            self.assertEqual(result['state'],'failed')
            self.assertEqual(run.call_count,1)
            again=flow.tick(self.root,POLICY)
            self.assertEqual(again['state'],'idle')
            self.assertEqual(run.call_count,1)
        report=Path(result['integration'])/'docs/tasks'/(result['id']+'-retrospective.md')
        self.assertIn('未完成',report.read_text())
        self.assertFalse((Path(result['integration'])/'LESSONS.md').exists())

    def test_complete_cycle_writes_git_feedback_without_touching_main(self):
        flow=self.prepare()
        (self.root/'docs/exists.md').write_text('intended target')
        (self.root/'scripts').mkdir()
        (self.root/'scripts/verify.sh').write_text('#!/bin/sh\nexit 0\n')
        git(self.root,'add','.');git(self.root,'commit','-m','fixture gate')
        before=git(self.root,'rev-parse','HEAD')
        adapters.AdapterTests.fake_tools(self)
        policy=dict(POLICY,author=dict(harness='pi',model='magpie/test-gemini'),reviewer=dict(harness='omp',model='magpie/test-claude'))
        with patch('evolution.snapshot_probe',return_value={'stable':True}),patch.dict(os.environ,{'EV_DOC_FIX':'1'}),patch('evolution.coauthor',return_value='Co-Authored-By: GPT <noreply@openai.com>'):
            result=flow.tick(self.root,policy)
            self.assertEqual(result['state'],'complete',result)
            self.assertEqual(result['agent_runs'],2)
            self.assertEqual(flow.tick(Path(result['integration']),policy)['state'],'idle')
        self.assertEqual(git(self.root,'rev-parse','HEAD'),before)
        task=self.ledger.task(result['id'])
        self.assertEqual(task['state'],'integrated')
        self.assertNotEqual(task['integrated_target'],'main')
        target=Path(result['integration'])
        self.assertEqual(git(target,'status','--porcelain'),'')
        self.assertIn(result['id'],(target/'LESSONS.md').read_text())
        self.assertIn('未合并 main',(target/'docs/tasks'/(result['id']+'-retrospective.md')).read_text())

    def test_dirty_discovery_and_concurrent_cycle_are_rejected(self):
        flow=self.prepare()
        (self.root/'docs/start.md').write_text('dirty')
        with self.assertRaisesRegex(Error,'clean'):
            detect(self.root)
        with flow.lock():
            with self.assertRaisesRegex(Error,'active'):
                with Evolution(self.ledger).lock():pass

    def test_policy_rejects_unknown_actions_and_same_model_via_other_harness(self):
        validate_policy(POLICY)
        wrong=json.loads(json.dumps(POLICY));wrong['automatic_kinds'].append('upgrade_crypto')
        with self.assertRaises(Error):validate_policy(wrong)
        wrong=json.loads(json.dumps(POLICY));wrong['reviewer']['model']='another/route/gpt-6.1-sol'
        with self.assertRaisesRegex(Error,'different'):validate_policy(wrong)
        wrong=dict(POLICY,auto_push=True)
        with self.assertRaisesRegex(Error,'Unknown'):validate_policy(wrong)


if __name__=='__main__':unittest.main(verbosity=2)
