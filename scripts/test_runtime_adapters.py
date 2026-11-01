#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import io

import test_agentctl as fixtures
from agentctl import Error, git
from agy_runner import execute, model_key
from runtime_adapters import parse_events


class AdapterTests(unittest.TestCase):
    setUp = fixtures.LedgerTests.setUp
    add = fixtures.LedgerTests.add

    def fake_tools(self):
        bindir = Path(self.tmp.name) / 'bin'; bindir.mkdir()
        source = '#!' + sys.executable + '\n' + r'''
import json, sys, subprocess, os
from pathlib import Path
a=sys.argv[1:]
if '--list-models' in a:
    print('provider model context max-out thinking images\nmagpie test-gemini 1M 1K yes yes\nmagpie test-claude 1M 1K yes yes'); sys.exit(0)
if a[0]=='models':
    print(json.dumps({'models':[{'provider':'magpie','id':m} for m in ['test-gemini','test-claude']]})); sys.exit(0)
assert '--no-extensions' in a and '--no-context-files' in a and '--no-session' in a
model=a[a.index('--model')+1]
if '--provider' in a: provider=a[a.index('--provider')+1]
else: provider,model=model.split('/',1)
tools=a[a.index('--tools')+1]
if tools=='read,edit,write':
    if os.environ.get('EV_DOC_FIX'): Path('docs/start.md').write_text('[fixed](exists.md)\n')
    else: Path('docs/result.md').write_text('real fixture subprocess\n')
    answer='implemented'
else:
    assert tools=='read'
    head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    answer=json.dumps(dict(head=head,verdict='ISSUES' if os.environ.get('EV_REVIEW_ISSUES') else 'PASS',findings=['fixture issue'] if os.environ.get('EV_REVIEW_ISSUES') else [],checks=['fixture inspected']))
message=dict(role='assistant', provider=provider, model=model, stopReason='stop', content=[dict(type='text',text=answer)])
for e in [dict(type='session',id='fixture-session'),dict(type='message_end',message=message),dict(type='agent_end',messages=[message])]:print(json.dumps(e))
'''
        for tool in ('pi','omp'):
            p=bindir/tool;p.write_text(source);p.chmod(0o755)
        os.environ['PATH']=str(bindir)+os.pathsep+os.environ['PATH']

    def test_pi_execution_omp_review_bound_to_runtime(self):
        self.fake_tools(); self.add()
        claim=self.ledger.claim('one','author','pi','main',3600)
        author=execute(self.ledger,'one','execute','magpie/test-gemini','author',claim['token'],10)
        self.assertEqual(author['state'],'succeeded',author)
        wt=claim['worktree'];git(wt,'add','docs/result.md');git(wt,'commit','-m','fixture')
        head=git(wt,'rev-parse','HEAD');self.ledger.submit('one',claim['token'],head,self.report)
        with self.assertRaisesRegex(Error,'runtime evidence'):
            self.ledger.review('one','reviewer',head,'PASS',self.report)
        with self.assertRaisesRegex(Error,'different model'):
            execute(self.ledger,'one','review','magpie/test-gemini','reviewer',None,10,harness='omp')
        review=execute(self.ledger,'one','review','magpie/test-claude','reviewer',None,10,harness='omp')
        self.assertEqual(review['state'],'succeeded',review)
        self.assertEqual(review['harness'],'omp')
        approved=self.ledger.review('one','reviewer',head,'PASS',Path(review['directory'])/'response.txt')
        self.assertEqual(approved['state'],'approved')

    def test_event_parser_rejects_backend_mismatch_and_incomplete_turns(self):
        msg=dict(role='assistant',provider='magpie',model='group/gemini-3.8-flash',stopReason='stop',content=[dict(type='text',text='OK')])
        events=[dict(type='session',id='test'),dict(type='message_end',message=msg),dict(type='agent_end')]
        def parse():return parse_events('\n'.join(json.dumps(e) for e in events),'magpie/group/gemini-3.8-flash')
        self.assertEqual(parse()['response'],'OK')
        events.append(dict(type='agent_settled',aborted=False))
        self.assertEqual(parse()['response'],'OK')
        events[-1]['aborted']=True
        with self.assertRaisesRegex(ValueError,'terminal'):parse()
        events.pop()
        msg['responseModel']='deepseek-v4.1-flash'
        with self.assertRaisesRegex(ValueError,'contradicts'):parse()
        del msg['responseModel']
        for reason in ('error','aborted','length','toolUse'):
            msg['stopReason']=reason
            with self.assertRaises(ValueError):parse()
        msg['stopReason']='stop';events.pop()
        with self.assertRaisesRegex(ValueError,'terminal'):parse()

    def test_model_identity_ignores_harness_route_and_effort(self):
        self.assertEqual(model_key('magpie/group/Gemini-3.8-flash'),model_key('gemini-3.8-flash-high'))
        self.assertNotEqual(model_key('gemini-3.8-flash'),model_key('gpt-6.1-sol'))


class BootstrapTests(unittest.TestCase):
    def test_missing_waitid_reexecs_before_work_with_preserved_arguments(self):
        import agy_runner
        # Simulate an unsupported current executable; probe the real capable interpreter.
        executable=sys.executable
        with patch('agy_runner.supervisor_supported',return_value=False), patch('agy_runner.supervisor_candidates',return_value=[os.path.relpath(executable)]), patch('agy_runner.sys.executable','/unsupported/python3'), patch('agy_runner.sys.argv',['scripts/evolution.py','watch','--cycles','4']), patch.dict(os.environ,{'PATH':'/original/bin'}), patch('agy_runner.sys.stderr',new_callable=io.StringIO) as err, patch('agy_runner.os.execv',side_effect=RuntimeError('reexec')) as launch:
            with self.assertRaisesRegex(RuntimeError,'reexec'):
                agy_runner.ensure_supervisor_python()
            self.assertEqual(launch.call_args.args[1][1:], [str(Path('scripts/evolution.py').resolve()),'watch','--cycles','4'])
            self.assertEqual(os.environ['PATH'],str(Path(executable).parent)+os.pathsep+'/original/bin')
            self.assertIn('restarting',err.getvalue())

    def test_no_compatible_interpreter_fails_without_launch_or_path_change(self):
        import agy_runner
        with patch('agy_runner.supervisor_supported',return_value=False), patch('agy_runner.supervisor_candidates',return_value=[]), patch('agy_runner.os.execv') as launch, patch.dict(os.environ,{'PATH':'/original/bin'}):
            with self.assertRaisesRegex(Error,'No compatible local interpreter'):
                agy_runner.ensure_supervisor_python()
            launch.assert_not_called()
            self.assertEqual(os.environ['PATH'],'/original/bin')


if __name__=='__main__':unittest.main(verbosity=2)
