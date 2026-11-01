#!/usr/bin/env python3
"""Bounded, foreground maintenance cycles. Never merges or pushes main."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

from agentctl import Error, Ledger, git, require, ancestor
from agy_runner import execute, model_key, stop_group, wait_unreaped, worktree_digest

KINDS = ('snapshot_directory_replacement', 'broken_markdown_link')


def command(argv, cwd, log, seconds):
    """Run a fixed command without a shell; stop its group even on normal exit."""
    with Path(log).open('wb') as output:
        proc = subprocess.Popen(argv, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        try:
            wait_unreaped(proc, seconds)
        finally:
            stop_group(proc)
    return proc.returncode


def snapshot_probe(root):
    """Exercise the current checkout's digest against a real isolated Git index."""
    code = r'''
import json, os, sys, tempfile, subprocess
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from agy_runner import worktree_digest
with tempfile.TemporaryDirectory(prefix='yacrypt-snapshot-probe-') as d:
 p=Path(d)
 env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
 env.update(GIT_CONFIG_GLOBAL=os.devnull,GIT_CONFIG_NOSYSTEM='1')
 def git(*args):
  subprocess.run(['git','-c','core.hooksPath='+os.devnull,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid',*args],cwd=p,env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 git('init','-b','main');(p/'item').write_text('file');git('add','.');git('commit','-m','fixture')
 (p/'item').unlink();(p/'item').mkdir();(p/'item'/'child').write_text('replacement')
 before=worktree_digest(p);git('add','-A');git('commit','-m','directory')
 after=worktree_digest(p)
 print(json.dumps(dict(before=before,after=after,stable=before==after)))
'''
    with tempfile.TemporaryDirectory(prefix='yacrypt-probe-log-') as d:
        log=Path(d)/'probe.log'
        rc=command([sys.executable,'-c',code,str(Path(root)/'scripts')],root,log,30)
        require(rc==0, 'Snapshot probe failed to execute: '+log.read_text()[-1000:])
        result=json.loads(log.read_text())
        require(isinstance(result.get('stable'),bool),'Invalid snapshot probe result')
        return result


def detect(root):
    root=Path(root)
    require(not git(root,'status','--porcelain','--untracked-files=all'),'Discovery requires a clean checkout')
    head=git(root,'rev-parse','HEAD');found=[]
    probe=snapshot_probe(root)
    if not probe['stable']:
        found.append(dict(kind=KINDS[0],key=KINDS[0],path='scripts/agy_runner.py',head=head,
                          evidence=probe,
                          goal='Fix worktree_digest so replacing a tracked file with a directory has the same snapshot before and after commit. Preserve deletion, rename, symlink and coordinator-edit detection; add a meaningful regression.',
                          allowed_paths=['scripts/agy_runner.py','scripts/test_agy_runner.py','docs/subsystems/coordination.md']))
    for name in git(root,'ls-files','-z','*.md').split('\0'):
        if not name or '/evidence/' in name or not name.startswith('docs/'):
            continue
        path=root/name
        require(path.resolve().is_relative_to(root.resolve()),'Document path escapes checkout')
        body=re.sub(r'```.*?```','',path.read_text(encoding='utf-8'),flags=re.S)
        for target in sorted(set(re.findall(r'\]\(([^\s)]+)\)',body))):
            if re.match(r'^[a-zA-Z][\w+.-]*:',target) or target.startswith(('#','/','<')):
                continue
            local=target.split('#')[0]
            if not local or '%' in local or not (path.parent/local).resolve().is_relative_to(root.resolve()):
                continue
            if not (path.parent/local).exists():
                found.append(dict(kind=KINDS[1],key=KINDS[1]+':'+name+':'+target,path=name,head=head,
                                  evidence=dict(target=target),goal='Repair the broken local Markdown link '+target+' in '+name+'. Locate the intended tracked target; preserve the documentation meaning. Do not merely delete the explanatory content.',allowed_paths=[name]))
    return found


class Evolution:
    def __init__(self,ledger):
        self.ledger=ledger
        ledger.db.execute('CREATE TABLE IF NOT EXISTS candidates (key TEXT PRIMARY KEY, body TEXT NOT NULL)')
        self.directory=ledger.directory/'evolution';self.directory.mkdir(mode=0o700,exist_ok=True)

    @contextmanager
    def lock(self):
        with (self.directory/'cycle.lock').open('a') as lock:
            try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError: raise Error('Another evolution cycle is active')
            try: yield
            finally: fcntl.flock(lock,fcntl.LOCK_UN)

    def scan(self,root):
        found=detect(root)
        with self.ledger.transaction():
            for item in found:
                row=self.ledger.db.execute('SELECT body FROM candidates WHERE key=?',(item['key'],)).fetchone()
                old=json.loads(row[0]) if row else None
                # A queued attempt needs explicit reconciliation; never spend again on each scan.
                if old and old['state']=='queued':continue
                item.update(state='detected',generation=(old or {}).get('generation',1),seen=time.time())
                if old:
                    item.update({k:old[k] for k in ('previous_task','reconciled_reason') if k in old})
                if old and old['state']=='resolved':item['generation']=old['generation']+1
                self.ledger.db.execute('INSERT OR REPLACE INTO candidates VALUES (?,?)',(item['key'],json.dumps(item)))
            keys={x['key'] for x in found}
            for row in self.ledger.db.execute('SELECT body FROM candidates').fetchall():
                item=json.loads(row[0])
                can_resolve = item['state']=='detected'
                if item['state']=='queued' and item.get('task'):
                    row=self.ledger.db.execute('SELECT body FROM tasks WHERE id=?',(item['task'],)).fetchone()
                    task=json.loads(row[0]) if row else {}
                    can_resolve=task.get('state')=='integrated' and ancestor(root,task['integrated_head'],git(root,'rev-parse','HEAD'))
                if item['key'] not in keys and can_resolve:
                    item['state']='resolved'
                    self.ledger.db.execute('UPDATE candidates SET body=? WHERE key=?',(json.dumps(item),item['key']))
        return found

    def candidates(self):
        return [json.loads(r[0]) for r in self.ledger.db.execute('SELECT body FROM candidates ORDER BY key')]

    def reconcile(self, name, stopped, reason):
        require(stopped and reason.strip(), 'Confirm old processes stopped and provide a reason')
        with self.lock():
            matches=[c for c in self.candidates() if c.get('task')==name and c['state']=='queued']
            require(len(matches)==1, 'No queued candidate for this task')
            item=matches[0]
            row=self.ledger.db.execute('SELECT body FROM tasks WHERE id=?',(name,)).fetchone()
            if row:
                task=json.loads(row[0])
                require(task['state']!='integrated', 'Integrated task must be merged or inspected, not retried')
                if task['state']!='ready':self.ledger.recover(name,True,reason)
            with self.ledger.transaction():
                item.update(state='detected',generation=item['generation']+1,
                            previous_task=name,reconciled_reason=reason)
                item.pop('task',None)
                self.ledger.db.execute('UPDATE candidates SET body=? WHERE key=?',(json.dumps(item),item['key']))
            return item

    def tick(self,root,policy):
        validate_policy(policy)
        with self.lock():
            self.scan(root)
            choices=[c for c in self.candidates() if c['state']=='detected' and c['kind'] in policy['automatic_kinds']]
            if not choices:return {'state':'idle','agent_runs':0}
            require(not self.ledger.db.execute('SELECT 1 FROM integration').fetchone(), 'Integration slot occupied; do not spend model budget')
            candidate=choices[0]
            name='EV-'+hashlib.sha256((candidate['key']+':'+str(candidate['generation'])).encode()).hexdigest()[:12]
            directory=self.directory/name;directory.mkdir(mode=0o700)
            state=dict(id=name,state='starting',source=candidate,started=time.time(),policy=policy,
                       agent_runs=0,stages=[],pid=os.getpid())
            def save(stage,**fields):save_cycle(directory,state,stage,**fields)
            def gate(worktree,label):return full_gate(worktree,directory,label,policy)
            branch='codex/evolution-'+name
            integration=self.ledger.primary/'.worktrees'/('evolution-'+name)
            try:
                # Reserve discovery before creating worktrees/tasks. Crash gaps stay queued,
                # requiring inspection rather than silently spending again.
                spec=dict(id=name,source=json.dumps(candidate,ensure_ascii=False),goal=candidate['goal'],
                          non_goals='No credential access, cryptography/dependency changes, gate weakening, policy edits, Git operations or changes outside allowed_paths.',
                          acceptance=['Original discovery probe must pass; add a regression for a code fix.','Coordinator full verify gate passes.','Independent different-model review returns PASS for exact commit.'],
                          allowed_paths=candidate['allowed_paths'],max_attempts=1)
                with self.ledger.transaction():
                    candidate.update(state='queued',task=name)
                    self.ledger.db.execute('UPDATE candidates SET body=? WHERE key=?',(json.dumps(candidate),candidate['key']))
                self.ledger.add(spec)
                save('provisioning')
                git(root,'worktree','add','-b',branch,str(integration),candidate['head'])
                claim=self.ledger.claim(name,'evolution-author',policy['author']['harness'],candidate['head'],86400)
                # Never persist the claim token in public cycle reports.
                save('executing',worktree=claim['worktree'],integration=str(integration),branch=branch,agent_runs=1)
                run=execute(self.ledger,name,'execute',policy['author']['model'],'evolution-author',claim['token'],policy['run_seconds'],harness=policy['author']['harness'])
                require(run['state']=='succeeded','Author runtime failed; preserve draft and inspect receipt')
                save('validating',author_run=run['id'])
                wt=Path(claim['worktree'])
                paths=set(filter(None,git(wt,'diff','--name-only','-z','HEAD').split('\0')))|set(filter(None,git(wt,'ls-files','--others','--exclude-standard','-z').split('\0')))
                require(paths,'Author made no change')
                require(all(p in candidate['allowed_paths'] for p in paths),'Author changed paths outside the task')
                if candidate['kind']==KINDS[0]:require(snapshot_probe(wt)['stable'],'Original snapshot regression still fails')
                first_gate=gate(wt,'author-gate')
                git(wt,'add','--',*candidate['allowed_paths'])
                git(wt,'commit','-m','fix(agent): '+name+' '+candidate['kind'],'-m','Discovered from a reproducible probe. Full verify gate passed before commit. Runtime evidence retained by the coordinator.','-m',coauthor(policy['author']['model']))
                head=git(wt,'rev-parse','HEAD')
                if candidate['kind']==KINDS[1]:require(not any(c['key']==candidate['key'] for c in detect(wt)),'Broken link still present')
                report=directory/'submission.json';report.write_text(json.dumps(dict(head=head,run=run['id'],gate=first_gate)),encoding='utf-8')
                self.ledger.submit(name,claim['token'],head,report)
                notes=directory/'review-instructions.txt';notes.write_text('Coordinator verified full gate exit 0 and allowed paths. '+json.dumps(first_gate)+'\nReturn ONLY JSON. PASS requires findings: []. Inspect actual code using read; no shell tools are available. Do not claim you ran tests. Include inspection and this limitation in checks.',encoding='utf-8')
                save('reviewing',head=head,agent_runs=2)
                review=execute(self.ledger,name,'review',policy['reviewer']['model'],'evolution-reviewer',None,policy['run_seconds'],notes,policy['reviewer']['harness'])
                require(review['state']=='succeeded','Reviewer runtime or response failed')
                self.ledger.review(name,'evolution-reviewer',head,review['review']['verdict'],Path(review['directory'])/'response.txt')
                save('reviewed',review_run=review['id'],verdict=review['review']['verdict'])
                require(review['review']['verdict']=='PASS','Independent review did not pass; automatic retry disabled')
                return self.complete(state,directory,save,gate)
            except Exception as exc:
                save('failed',error=type(exc).__name__+': '+str(exc),finished=time.time())
                if integration.exists():self.writeback(integration,state,False)
                # Leave source, leases, integration slot and reports intact for explicit recovery.
                return state

    def complete(self,state,directory,save,gate):
        name=state['id'];branch='codex/evolution-'+name
        integration=self.ledger.primary/'.worktrees'/('evolution-'+name)
        task=self.ledger.task(name);head=task['head'];policy=state['policy']
        require(task['state']=='approved' and self.ledger.current_head(task)==head,'Need current independent approval before completion')
        require(git(integration,'symbolic-ref','--short','HEAD')==branch,'Wrong candidate branch')
        # A stopped cycle may have an untracked failure report. Preserve it before merge.
        report=integration/'docs/tasks'/(name+'-retrospective.md')
        if report.exists() and not git(integration,'ls-files','--',str(report.relative_to(integration))):
            data=report.read_bytes();backup=directory/('failed-retrospective-'+hashlib.sha256(data).hexdigest()+'.md')
            backup.write_bytes(data);report.unlink()
        require(not git(integration,'status','--porcelain','--untracked-files=all'),'Candidate checkout is dirty; inspect before resume')
        slot=self.ledger.reserve(name,branch,'evolution-integrator')
        save('integrating',head=head,error=None)
        git(integration,'merge','--ff-only',head)
        proof=gate(integration,'integration-gate')
        gate_path=directory/'integration-gate.json';gate_path.write_text(json.dumps(proof),encoding='utf-8')
        self.ledger.finish(slot['token'],head,gate_path)
        save('integrated',integrated_head=head)
        self.writeback(integration,state,True)
        gate(integration,'retrospective-gate')
        git(integration,'add','LESSONS.md','docs/tasks/'+name+'-retrospective.md')
        git(integration,'commit','-m','docs(agent): record '+name+' verified feedback','-m','Deterministically record discovery, execution, independent review and gate evidence as observations. Do not promote unverified suggestions to permanent standards.','-m',coauthor(policy['author']['model']))
        save('complete',result_head=git(integration,'rev-parse','HEAD'),finished=time.time())
        return state

    def resume(self,name,recheck,reason,instructions=None):
        require(isinstance(name,str) and re.fullmatch(r'EV-[a-f0-9]{12}',name),'Invalid evolution task ID')
        require(reason.strip(),'Resume requires an explicit reason')
        with self.lock():
            directory=self.directory/name;state=json.loads((directory/'cycle.json').read_text(encoding='utf-8'))
            require(state['state']=='failed','Resume handles failed cycles only')
            require(not self.ledger.db.execute('SELECT 1 FROM integration').fetchone(),'Release or reconcile the integration slot first')
            task=self.ledger.task(name)
            require(not task.get('active_run'),'Stop active runtime before resume')
            require(task['state'] in ('running','review','approved') and task.get('head'),'Need a submitted implementation; use reconcile for earlier failures')
            require(self.ledger.current_head(task)==task['head'],'Implementation changed; submit a verified new snapshot instead')
            policy=state['policy'];validate_policy(policy)
            # Preserve the previous complete failure record before changing any state.
            data=(directory/'cycle.json').read_bytes()
            (directory/('prior-cycle-'+hashlib.sha256(data).hexdigest()+'.json')).write_bytes(data)
            def save(stage,**fields):save_cycle(directory,state,stage,**fields)
            def gate(wt,label):return full_gate(wt,directory,label,policy)
            try:
                save('resuming',resume_reason=reason,prior_error=state.get('error'),error=None)
                if recheck:
                    proof=gate(task['worktree'],'recheck-gate')
                    evidence=directory/'recheck-gate.json';evidence.write_text(json.dumps(proof),encoding='utf-8')
                    self.ledger.submit(name,task['token'],task['head'],evidence)
                    text='Coordinator verified the full gate on this exact clean commit: '+json.dumps(proof)+'. Return only JSON; findings are actionable defects violating acceptance, not optional preferences or environmental limitations. PASS requires findings: []. Put nonblocking notes and read-only limitations in checks. Do not claim tests were run by you.\n'
                    if instructions:text+=Path(instructions).read_text(encoding='utf-8')
                    notes=directory/'recheck-instructions.txt';notes.write_text(text,encoding='utf-8')
                    save('rechecking',agent_runs=state.get('agent_runs',0)+1)
                    review=execute(self.ledger,name,'review',policy['reviewer']['model'],'evolution-reviewer',None,policy['run_seconds'],notes,policy['reviewer']['harness'])
                    require(review['state']=='succeeded','Explicit recheck runtime failed')
                    self.ledger.review(name,'evolution-reviewer',task['head'],review['review']['verdict'],Path(review['directory'])/'response.txt')
                    save('reviewed',review_run=review['id'],verdict=review['review']['verdict'])
                    require(review['review']['verdict']=='PASS','Explicit recheck did not pass')
                return self.complete(state,directory,save,gate)
            except Exception as exc:
                save('failed',error=type(exc).__name__+': '+str(exc),finished=time.time())
                return state

    @staticmethod
    def writeback(root,state,passed):
        root=Path(root);name=state['id']
        body='# '+name+' 自动复盘\n\n```json\n'+json.dumps({k:state.get(k) for k in ('id','state','source','policy','author_run','review_run','head','verdict','integrated_head','error','prior_error','resume_reason','agent_runs')},ensure_ascii=False,indent=2)+'\n```'
        body+='\n\n已验证事实：'+('发现探针、完整门禁及独立验收通过；代码已集成到上述候选分支。' if passed else '本轮未完成；保留现场，需人工检查，不自动重新领取。')
        body+='\n运行日志与原始回执保留在本机 Git common dir/agentctl/evolution 和 runs。未合并 main、未推送或发布。\n'
        path=root/'docs/tasks'/ (name+'-retrospective.md');path.parent.mkdir(parents=True,exist_ok=True);path.write_text(body,encoding='utf-8')
        if passed:
            lessons=root/'LESSONS.md'
            prior=lessons.read_text(encoding='utf-8') if lessons.exists() else '# 开发教训\n'
            prior+='\n## '+name+'：自动探针的已验证记录\n\n'
            prior+='探针 '+state['source']['kind']+' 在 '+state['source']['head']+' 失败，在 '+state['head']+' 通过。\n'
            prior+='这是一条事实记录，尚未自动晋升为工程规范。证据见 [复盘](docs/tasks/'+name+'-retrospective.md)。\n'
            lessons.write_text(prior,encoding='utf-8')


def save_cycle(directory,state,stage,**fields):
    state.update(fields,state=stage)
    state['stages'].append(dict(stage=stage,time=time.time()))
    p=directory/'cycle.json.tmp';p.write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf-8')
    p.replace(directory/'cycle.json')


def full_gate(worktree,directory,label,policy):
    log=directory/(label+'.log');before=worktree_digest(worktree)
    rc=command(['bash','scripts/verify.sh'],worktree,log,policy['gate_seconds'])
    require(rc==0,'Full gate failed: '+str(log))
    require(worktree_digest(worktree)==before,'Gate changed project contents; inspect before committing')
    return dict(head=git(worktree,'rev-parse','HEAD'),worktree=str(worktree),worktree_digest=before,
                command='bash scripts/verify.sh',exit_code=0,
                log=str(log)+' SHA256 '+hashlib.sha256(log.read_bytes()).hexdigest())


def coauthor(model):
    key=model_key(model)
    for prefix,name,email in [('gpt','GPT','noreply@openai.com'),('gemini','Gemini','218195315+gemini-cli@users.noreply.github.com'),('claude','Claude','noreply@anthropic.com'),('deepseek','DeepSeek','noreply@deepseek.com')]:
        if key.startswith(prefix):return 'Co-Authored-By: '+name+' <'+email+'>'
    raise Error('No verified model-family attribution for '+model)


def validate_policy(policy):
    require(isinstance(policy,dict),'Policy must be an object')
    require(set(policy)=={'automatic_kinds','author','reviewer','run_seconds','gate_seconds'},'Unknown or missing policy fields')
    require(isinstance(policy.get('automatic_kinds'),list) and set(policy['automatic_kinds'])<=set(KINDS),'Unknown automatic discovery kind')
    for key in ('author','reviewer'):
        p=policy.get(key,{})
        require(p.get('harness') in ('agy','pi','omp') and isinstance(p.get('model'),str),'Explicit runtime/model required')
        coauthor(p['model'])
    require(model_key(policy['author']['model'])!=model_key(policy['reviewer']['model']),'Use different author and reviewer models')
    for key,low,high in [('run_seconds',30,1800),('gate_seconds',30,1800)]:
        require(type(policy.get(key)) is int and low<=policy[key]<=high,'Invalid '+key)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',default='.')
    parser.add_argument('action',choices=['scan','status','tick','watch','reconcile','resume'])
    parser.add_argument('--policy',type=Path)
    parser.add_argument('--task')
    parser.add_argument('--stopped',action='store_true')
    parser.add_argument('--reason',default='')
    parser.add_argument('--recheck',action='store_true')
    parser.add_argument('--instructions',type=Path)
    parser.add_argument('--cycles',type=int,default=1)
    parser.add_argument('--interval',type=int,default=300)
    args=parser.parse_args();ledger=None
    def interrupt(signum,frame):raise KeyboardInterrupt
    previous={s:signal.signal(s,interrupt) for s in (signal.SIGTERM,signal.SIGHUP,signal.SIGQUIT)}
    try:
        ledger=Ledger(args.repo);flow=Evolution(ledger)
        if args.action=='status':result=flow.candidates()
        elif args.action=='reconcile':result=flow.reconcile(args.task,args.stopped,args.reason)
        elif args.action=='resume':result=[flow.resume(args.task,args.recheck,args.reason,args.instructions)]
        elif args.action=='scan':
            with flow.lock():result=flow.scan(ledger.repo)
        else:
            require(args.policy is not None,'Explicit approved policy required')
            policy=json.loads(args.policy.read_text(encoding='utf-8'));validate_policy(policy)
            require(1<=args.cycles<=24 and 60<=args.interval<=86400,'Invalid cycle or interval budget')
            result=[]
            scan_root=ledger.repo
            for i in range(args.cycles if args.action=='watch' else 1):
                current=flow.tick(scan_root,policy);result.append(current)
                if current['state']=='complete':scan_root=Path(current['integration'])
                print(json.dumps({k:current[k] for k in ('id','state','agent_runs') if k in current}),flush=True)
                if current['state']=='failed':break
                if args.action=='watch' and i+1<args.cycles:time.sleep(args.interval)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 1 if isinstance(result,list) and any(r.get('state')=='failed' for r in result) else 0
    except KeyboardInterrupt:
        print('Cycle interrupted; inspect the journal and confirm processes stopped before recovery',file=sys.stderr)
        return 130
    except (Error,OSError,ValueError,subprocess.SubprocessError) as exc:
        print(json.dumps({'error':str(exc)},ensure_ascii=False),file=sys.stderr);return 1
    finally:
        if ledger:ledger.db.close()
        for signum,handler in previous.items():signal.signal(signum,handler)


if __name__=='__main__':sys.exit(main())
