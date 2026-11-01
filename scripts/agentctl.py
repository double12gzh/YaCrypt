#!/usr/bin/env python3
"""Local, cooperative task coordination. No daemon or automatic merge; explicit supervised agy runs."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import sqlite3
import subprocess
import sys
import time


class Error(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Error(message)


def git(repo, *args):
    # A CLI launched from a Git hook must still operate on the explicit repository.
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_') or k in ('GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_NOSYSTEM')}
    p = subprocess.run(['git', '-C', str(repo), *args], env=env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode:
        raise Error(p.stderr.strip() or p.stdout.strip() or 'git failed')
    return p.stdout.rstrip('\n')


def ancestor(repo, older, newer):
    try:
        git(repo, 'merge-base', '--is-ancestor', older, newer)
        return True
    except Error:
        return False


def evidence(path, head=None):
    data = Path(path).read_bytes()
    require(0 < len(data) <= 1024 * 1024, 'Evidence must be 1 byte to 1 MiB')
    text = data.decode('utf-8')
    if head is not None:
        record = json.loads(text)
        require(isinstance(record, dict) and record.get('head') == head and record.get('exit_code') == 0
                and record.get('command') == 'bash scripts/verify.sh'
                and bool(record.get('log')) and isinstance(record.get('worktree'), str), 'Gate evidence must name this head, command, exit_code=0, log and worktree')
    return {'sha256': hashlib.sha256(data).hexdigest(), 'text': text}


class Ledger:
    def __init__(self, repo, initialize=False):
        self.repo = Path(git(repo, 'rev-parse', '--show-toplevel')).resolve()
        common = Path(git(self.repo, 'rev-parse', '--git-common-dir'))
        self.common = (self.repo / common).resolve()
        # First worktree is Git's primary checkout, shared by all linked checkouts.
        self.primary = Path(git(self.repo, 'worktree', 'list', '--porcelain').splitlines()[0][9:]).resolve()
        self.directory = self.common / 'agentctl'
        self.dbpath = self.directory / 'ledger.sqlite3'
        if initialize:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(initialize or self.dbpath.exists(), 'Run init first')
        self.db = sqlite3.connect(self.dbpath, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        if initialize:
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS meta (version INTEGER NOT NULL);
                INSERT INTO meta SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM meta);
                CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY, task TEXT NOT NULL, time REAL NOT NULL,
                    kind TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS integration (slot INTEGER PRIMARY KEY CHECK(slot=1), body TEXT NOT NULL);
            ''')
        require(self.db.execute('SELECT version FROM meta').fetchone()[0] == 1, 'Unsupported ledger version')

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def task(self, name):
        row = self.db.execute('SELECT body FROM tasks WHERE id=?', (name,)).fetchone()
        require(row is not None, 'Unknown task: ' + name)
        return json.loads(row[0])

    def save(self, task, kind, details=None):
        self.db.execute('INSERT OR REPLACE INTO tasks VALUES (?,?)', (task['id'], json.dumps(task)))
        self.db.execute('INSERT INTO events(task,time,kind,body) VALUES (?,?,?,?)',
                        (task['id'], time.time(), kind, json.dumps(details or self.public(task))))

    @staticmethod
    def public(task):
        return {k: v for k, v in task.items() if k != 'token'}

    def add(self, spec):
        require(isinstance(spec, dict), 'Task spec must be an object')
        name = spec.get('id', '')
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', name), 'Invalid task id')
        for field in ('goal', 'source', 'non_goals'):
            require(isinstance(spec.get(field), str) and spec[field].strip(), 'Required: ' + field)
        for field in ('acceptance', 'allowed_paths'):
            require(isinstance(spec.get(field), list) and spec[field]
                    and all(isinstance(v, str) and v.strip() for v in spec[field]), 'Required list: ' + field)
        for path in spec['allowed_paths']:
            require(not PurePosixPath(path).is_absolute() and '..' not in PurePosixPath(path).parts
                    and path not in ('.', '') and '.git' not in PurePosixPath(path).parts, 'Invalid allowed path')
        deps = spec.get('depends_on', [])
        require(isinstance(deps, list) and all(isinstance(d, str) for d in deps), 'Invalid dependencies')
        attempts = spec.get('max_attempts', 3)
        require(type(attempts) is int and 1 <= attempts <= 10, 'max_attempts must be 1..10')
        with self.transaction():
            require(not self.db.execute('SELECT 1 FROM tasks WHERE id=?', (name,)).fetchone(), 'Duplicate task')
            for dep in deps:
                self.task(dep)  # Requiring existing deps prevents cycles at insertion.
            task = {k: spec[k] for k in ('id', 'goal', 'source', 'non_goals', 'acceptance', 'allowed_paths')}
            task.update(state='ready', attempt=0, depends_on=deps, max_attempts=attempts)
            self.save(task, 'added')
        return task

    def claim(self, name, owner, harness, base, seconds):
        require(owner.strip(), 'Owner is required')
        require(1 <= seconds <= 86400, 'Lease must be 1..86400 seconds')
        base = git(self.repo, 'rev-parse', '--verify', base + '^{commit}')
        with self.transaction():
            task = self.task(name)
            require(task['state'] == 'ready', 'Task is not ready; expired leases require explicit recovery')
            require(task['attempt'] < task['max_attempts'], 'Attempt budget exhausted')
            for dep in task['depends_on']:
                d = self.task(dep)
                require(d['state'] == 'integrated' and ancestor(self.repo, d['integrated_head'], base),
                        'Dependency must be integrated and included in base: ' + dep)
            number = task['attempt'] + 1
            worktree = self.primary / '.worktrees' / 'agentctl' / f'{name}-{number}'
            require(worktree.resolve().is_relative_to(self.primary), 'Worktree path escapes repository')
            require(not worktree.exists(), 'Worktree path already exists; preserve it and inspect')
            task.update(state='provisioning', attempt=number, owner=owner, harness=harness, base=base,
                        worktree=str(worktree), branch=f'codex/task-{name}-{number}',
                        token=secrets.token_hex(24), expires=time.time() + seconds)
            self.save(task, 'claim_reserved')
        # Persist reservation first: interruption never silently returns the task to ready.
        try:
            git(self.repo, 'worktree', 'add', '-b', task['branch'], str(worktree), base)
            with self.transaction():
                current = self.task(name)
                require(current.get('token') == task['token'] and current['state'] == 'provisioning',
                        'Reservation was recovered; preserve this attempt worktree')
                current['state'] = 'running'
                self.save(current, 'claimed')
                task = current
        except BaseException:
            # Reservation and partial worktree remain inspectable for explicit recovery.
            raise
        return task

    def leased(self, name, token):
        task = self.task(name)
        require(task.get('token') == token, 'Stale or incorrect attempt token')
        require(task.get('expires', 0) > time.time(), 'Lease expired; explicit stopped recovery required')
        return task

    def renew(self, name, token, seconds):
        require(1 <= seconds <= 86400, 'Lease must be 1..86400 seconds')
        with self.transaction():
            task = self.leased(name, token)
            require(task['state'] == 'running', 'Only a running task can renew')
            task['expires'] = time.time() + seconds
            self.save(task, 'renewed')
        return self.public(task)

    def recover(self, name, stopped, reason):
        require(stopped and reason.strip(), 'Confirm old session stopped and supply reason')
        with self.transaction():
            task = self.task(name)
            require(task['state'] in ('provisioning', 'running', 'review', 'approved'), 'Task cannot be recovered')
            require(not self.reservation_for(name), 'Release integration reservation first')
            if task.get('active_run'):
                task['runs'][-1]['state'] = 'abandoned'
                self.save(task, 'run_abandoned', {'id': task.pop('active_run'), 'stopped_confirmed': True})
            self.save(task, 'attempt_closed', {'attempt': task['attempt'], 'worktree': task.get('worktree'),
                                             'reason': reason, 'stopped_confirmed': True})
            for key in ('token', 'expires', 'head', 'submission', 'review', 'execution_run'):
                task.pop(key, None)
            task['state'] = 'ready'
            self.save(task, 'recovered')
        return self.public(task)

    def current_head(self, task):
        worktree = task['worktree']
        require(git(worktree, 'rev-parse', '--show-toplevel') == str(Path(worktree).resolve()), 'Wrong worktree')
        require(git(worktree, 'symbolic-ref', '--short', 'HEAD') == task['branch'], 'Wrong branch')
        require(not git(worktree, 'status', '--porcelain', '--untracked-files=all'), 'Worktree is dirty')
        return git(worktree, 'rev-parse', 'HEAD')

    def submit(self, name, token, head, report):
        proof = evidence(report)
        with self.transaction():
            task = self.leased(name, token)
            require(not task.get('active_run'), 'Wait for the active run to stop before submitting')
            require(task['state'] in ('running', 'review', 'approved'), 'Task cannot submit')
            require(not self.reservation_for(name), 'Release integration reservation before resubmitting')
            require(self.current_head(task) == head, 'Submission must match current clean worktree HEAD')
            require(head != task['base'] and ancestor(self.repo, task['base'], head), 'Head must extend base')
            files = git(self.repo, 'diff', '--no-renames', '--name-only', '-z', task['base'], head).split('\0')
            for path in filter(None, files):
                require(any(path == p.rstrip('/') or path.startswith(p.rstrip('/') + '/')
                            for p in task['allowed_paths']), 'Out-of-scope path: ' + path)
            if task['harness'] == 'agy':
                from agy_runner import worktree_digest
                runs = [r for r in task.get('runs', []) if r['role'] == 'execute'
                        and r['attempt'] == task['attempt'] and r['state'] == 'succeeded']
                require(runs and runs[-1].get('worktree_digest') == worktree_digest(task['worktree']),
                        'Submission differs from the successful agy execution snapshot')
                task['execution_run'] = runs[-1]['id']
            task.update(state='review', head=head, submission=proof)
            task.pop('review', None)
            self.save(task, 'submitted')
        return self.public(task)

    def review(self, name, reviewer, head, verdict, report):
        proof = evidence(report)
        with self.transaction():
            task = self.task(name)
            require(not task.get('active_run'), 'Wait for the active review run to stop')
            require(task['state'] == 'review', 'Task is not awaiting review')
            require(reviewer.strip() and reviewer != task['owner'], 'Independent reviewer identity required')
            require(task['head'] == head == self.current_head(task), 'Review is stale; resubmit current head')
            run_proof = None
            if task['harness'] == 'agy':
                runs = [r for r in task.get('runs', []) if r['role'] == 'review'
                        and r['attempt'] == task['attempt'] and r['state'] == 'succeeded'
                        and r['actor'] == reviewer and r['review']['head'] == head
                        and r['review']['verdict'] == verdict and r['response.txt_sha256'] == proof['sha256']]
                require(runs, 'agy review requires matching cross-model runtime evidence')
                run_proof = {k: runs[-1][k] for k in ('id', 'requested_model', 'conversation_id')}
            task['review'] = dict(reviewer=reviewer, head=head, verdict=verdict, evidence=proof)
            if run_proof:
                task['review']['run'] = run_proof
            task['state'] = 'approved' if verdict == 'PASS' else 'running'
            self.save(task, 'reviewed')
        return self.public(task)

    def queue(self):
        result = []
        for row in self.db.execute('SELECT body FROM tasks ORDER BY id'):
            task = json.loads(row[0])
            if task['state'] == 'approved':
                try:
                    fresh = self.current_head(task) == task['head']
                except Error:
                    fresh = False
                result.append(dict(id=task['id'], head=task['head'], eligible=fresh))
        return result

    def reservation_for(self, name):
        row = self.db.execute('SELECT body FROM integration WHERE slot=1').fetchone()
        return row and json.loads(row[0])['task'] == name

    def reserve(self, name, target, integrator):
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./-]*', target), 'Use a local branch name')
        require(integrator.strip(), 'Integrator required')
        with self.transaction():
            require(not self.db.execute('SELECT 1 FROM integration').fetchone(), 'Integration slot occupied')
            task = self.task(name)
            require(task['state'] == 'approved' and task['head'] == self.current_head(task), 'Approval stale or absent')
            require(target != task['branch'], 'Integration target must differ from the task branch')
            target_sha = git(self.repo, 'rev-parse', '--verify', 'refs/heads/' + target)
            record = dict(task=name, head=task['head'], target=target, base=target_sha,
                          integrator=integrator, token=secrets.token_hex(24))
            self.db.execute('INSERT INTO integration VALUES (1,?)', (json.dumps(record),))
            self.save(task, 'integration_reserved', {k: v for k, v in record.items() if k != 'token'})
        return record

    def finish(self, token, head, report):
        proof = evidence(report, head)
        with self.transaction():
            row = self.db.execute('SELECT body FROM integration').fetchone()
            require(row is not None, 'No integration reservation')
            slot = json.loads(row[0])
            require(slot['token'] == token, 'Wrong integration token')
            task = self.task(slot['task'])
            require(task['state'] == 'approved' and task['head'] == slot['head'] == self.current_head(task),
                    'Approval changed since reservation')
            require(git(self.repo, 'rev-parse', 'refs/heads/' + slot['target']) == head,
                    'Evidence must match current target branch head')
            require(ancestor(self.repo, slot['head'], head) and ancestor(self.repo, slot['base'], head),
                    'Integration must contain approved head and target baseline')
            checked = Path(json.loads(proof['text'])['worktree']).resolve()
            require(git(checked, 'rev-parse', '--show-toplevel') == str(checked), 'Gate worktree must be a checkout root')
            common = Path(git(checked, 'rev-parse', '--git-common-dir'))
            require((checked / common).resolve() == self.common, 'Gate worktree belongs to another repository')
            require(git(checked, 'symbolic-ref', '--short', 'HEAD') == slot['target']
                    and git(checked, 'rev-parse', 'HEAD') == head, 'Gate worktree must check out the target head')
            require(not git(checked, 'status', '--porcelain', '--untracked-files=all'), 'Gate worktree is dirty')
            task.update(state='integrated', integrated_head=head, integrated_target=slot['target'], gate=proof)
            self.save(task, 'integrated')
            self.db.execute('DELETE FROM integration')
        return self.public(task)

    def release(self, token, reason):
        require(reason.strip(), 'Reason required')
        with self.transaction():
            row = self.db.execute('SELECT body FROM integration').fetchone()
            require(row is not None, 'No integration reservation')
            slot = json.loads(row[0])
            require(slot['token'] == token, 'Wrong integration token')
            self.save(self.task(slot['task']), 'integration_released', {'reason': reason})
            self.db.execute('DELETE FROM integration')
        return {'released': slot['task']}

    def handoff(self, name):
        task = self.task(name)
        require(task['state'] == 'running', 'Handoff requires running task')
        return {'task': self.public(task), 'instructions': [
            'Open a separate agy/Codex/pi/omp session at the exact worktree path.',
            'Read AGENTS.md, LESSONS.md and relevant subsystem references before editing.',
            'Meet acceptance, stay within allowed_paths, run bash scripts/verify.sh.',
            'Commit locally. Write evidence outside the worktree, then submit exact SHA with the claim token.',
            'No push, merge, release or automatic scope expansion. Coordinator renews lease while session is active.',
            'For interruption: stop the old session first, then recover; preserve old worktree and logs.'
        ]}


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', default=str(Path(__file__).resolve().parent.parent))
    sub = p.add_subparsers(dest='cmd', required=True)
    sub.add_parser('init')
    a = sub.add_parser('add'); a.add_argument('spec', type=Path)
    sub.add_parser('list'); sub.add_parser('queue'); sub.add_parser('integration')
    for name in ('show', 'handoff'):
        a = sub.add_parser(name); a.add_argument('id')
    a = sub.add_parser('claim'); a.add_argument('id'); a.add_argument('--owner', required=True)
    a.add_argument('--harness', choices=['agy','codex','pi','omp'], required=True)
    a.add_argument('--base', default='main'); a.add_argument('--seconds', type=int, default=3600)
    a = sub.add_parser('renew'); a.add_argument('id'); a.add_argument('--token', required=True)
    a.add_argument('--seconds', type=int, default=3600)
    a = sub.add_parser('recover'); a.add_argument('id'); a.add_argument('--stopped', action='store_true')
    a.add_argument('--reason', required=True)
    a = sub.add_parser('submit'); a.add_argument('id'); a.add_argument('--token', required=True)
    a.add_argument('--head', required=True); a.add_argument('--evidence', required=True)
    a = sub.add_parser('review'); a.add_argument('id'); a.add_argument('--reviewer', required=True)
    a.add_argument('--head', required=True); a.add_argument('--verdict', choices=['PASS','ISSUES','BLOCKED'], required=True)
    a.add_argument('--evidence', required=True)
    a = sub.add_parser('reserve'); a.add_argument('id'); a.add_argument('--target', default='main')
    a.add_argument('--integrator', required=True)
    a = sub.add_parser('finish'); a.add_argument('--token', required=True); a.add_argument('--head', required=True)
    a.add_argument('--evidence', required=True)
    a = sub.add_parser('run'); a.add_argument('id'); a.add_argument('--role', choices=['execute','review'], required=True)
    a.add_argument('--model', required=True); a.add_argument('--actor', required=True); a.add_argument('--token')
    a.add_argument('--seconds', type=int, default=300); a.add_argument('--instructions')
    a = sub.add_parser('release'); a.add_argument('--token', required=True); a.add_argument('--reason', required=True)
    return p


def main():
    args = parser().parse_args()
    ledger = None
    try:
        ledger = Ledger(args.repo, initialize=args.cmd == 'init')
        if args.cmd == 'init': result = {'database': str(ledger.dbpath), 'version': 1}
        elif args.cmd == 'add': result = ledger.add(json.loads(args.spec.read_text()))
        elif args.cmd == 'list':
            result = [ledger.public(json.loads(r[0])) for r in ledger.db.execute('SELECT body FROM tasks ORDER BY id')]
        elif args.cmd == 'show':
            result = ledger.public(ledger.task(args.id))
            result['events'] = [dict(r) for r in ledger.db.execute('SELECT * FROM events WHERE task=? ORDER BY seq', (args.id,))]
        elif args.cmd == 'handoff': result = ledger.handoff(args.id)
        elif args.cmd == 'integration':
            row = ledger.db.execute('SELECT body FROM integration').fetchone()
            result = json.loads(row[0]) if row else None
        elif args.cmd == 'queue': result = ledger.queue()
        elif args.cmd == 'claim': result = ledger.claim(args.id, args.owner, args.harness, args.base, args.seconds)
        elif args.cmd == 'renew': result = ledger.renew(args.id, args.token, args.seconds)
        elif args.cmd == 'recover': result = ledger.recover(args.id, args.stopped, args.reason)
        elif args.cmd == 'submit': result = ledger.submit(args.id, args.token, args.head, args.evidence)
        elif args.cmd == 'review': result = ledger.review(args.id, args.reviewer, args.head, args.verdict, args.evidence)
        elif args.cmd == 'reserve': result = ledger.reserve(args.id, args.target, args.integrator)
        elif args.cmd == 'finish': result = ledger.finish(args.token, args.head, args.evidence)
        elif args.cmd == 'run':
            from agy_runner import execute
            result = execute(ledger, args.id, args.role, args.model, args.actor, args.token, args.seconds, args.instructions)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result['state'] == 'succeeded' else 1
        elif args.cmd == 'release': result = ledger.release(args.token, args.reason)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (Error, OSError, ValueError, sqlite3.Error) as exc:
        print(json.dumps({'error': str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    finally:
        if ledger:
            ledger.db.close()
    return 0


if __name__ == '__main__':
    # Keep Error/Ledger identity shared with the lazily imported runtime.
    sys.modules['agentctl'] = sys.modules[__name__]
    sys.exit(main())
