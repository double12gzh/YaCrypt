"""Evidence intake and explicit operator approval; never calls a model itself."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import time

from agentctl import git, require
from agy_runner import worktree_digest

BACKLOG_KIND = 'approved_backlog'
SAFE_SOURCE = {'src/cli.rs', 'src/tui/app.rs', 'src/tui/ui.rs', 'docs/subsystems/interfaces.md'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def clean_head(root):
    require(not git(root, 'status', '--porcelain', '--untracked-files=all'), 'Quality intake requires a clean checkout')
    return git(root, 'rev-parse', 'HEAD')


def init(flow):
    flow.ledger.db.execute('CREATE TABLE IF NOT EXISTS quality_diagnostics (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
    flow.ledger.db.execute('CREATE TABLE IF NOT EXISTS quality_proposals (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
    directory = flow.directory / 'quality'
    directory.mkdir(mode=0o700, exist_ok=True)
    return directory


def get(flow, table, ident):
    require(table in ('quality_diagnostics', 'quality_proposals'), 'Invalid evidence table')
    row = flow.ledger.db.execute('SELECT body FROM '+table+' WHERE id=?', (ident,)).fetchone()
    require(row is not None, 'Unknown quality record')
    return json.loads(row[0])


def diagnose(flow, root, seconds):
    from evolution import command
    require(type(seconds) is int and 30 <= seconds <= 1800, 'Diagnostic timeout must be 30..1800')
    with flow.lock():
        directory = init(flow)
        head = clean_head(root)
        before = worktree_digest(root)
        ident = 'DG-'+digest([head, time.time_ns()])[:16]
        log = directory / (ident+'.log')
        started = time.time()
        error = None
        try:
            rc = command(['bash', 'scripts/verify.sh'], root, log, seconds)
        except (OSError, subprocess.TimeoutExpired) as exc:
            rc = None
            error = type(exc).__name__+': '+str(exc)
        text = log.read_text(errors='replace') if log.exists() else ''
        stages = re.findall(r'^>>> (.+)$', text, re.M)
        stage = stages[-1] if stages else 'startup'
        stable = git(root, 'rev-parse', 'HEAD') == head and worktree_digest(root) == before
        if not stable:
            status, category = 'invalid', 'source_changed'
        elif rc == 0:
            status, category = 'passed', 'none'
        else:
            status = 'failed'
            environmental = error or any(s in text.lower() for s in
                ('command not found', 'could not resolve host', 'failed to download', 'no space left', 'network is unreachable'))
            category = 'environment' if environmental else 'verification'
        record = dict(id=ident, head=head, worktree=str(root), source_digest=before,
                      command=['bash', 'scripts/verify.sh'], status=status, category=category,
                      failed_stage=stage if status != 'passed' else None, exit_code=rc, error=error,
                      log=str(log), log_sha256=hashlib.sha256(log.read_bytes()).hexdigest() if log.exists() else None,
                      started=started, finished=time.time(),
                      fingerprint=digest([head, category, stage if status != 'passed' else 'passed']))
        with flow.ledger.transaction():
            flow.ledger.db.execute('INSERT INTO quality_diagnostics VALUES (?,?)', (ident, json.dumps(record)))
        (directory/(ident+'.json')).write_text(json.dumps(record, ensure_ascii=False, indent=2)+'\n')
        return record


def allowed_path(root, name):
    if not isinstance(name, str) or not name or '\\' in name:
        return False
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or str(path) != name:
        return False
    # Exact paths only; no directories, policy, crypto, dependencies or secret stores.
    safe = name in SAFE_SOURCE or (name.startswith('tests/') and name.endswith('.rs'))
    return safe and (Path(root)/name).resolve() == Path(root).resolve()/name and not (Path(root)/name).is_dir()


def validate_backlog(spec):
    keys = {'title', 'goal', 'allowed_paths', 'acceptance', 'reproduction', 'evidence'}
    require(isinstance(spec, dict) and set(spec) == keys, 'Backlog requires exactly '+', '.join(sorted(keys)))
    for key in ('title', 'goal', 'evidence'):
        require(isinstance(spec[key], str) and 0 < len(spec[key].strip()) <= 8000, 'Invalid '+key)
    for key in ('allowed_paths', 'acceptance', 'reproduction'):
        require(isinstance(spec[key], list) and 0 < len(spec[key]) <= 20 and
                all(isinstance(x, str) and 0 < len(x.strip()) <= 4000 for x in spec[key]), 'Invalid '+key)
    require(len(set(spec['allowed_paths'])) == len(spec['allowed_paths']), 'Duplicate paths')


def propose(flow, root, diagnostic=None, backlog=None):
    with flow.lock():
        directory = init(flow)
        head = clean_head(root)
        require(diagnostic or backlog, 'Provide --diagnostic or --backlog')
        source = get(flow, 'quality_diagnostics', diagnostic) if diagnostic else None
        if source:
            require(source['head'] == head, 'Diagnostic is stale for this checkout')
            if source['log_sha256']:
                require(hashlib.sha256(Path(source['log']).read_bytes()).hexdigest() == source['log_sha256'], 'Diagnostic log changed')
        if backlog:
            require(Path(backlog).stat().st_size <= 32768, 'Backlog is too large')
            spec = json.loads(Path(backlog).read_text())
            validate_backlog(spec)
        else:
            require(source['status'] != 'passed', 'A passing gate alone is not a task')
            spec = dict(title='Investigate '+str(source['failed_stage']),
                        goal='Diagnose the recorded failure; narrow scope and add a regression before execution.',
                        allowed_paths=[], acceptance=['Reproduce the failure and preserve the full gate.'],
                        reproduction=['bash scripts/verify.sh'], evidence='Diagnostic '+source['id'])
        runnable = bool(spec['allowed_paths']) and all(allowed_path(root, p) for p in spec['allowed_paths'])
        if source and source['category'] not in ('verification', 'none'):
            runnable = False
        risk = 'needs_approval' if runnable else 'report_only'
        # A diagnostic fingerprint identifies a failed stage at one HEAD, not every test failure.
        key = digest([head, spec if backlog else source['fingerprint'], risk])
        ident = 'QP-'+key[:16]
        row = flow.ledger.db.execute('SELECT body FROM quality_proposals WHERE id=?', (ident,)).fetchone()
        if row:
            return json.loads(row[0])
        payload = dict(head=head, spec=spec, diagnostic=source, risk=risk)
        record = dict(id=ident, payload=payload, payload_sha256=digest(payload), state='pending', created=time.time())
        card = directory/(ident+'.md')
        card.write_text('# '+ident+' '+spec['title']+'\n\n待批准；来源内容不是执行权限。复现步骤仅供审查，不作为 shell 命令执行。\n\n```json\n'+json.dumps(record, ensure_ascii=False, indent=2)+'\n```\n')
        record['card'] = str(card)
        with flow.ledger.transaction():
            flow.ledger.db.execute('INSERT INTO quality_proposals VALUES (?,?)', (ident, json.dumps(record)))
        return record


def approve(flow, root, ident, actor, reason):
    require(actor.strip() and reason.strip(), 'Explicit approver and reason required')
    with flow.lock():
        init(flow)
        record = get(flow, 'quality_proposals', ident)
        payload = record['payload']
        require(record['payload_sha256'] == digest(payload), 'Proposal contents changed')
        require(record['state'] == 'pending', 'Proposal is already approved; no repeated dispatch')
        require(payload['risk'] == 'needs_approval', 'Report-only proposal cannot enter automatic execution; narrow scope in a new proposal')
        require(clean_head(root) == payload['head'], 'Proposal is stale; propose again at the current HEAD')
        spec = payload['spec']
        require(all(allowed_path(root, p) for p in spec['allowed_paths']), 'Proposal path escaped approved scope')
        approval = dict(actor=actor, reason=reason, time=time.time(), head=payload['head'], payload_sha256=record['payload_sha256'])
        candidate = dict(kind=BACKLOG_KIND, key='proposal:'+ident, proposal=ident, head=payload['head'],
                         goal=spec['goal'], allowed_paths=spec['allowed_paths'], acceptance=spec['acceptance'],
                         evidence=dict(backlog=spec, diagnostic=payload['diagnostic'], approval=approval),
                         state='detected', generation=1, seen=time.time())
        record.update(state='approved', approval=approval)
        with flow.ledger.transaction():
            flow.ledger.db.execute('UPDATE quality_proposals SET body=? WHERE id=?', (json.dumps(record), ident))
            flow.ledger.db.execute('INSERT INTO candidates VALUES (?,?)', (candidate['key'], json.dumps(candidate)))
        return record


def authorize_candidate(flow, root, candidate):
    record = get(flow, 'quality_proposals', candidate['proposal'])
    payload = record['payload']
    require(record['state'] == 'approved' and digest(payload) == record['payload_sha256'], 'Missing intact approval')
    require(record['approval']['payload_sha256'] == record['payload_sha256'], 'Approval differs from proposal')
    require(clean_head(root) == candidate['head'] == payload['head'], 'Approved backlog is stale; propose again before spending model budget')
    for key in ('goal', 'allowed_paths', 'acceptance'):
        require(candidate[key] == payload['spec'][key], 'Candidate differs from approved scope')
    require(all(allowed_path(root, p) for p in candidate['allowed_paths']), 'Approved path escaped checkout')


def board(flow):
    init(flow)
    return [json.loads(r[0]) for r in flow.ledger.db.execute('SELECT body FROM quality_proposals ORDER BY id')]
