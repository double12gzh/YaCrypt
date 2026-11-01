"""CLI-specific catalogs, arguments and wire formats; supervision lives in agy_runner."""
import json
import re
import subprocess
import tempfile


def catalog(harness, executable):
    from agy_runner import wait_unreaped, stop_group
    argv = ([executable, '--list-models', '--no-extensions', '--no-mcp'] if harness == 'pi'
            else [executable, 'models', '--json', '--no-extensions'])
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        proc = subprocess.Popen(argv, stdout=out, stderr=err, start_new_session=True)
        try:
            wait_unreaped(proc, 45)
        finally:
            stop_group(proc)
        out.seek(0); err.seek(0)
        if proc.returncode:
            raise ValueError('Model catalog failed: ' + err.read().decode('utf-8', 'replace')[-1000:])
        raw = out.read().decode('utf-8')
    if harness == 'omp':
        models = {m['provider'] + '/' + m['id']: m.get('name', m['id'])
                  for m in json.loads(raw)['models'] if m.get('kind', 'chat') == 'chat'}
    else:
        models = {}
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] != 'provider' and re.fullmatch(r'[\w./-]+', parts[1]):
                models[parts[0] + '/' + parts[1]] = parts[1]
    if not models:
        raise ValueError('No usable models in catalog')
    return models


def command(harness, executable, model, role, seconds, prompt):
    # Only file tools: no shell, MCP, extensions, network tools or recursive agents.
    # This is a cooperative tool restriction, not a filesystem security boundary.
    tools = 'read,edit,write' if role == 'execute' else 'read'
    if harness == 'pi':
        provider, model_id = model.split('/', 1)
        return [executable, '--provider', provider, '--model', model_id, '--mode', 'json',
                '--print', '--no-session', '--no-extensions', '--no-mcp', '--no-skills',
                '--no-context-files', '--no-prompt-templates', '--no-themes', '--no-approve',
                '--tools', tools, '--', prompt]
    return [executable, '--model', model, '--mode', 'json', '--print', '--no-session',
            '--no-extensions', '--no-skills', '--no-context-files', '--no-rules', '--no-lsp',
            '--no-title', '--no-prewalk', '--no-pty', '--max-time', str(seconds),
            '--tools', tools, '--', prompt]


def parse_events(raw, requested):
    """Accept a complete event stream, not a partial assistant delta or exit code alone."""
    events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    if not events or any(not isinstance(e, dict) for e in events):
        raise ValueError('Invalid event stream')
    sessions = [e for e in events if e.get('type') == 'session']
    endings = [e for e in events if e.get('type') == 'agent_end']
    messages = [e.get('message', {}) for e in events if e.get('type') == 'message_end']
    assistant = [m for m in messages if m.get('role') == 'assistant']
    if len(sessions) != 1 or not sessions[0].get('id') or not endings or not assistant:
        raise ValueError('Missing session, terminal event or assistant message')
    if events[-1].get('type') != 'agent_end' or events[-1].get('isTerminal') is False:
        raise ValueError('Missing terminal completion of the final turn')
    if any(m.get('stopReason') in ('error', 'aborted', 'length') for m in assistant):
        raise ValueError('Model turn failed, aborted or was truncated')
    final = assistant[-1]
    if final.get('stopReason') != 'stop':
        raise ValueError('Final assistant message is not complete')
    provider, model = requested.split('/', 1)
    if any(m.get('provider') != provider or m.get('model') != model for m in assistant):
        raise ValueError('Runtime model differs from requested selector')
    from agy_runner import model_key
    if any(m.get('responseModel') and model_key(m['responseModel']) != model_key(model) for m in assistant):
        raise ValueError('Backend responseModel contradicts requested model')
    response = '\n'.join(c['text'] for c in final.get('content', []) if c.get('type') == 'text')
    return dict(status='SUCCESS', response=response, conversation_id=sessions[0]['id'],
                model=requested, usage=[m.get('usage') for m in assistant],
                reported_model=dict(provider=provider, model=model),
                response_models=sorted({m['responseModel'] for m in assistant if m.get('responseModel')}))
