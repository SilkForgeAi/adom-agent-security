"""Recompute historical banking native scores from recorded dispatches, offline."""
import argparse
import copy
import json
import socket
from pathlib import Path
from importlib.metadata import version
from verify import ROOT, read_evidence, verify


def offline_only(*args, **kwargs):
    raise RuntimeError('Network access is prohibited during offline rescoring')


def rescore(directory):
    verify(directory)
    if version('agentdojo') != '0.1.35':
        raise ValueError('Install the pinned requirements.lock')
    socket.socket.connect = offline_only
    socket.create_connection = offline_only
    from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.task_suite.task_suite import model_output_from_messages, functions_stack_trace_from_messages
    manifest, files = read_evidence(directory)
    suite = get_suite('v1.2.2', 'banking')
    checked = 0
    for name, episode in files.items():
        if not name.startswith('episodes/'):
            continue
        if episode['status'] != 'VALID':
            raise ValueError('Historical rescorer requires complete valid episodes')
        native = next(v for n, v in files.items() if n.startswith(f'logs/{episode["phase"]}/r1-{episode["condition"]}/')
                      and n.endswith(f'/banking/{episode["task"]}/{episode.get("attack") or "none"}/{episode.get("injection_task") or "none"}.json'))
        task = suite.user_tasks[episode['task']]
        env = task.init_environment(suite.load_and_inject_default_environment(native['injections']))
        pre = env.model_copy(deep=True)
        runtime = FunctionsRuntime(suite.tools)
        # The historical global runtime hook also captured checker/reference
        # calls. Use the executor-owned audit for ADOM and actual tool-result
        # messages for baseline, never that contaminated dispatch list.
        if episode['condition'] == 'adom':
            dispatches = [dict(tool=r['tool'], args=r.get('dispatch_args', r['args']), outcome=r['outcome'])
                          for r in episode['adapter_audit'] if r.get('event') == 'tool'
                          and r.get('allowed') and r.get('outcome') in ('RETURNED', 'ERROR', 'EXCEPTION')]
        else:
            dispatches = [dict(tool=m['tool_call']['function'], args=m['tool_call']['args'],
                               outcome='ERROR' if m.get('error') else 'RETURNED')
                          for m in native['messages'] if m['role'] == 'tool']
        for call in dispatches:
            if call['outcome'] not in ('RETURNED', 'ERROR'):
                raise ValueError('Cannot faithfully replay exception outcome: ' + episode['id'])
            _, error = runtime.run_function(env, call['tool'], copy.deepcopy(call['args']))
            if bool(error) != (call['outcome'] == 'ERROR'):
                raise ValueError('Recorded/replayed dispatch outcome mismatch: ' + episode['id'])
        messages = copy.deepcopy(native['messages'])
        for msg in messages:
            if msg['role'] == 'assistant':
                msg['tool_calls'] = [FunctionCall.model_validate(c) for c in msg.get('tool_calls') or []]
            elif msg['role'] == 'tool':
                msg['tool_call'] = FunctionCall.model_validate(msg['tool_call'])
        output = model_output_from_messages(messages) or []
        calls = functions_stack_trace_from_messages(messages)
        utility = suite._check_task_result(task, output, pre, env, calls)
        if utility != native['utility']:
            raise ValueError('Recomputed utility mismatch: ' + episode['id'])
        if episode['phase'] == 'attack':
            security = suite._check_task_result(suite.injection_tasks[episode['injection_task']], output, pre, env, calls)
            if security != native['security']:
                raise ValueError('Recomputed native ASR mismatch: ' + episode['id'])
        checked += 1
    return {'status': 'OFFLINE_NATIVE_SCORES_RECOMPUTED', 'episodes': checked, 'api_requests': 0,
            'scope': 'Replay of author-recorded dispatched actions against synthetic banking fixtures and native checkers; not new model responses or independent provider evidence.'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('evidence', nargs='?', type=Path, default=ROOT / 'evidence/banking-v6')
    print(json.dumps(rescore(p.parse_args().evidence), indent=2))
