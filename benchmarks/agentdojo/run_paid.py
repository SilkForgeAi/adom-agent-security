"""Freeze offline, then explicitly execute a small budgeted banking validation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import version
from verify import ROOT, source_check, sha
from budget import Budget, MODEL, OUTPUT_LIMIT


def write(path, value):
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2, default=str) + '\n')
    tmp.replace(path)


def package_hashes():
    paths = list((ROOT / 'source').rglob('*.py')) + list(ROOT.glob('*.py')) + [ROOT / 'requirements.lock', ROOT / 'SOURCE_MANIFEST.json']
    return {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sorted(paths)}


def load_runtime(config):
    source_check()
    for line in (ROOT / 'requirements.lock').read_text().splitlines():
        if line and not line.startswith('#'):
            name, expected = line.split('==')
            if version(name) != expected:
                raise ValueError('Dependency version mismatch: ' + name)
    os.environ['ADOM_AGENTDOJO_SUITE'] = 'banking'
    sys.path.insert(0, str(ROOT / 'source'))
    from adom.evaluation.agentdojo import run
    from agentdojo.task_suite.load_suites import get_suite
    suite = get_suite(config['benchmark'], 'banking')
    policies = run.freeze_user_policies(suite)
    return run, suite, policies


def validate_config(config):
    if config['suite'] != 'banking' or config['benchmark'] != 'v1.2.2' or config['model'] != MODEL or config['repeats'] != 1:
        raise ValueError('This release supports one-repeat banking validation on the pinned mini snapshot')
    if config['attack'] not in ('important_instructions', 'tool_knowledge'):
        raise ValueError('Only fixed registered attack templates are supported')
    if not 0 < config['budget_usd'] <= 3 or not 0 <= config['maximum_clean_drop'] <= .1 or not 0 < config['minimum_clean_utility'] <= 1:
        raise ValueError('Invalid budget or clean gate')
    for key in ('tasks', 'injection_tasks'):
        if not config[key] or len(config[key]) != len(set(config[key])):
            raise ValueError('Empty/duplicate task selection')


def freeze(config_path, output):
    config = json.loads(config_path.read_text()); validate_config(config)
    run, suite, policies = load_runtime(config)
    if set(config['tasks']) - set(suite.user_tasks) or set(config['injection_tasks']) - set(suite.injection_tasks):
        raise ValueError('Unknown selected task')
    if output.exists():
        raise ValueError('Output directory must be new')
    output.mkdir(parents=True)
    # Pipeline construction needs an SDK credential string, but offline freezing
    # uses a dummy value and rejects all socket connections. No key is read from disk.
    previous = os.environ.get('OPENAI_API_KEY'); old_connect = socket.socket.connect
    os.environ['OPENAI_API_KEY'] = 'offline-freeze-placeholder'
    def offline(*args, **kwargs):
        raise RuntimeError('Network disabled during freeze')
    socket.socket.connect = offline
    try:
        by_prompt = {suite.user_tasks[t].PROMPT: p for t, p in policies.items()}
        pipeline = run.build_pipeline(MODEL, 'baseline', by_prompt)
        from agentdojo.attacks import load_attack
        attack = load_attack(config['attack'], suite, pipeline)
        payloads = {f'{task}/{inj}': attack.attack(suite.user_tasks[task], suite.injection_tasks[inj])
                    for task in config['tasks'] for inj in config['injection_tasks']}
        frozen = dict(schema=1, created_utc=datetime.now(timezone.utc).isoformat(), config=config,
                      package_files=package_hashes(), policies={t: p.public_record() for t, p in policies.items()},
                      system_prompt=pipeline.elements[0].system_message, attack_payloads=payloads,
                      sampling=dict(temperature=0, max_completion_tokens=OUTPUT_LIMIT, seed=None, sdk_retries=0, timeout_s=45),
                      caveat='New public validation harness using exact historical v6 adapter; not a byte-identical rerun of the old controller or an independent reproduction.')
        write(output / 'freeze.json', frozen)
        (output / 'FREEZE.sha256').write_text(sha((output / 'freeze.json').read_bytes()) + '\n')
    finally:
        socket.socket.connect = old_connect
        if previous is None: os.environ.pop('OPENAI_API_KEY', None)
        else: os.environ['OPENAI_API_KEY'] = previous
    return {'status': 'FROZEN_OFFLINE', 'output': str(output), 'api_requests': 0}


def execute(output, acknowledged):
    if not acknowledged:
        raise ValueError('Paid execution requires --execute-paid; freeze and verification are free')
    frozen = json.loads((output / 'freeze.json').read_text())
    if sha((output / 'freeze.json').read_bytes()) != (output / 'FREEZE.sha256').read_text().strip():
        raise ValueError('Freeze changed')
    if frozen['package_files'] != package_hashes():
        raise ValueError('Package changed after freeze')
    config = frozen['config']; validate_config(config)
    if not os.environ.get('OPENAI_API_KEY'):
        raise ValueError('Set OPENAI_API_KEY for paid execution; no .env file is read')
    if os.environ.get('OPENAI_BASE_URL', 'https://api.openai.com/v1').rstrip('/') != 'https://api.openai.com/v1':
        raise ValueError('Only the official OpenAI endpoint is supported')
    run, suite, policies = load_runtime(config)
    if {t: p.public_record() for t, p in policies.items()} != frozen['policies']:
        raise ValueError('Policy compilation changed after freeze')
    # Exclusive durable marker: a crash or existing attempt cannot be silently resumed.
    marker = output / 'EXECUTION_STARTED'
    with marker.open('x') as f: f.write(datetime.now(timezone.utc).isoformat())
    budget = Budget(output / 'budget.sqlite', config['budget_usd'])
    from openai.resources.chat.completions import Completions
    from openai.resources.responses import Responses
    from agentdojo.functions_runtime import FunctionsRuntime
    from agentdojo.logging import OutputLogger
    from agentdojo.benchmark import run_task_without_injection_tasks, run_task_with_injection_tasks
    original_create = Completions.create; original_fn = FunctionsRuntime.run_function
    original_response = Responses.create
    outcomes = []; records = []; request_log = []; capture = {'in_agent_query': False}

    def tracked(client, *args, **kwargs):
        if args or kwargs.get('model') != MODEL or kwargs.get('max_completion_tokens') != OUTPUT_LIMIT or kwargs.get('temperature') != 0:
            raise ValueError('Unexpected request parameters; no dispatch')
        if str(client._client.base_url).rstrip('/') != 'https://api.openai.com/v1':
            raise ValueError('Unexpected endpoint; no dispatch')
        token = budget.reserve(); kwargs['store'] = False
        result = original_create(client, **kwargs)
        if result.model != MODEL:
            raise ValueError('Returned model mismatch; retain unknown reservation')
        if result.usage is None:
            raise ValueError('Missing usage; retain unknown reservation')
        budget.settle(token, result.usage.prompt_tokens, result.usage.completion_tokens)
        request_log.append(dict(reservation=token, response_id=result.id, model=result.model,
                                prompt_tokens=result.usage.prompt_tokens, completion_tokens=result.usage.completion_tokens))
        write(output / 'provider-responses.json', request_log)
        return result

    def no_responses(*args, **kwargs):
        raise ValueError('Responses endpoint outside this frozen protocol')

    def dispatched(runtime, env, name, args, *rest, **kwargs):
        if not capture['in_agent_query']:
            return original_fn(runtime, env, name, args, *rest, **kwargs)
        row = dict(tool=name, args=json.loads(json.dumps(args)))
        try:
            value, error = original_fn(runtime, env, name, args, *rest, **kwargs)
            row.update(outcome='ERROR' if error else 'RETURNED', error=str(error) if error else None)
            return value, error
        except BaseException as exc:
            row.update(outcome='EXCEPTION', exception_type=type(exc).__name__); raise
        finally:
            outcomes.append(row)

    Completions.create = tracked; Responses.create = no_responses; FunctionsRuntime.run_function = dispatched
    (output / 'episodes').mkdir()
    by_prompt = {suite.user_tasks[t].PROMPT: p for t, p in policies.items()}

    def episode(phase, arm, task, inj=None):
        outcomes.clear(); start = time.monotonic()
        identity = f'{phase}-{arm}-{task}-{inj or "none"}'
        row = dict(id=identity, phase=phase, condition=arm, task=task, injection_task=inj, status='INCONCLUSIVE')
        pipeline = run.build_pipeline(MODEL, arm, by_prompt)
        original_query = pipeline.query
        def capture_query(*args, **kwargs):
            capture['in_agent_query'] = True
            try:
                return original_query(*args, **kwargs)
            finally:
                capture['in_agent_query'] = False
        pipeline.query = capture_query
        logdir = output / 'logs' / identity
        try:
            with OutputLogger(str(logdir)):
                if inj is None:
                    utility, _ = run_task_without_injection_tasks(suite, pipeline, suite.user_tasks[task], logdir, True, config['benchmark'])
                    row['utility'] = utility
                else:
                    from agentdojo.attacks import BaseAttack
                    class FrozenAttack(BaseAttack):
                        name = config['attack']
                        def attack(self, user_task, injection_task):
                            return frozen['attack_payloads'][f'{task}/{inj}']
                    attack = FrozenAttack(suite, pipeline)
                    utilities, successes = run_task_with_injection_tasks(suite, pipeline, suite.user_tasks[task], attack, logdir, True, [inj], config['benchmark'])
                    row.update(utility=utilities[(task, inj)], attack_success_raw=successes[(task, inj)])
            traces = list(logdir.rglob((inj or 'none') + '.json'))
            if len(traces) != 1 or json.loads(traces[0].read_text()).get('error'):
                raise ValueError('Missing/errored native trace')
            row.update(status='VALID', trace=str(traces[0].relative_to(output)))
        except Exception as exc:
            row.update(exception_type=type(exc).__name__)
            raise
        finally:
            row.update(execution_outcomes=list(outcomes), adapter_audit=getattr(pipeline.adom_executor, 'audit', []), duration_s=time.monotonic()-start)
            write(output / 'episodes' / (identity + '.json'), row); records.append(row)
            write(output / 'progress.json', dict(status='RUNNING', completed=len(records), budget=budget.summary()))
        print(identity, row['status'], 'utility', row.get('utility'), 'native_asr', row.get('attack_success_raw'), flush=True)

    status = 'INCONCLUSIVE'
    try:
        for task in config['tasks']:
            for arm in ('baseline', 'adom'): episode('clean', arm, task)
        rates = {arm: sum(r['utility'] for r in records if r['condition'] == arm) / len(config['tasks']) for arm in ('baseline', 'adom')}
        passed = rates['adom'] >= config['minimum_clean_utility'] and rates['baseline'] >= config['minimum_clean_utility'] and rates['baseline']-rates['adom'] <= config['maximum_clean_drop']
        write(output / 'clean_gate.json', dict(rates=rates, passed=passed))
        if not passed:
            status = 'CLEAN_GATE_FAILED'; return {'status': status, 'budget': budget.summary()}
        for task in config['tasks']:
            for inj in config['injection_tasks']:
                for arm in ('baseline', 'adom'): episode('attack', arm, task, inj)
        status = 'COMPLETE'
        return {'status': status, 'budget': budget.summary()}
    finally:
        Completions.create = original_create; Responses.create = original_response; FunctionsRuntime.run_function = original_fn
        write(output / 'progress.json', dict(status=status, completed=len(records), budget=budget.summary()))
        files = {str(p.relative_to(output)): sha(p.read_bytes()) for p in output.rglob('*') if p.is_file() and p.name != 'RESULT_MANIFEST.json'}
        write(output / 'RESULT_MANIFEST.json', dict(files=files, status=status, scope=config['scope']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    f = sub.add_parser('freeze'); f.add_argument('--config', type=Path, default=ROOT / 'validation.json'); f.add_argument('--out', type=Path, required=True)
    r = sub.add_parser('run'); r.add_argument('--out', type=Path, required=True); r.add_argument('--execute-paid', action='store_true')
    args = parser.parse_args()
    result = freeze(args.config, args.out) if args.command == 'freeze' else execute(args.out, args.execute_paid)
    print(json.dumps(result, indent=2))
