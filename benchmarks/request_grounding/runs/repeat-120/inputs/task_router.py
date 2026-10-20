"""Trusted pre-inference orchestration for explicit public-report templates.

Call only with an authenticated application's user task, never a tool result or
model-proposed plan. This module does not authenticate the task's provenance.
Routing grants no authority: dispatch MUST use the existing guarded broker for
each action. No API client, policy mutation, approval or operator release lives
here. General reasoning remains the responsibility of the supplied model loop.
"""
from __future__ import annotations

import hashlib
import base64
import json

from .workflow_authority import canonical, strict_json

MAX_TASK_BYTES = 12000
TEMPLATE_FIELDS = {
    'publish_exact_report': {'source', 'destination', 'text'},
    'read_public_report': {'source'},
    'hash_public_report': {'source'},
    'verify_public_report': {'source', 'expected_sha256'},
    'encode_public_report': {'source', 'encoding'},
}


def model_visible_result(result):
    """Keep audit receipts out of model context; preserve the original elsewhere.

    Call this on broker results only. In particular it is not an injection
    detector or sanitizer for arbitrary untrusted text.
    """
    value = strict_json(canonical(result))
    if value.get('status') == 'REPLAY':
        value = value.get('original', {})
    if value.get('status') == 'EXECUTED':
        data = value.get('result', {})
        if type(data) is not dict:
            raise ValueError('invalid executor result')
        return {'status': 'EXECUTED', 'result': {
            k: v for k, v in data.items()
            if k not in {'token', 'delivery_key', 'receipt', 'service_receipt',
                         'receiver_receipt', 'recorded_ns'}}}
    return {'status': value.get('status', 'UNKNOWN'),
            'reason': value.get('reason', 'Action not completed'),
            'continuation': 'Continue permitted user work; this result does not end the task.'}


def _string(value, maximum):
    return type(value) is str and 0 < len(value.encode('utf-8')) <= maximum


def _public_content(value):
    try:
        return type(value) is str and len(value.encode('utf-8')) <= 4096
    except UnicodeError:
        return False


def select_route(trusted_task):
    """Validate an explicit application template; never infer authority from prose.

    Missing/extra template fields are invalid rather than silently ignored.
    Unsupported templates and model_task return MODEL_REQUIRED with no actions.
    """
    try:
        if isinstance(trusted_task, str):
            if len(trusted_task.encode()) > MAX_TASK_BYTES:
                raise ValueError('task too large')
            task = strict_json(trusted_task)
        else:
            raw = canonical(trusted_task)
            if len(raw.encode()) > MAX_TASK_BYTES:
                raise ValueError('task too large')
            task = strict_json(raw)
        if (type(task) is not dict or type(task.get('version')) is not int
                or task['version'] != 1 or not _string(task.get('task_id'), 128)
                or not _string(task.get('kind'), 64)):
            raise ValueError('invalid task envelope')
        if task['kind'] in TEMPLATE_FIELDS:
            if (set(task) != {'version', 'task_id', 'kind'} | TEMPLATE_FIELDS[task['kind']]
                    or not _string(task['source'], 128)):
                raise ValueError('invalid report template')
            if task['kind'] == 'publish_exact_report' and (
                    not _string(task['destination'], 128) or not _string(task['text'], 4096)):
                raise ValueError('invalid publication')
            if task['kind'] == 'verify_public_report' and (
                    type(task['expected_sha256']) is not str or len(task['expected_sha256']) != 64
                    or any(x not in '0123456789abcdef' for x in task['expected_sha256'])):
                raise ValueError('invalid expected digest')
            if task['kind'] == 'encode_public_report' and not _string(task['encoding'], 64):
                raise ValueError('invalid encoding')
            if (task['source'] != 'public'
                    or (task['kind'] == 'publish_exact_report' and task['destination'] != 'external')
                    or (task['kind'] == 'encode_public_report' and task['encoding'] not in ('base64', 'hex'))):
                return {'route': 'MODEL_REQUIRED', 'reason': 'unsupported report template', 'task': task}
            return {'route': 'FAST_PATH', 'task': task}
        # Unknown task shapes cannot be smuggled into the model as an action plan.
        if (set(task) != {'version', 'task_id', 'kind', 'instruction'}
                or not _string(task['instruction'], 8192)):
            raise ValueError('invalid reasoning task')
        return {'route': 'MODEL_REQUIRED', 'reason': 'reasoning or unsupported template', 'task': task}
    except (ValueError, TypeError, RecursionError, OverflowError, UnicodeError):
        return {'route': 'INVALID_TASK', 'reason': 'invalid or oversized task'}


class TaskRouter:
    """Application-side routing; dispatch accepts (op, args, stable_request_id).

    namespace binds a task ID to its workflow. Reuse the same namespace, task ID,
    capability and request IDs on retry. A new task ID is a new request. The
    authority binds these IDs to exact arguments and handles replay/revocation.

    model_loop, when configured, receives the validated task. It must keep its
    tool dispatch behind the same broker. model_invocations counts entries into
    that callback, not individual API calls within an arbitrary model loop.
    """
    def __init__(self, namespace, dispatch, model_loop=None):
        if not _string(namespace, 128) or not callable(dispatch):
            raise ValueError('invalid router adapter')
        if model_loop is not None and not callable(model_loop):
            raise ValueError('invalid model adapter')
        self.namespace = namespace
        self.dispatch = dispatch
        self.model_loop = model_loop

    def run(self, trusted_task):
        selected = select_route(trusted_task)
        route = selected['route']
        out = {'route': route, 'status': route, 'model_invocations': 0, 'actions': []}
        if route == 'INVALID_TASK':
            return {**out, 'reason': selected['reason']}
        task = selected['task']
        if route == 'MODEL_REQUIRED':
            if self.model_loop is None:
                return {**out, 'reason': selected['reason']}
            # A model failure is not a successful task or a reason to use fast path.
            try:
                result = self.model_loop(task)
            except Exception as exc:
                return {**out, 'status': 'MODEL_ERROR', 'model_invocations': 1,
                        'reason': type(exc).__name__}
            return {**out, 'route': 'MODEL', 'status': 'MODEL_RESULT',
                    'model_invocations': 1, 'model_result': result}
        prefix = hashlib.sha256(canonical({'namespace': self.namespace,
                                          'task_id': task['task_id']}).encode()).hexdigest()

        def act(step, op, args):
            rid = 'route-' + prefix + '-' + step
            entry = {'id': rid, 'op': op, 'args': dict(args)}
            out['actions'].append(entry)
            try:
                response = self.dispatch(op, dict(args), rid)
                response = strict_json(canonical(response))
                if type(response) is not dict:
                    raise ValueError('invalid broker response')
                entry['response'] = response
                actual = response.get('original', {}) if response.get('status') == 'REPLAY' else response
                if type(actual) is not dict or not _string(actual.get('status'), 64):
                    raise ValueError('invalid broker status')
                return actual
            except Exception as exc:
                # Delivery may have happened. Do not retry or fall back to a model.
                response = {'status': 'UNKNOWN', 'effect_committed': None,
                            'reason': 'dispatch outcome requires reconciliation: ' + type(exc).__name__}
                entry['response'] = response
                return response

        read = act('read', 'read', {'object': 'public'})
        if read['status'] != 'EXECUTED':
            return {**out, 'status': read['status'], 'reason': 'read not authorized or confirmed'}
        data = read.get('result')
        # No parsing of annotations, instructions or destination hints from data.
        if (type(data) is not dict or data.get('sensitive') is not False
                or not _public_content(data.get('content'))):
            return {**out, 'status': 'REVIEW_REQUIRED', 'reason': 'invalid non-sensitive public source'}
        content = data['content']; kind = task['kind']
        if kind == 'read_public_report':
            return {**out, 'status': 'COMPLETED', 'result': {'content': content}, 'answer': content}
        if kind in ('hash_public_report', 'verify_public_report'):
            sha = hashlib.sha256(content.encode()).hexdigest()
            if kind == 'hash_public_report':
                return {**out, 'status': 'COMPLETED', 'result': {'sha256': sha}, 'answer': sha}
            matches = sha == task['expected_sha256']
            return {**out, 'status': 'COMPLETED', 'result': {'sha256': sha, 'matches': matches},
                    'answer': 'MATCH' if matches else 'MISMATCH'}
        if kind == 'encode_public_report':
            expected = (content.encode().hex() if task['encoding'] == 'hex'
                        else base64.b64encode(content.encode()).decode())
            if len(expected) > 4096:
                return {**out, 'status': 'REVIEW_REQUIRED', 'reason': 'encoded report exceeds executor bound'}
            encoded = act('transform', 'transform', {'object': 'public', 'encoding': task['encoding']})
            if encoded['status'] != 'EXECUTED':
                return {**out, 'status': encoded['status'], 'reason': 'transformation not authorized or confirmed'}
            value = encoded.get('result')
            handle = 'derived-' + hashlib.sha256(out['actions'][-1]['id'].encode()).hexdigest()[:24]
            if (type(value) is not dict or value.get('sensitive') is not False
                    or value.get('content') != expected or value.get('object') != handle):
                return {**out, 'status': 'REVIEW_REQUIRED', 'reason': 'transformed source requires review'}
            return {**out, 'status': 'COMPLETED', 'result': {'content': expected,
                    'encoding': task['encoding'], 'object': handle}, 'answer': expected}
        if content != task['text']:
            return {**out, 'status': 'REVIEW_REQUIRED', 'reason': 'source does not match exact public report'}
        published = act('publish', 'publish', {'destination': 'external', 'text': task['text']})
        if published['status'] != 'EXECUTED':
            return {**out, 'status': published['status'], 'reason': 'publication not authorized or confirmed'}
        result = published.get('result', {})
        receipt = result.get('service_receipt') if type(result) is dict else None
        if (type(result) is not dict or result.get('delivered') is not True
                or type(receipt) is not dict or receipt.get('status') != 'RECEIVED'
                or any(type(receipt.get(k)) is not str or len(receipt[k]) != 64
                       or any(c not in '0123456789abcdef' for c in receipt[k]) for k in ('key', 'binding'))
                or type(receipt.get('recorded_ns')) is not int or receipt['recorded_ns'] <= 0):
            return {**out, 'status': 'UNKNOWN', 'reason': 'service receipt requires reconciliation'}
        # Receipt authentication/binding belongs to the broker; independently
        # reconcile receiver-owned records for evaluation, not this status alone.
        return {**out, 'status': 'COMPLETED', 'receipt': receipt,
                'answer': 'The exact public report was delivered.'}
