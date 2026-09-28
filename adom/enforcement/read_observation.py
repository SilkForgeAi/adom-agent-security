"""Trusted exact read_file result adapter. Observe before exposing output to the agent.

Custom tools/result types must supply their own trusted observation adapter. Read labels
cannot be taken from agent-controlled arguments. Unknown result shapes latch policy closed.
"""
from adom.enforcement.action_kernel import snapshot_args

def observe_result(policy, name, args, result):
    if name != 'read_file':
        return result
    try:
        result = snapshot_args(result)
        if type(result) is str:
            content = result
        elif type(result) is dict and type(result.get('content')) is str:
            content = result['content']
        else:
            raise ValueError('unsupported read_file result schema')
        path = args.get('path') if isinstance(args, dict) else None
        policy.note_read(content, path=path if type(path) is str else None)
        return result
    except Exception:
        policy._observation_failed = True
        raise RuntimeError('Read observation failed; session requires trusted recovery') from None
