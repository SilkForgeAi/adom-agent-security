"""Shared, bounded pre-execution checks. No untrusted object coercion or truncation."""
import math
from adom.api.model_proxy import ModelProxyPolicy, ProxyVerdict


def snapshot_args(obj, _depth=0, _budget=None):
    if _budget is None:
        _budget = [5000, 262144]
    if _depth > 40 or _budget[0] <= 0:
        raise ValueError("argument structure exceeds limit")
    _budget[0] -= 1
    typ = type(obj)
    if typ in (str, bytes):
        _budget[1] -= len(obj.encode("utf-8") if typ is str else obj)
        if _budget[1] < 0:
            raise ValueError("argument bytes exceed limit")
        return obj
    if obj is None or typ in (bool, int):
        if typ is int and obj.bit_length() > 256:
            raise ValueError("integer exceeds limit")
        return obj
    if typ is float:
        if not math.isfinite(obj):
            raise ValueError("non-finite argument")
        return obj
    if typ is dict:
        if any(type(k) is not str for k in obj):
            raise ValueError("argument keys must be strings")
        return {snapshot_args(k, _depth+1, _budget): snapshot_args(v, _depth+1, _budget)
                for k, v in obj.items()}
    if typ in (list, tuple):
        values = [snapshot_args(v, _depth+1, _budget) for v in obj]
        return tuple(values) if typ is tuple else values
    raise ValueError("unsupported argument type")


def screen_action(policy, name, args):
    """Return the private execution snapshot and the shared policy verdict."""
    try:
        if type(name) is not str or not name or len(name) > 256:
            raise ValueError("invalid tool name")
        frozen = snapshot_args(args)
        verdict = policy.score_tool_call(name, frozen)
        if verdict.action not in ("allow", "flag", "block"):
            raise ValueError("invalid policy verdict")
        return frozen, verdict
    except Exception:
        return None, ProxyVerdict(action="block", reason="action validation or policy failed",
                                  signals=["action_kernel:fail_closed"])


def default_policy():
    return ModelProxyPolicy(strict_deny_unknown=True)
