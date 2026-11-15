"""
ADOM framework/SDK tool guards (#5).

Auto-intercept tool calls inside the stacks people actually run agents in — WITHOUT
requiring any of those frameworks to be installed. Everything here is duck-typed and
lazy: importing this module pulls in zero third-party packages.

One tested core, `guard_callable`, screens a tool's name + arguments through ADOM's
policy and BLOCKS a risky call before the underlying function ever runs. Thin shims
adapt it to each framework's calling convention:

    guard_callable(fn, name=..., policy=...)     # any plain function tool
    guarded_function_tool(policy=...)            # decorator (OpenAI Agents SDK style)
    guard_langchain_tool(tool, policy=...)       # LangChain Tool / StructuredTool / BaseTool
    guard_llamaindex_tool(tool, policy=...)      # LlamaIndex FunctionTool
    guard_mcp_handler(handler, policy=...)       # MCP tool-dispatch handler(name, arguments)

The policy is the same ModelProxyPolicy used by the inline API proxy — so a tool named
send_email carrying a secret, transfer_funds, delete_file, or exec_command is blocked
identically whether it arrives via the model API, an SDK, or MCP.
"""
from __future__ import annotations

from typing import Any, Callable, Optional
from dataclasses import replace
from adom.enforcement.read_observation import observe_result
import inspect

from adom.api.model_proxy import ModelProxyPolicy, ProxyVerdict
from adom.enforcement.action_kernel import snapshot_args, screen_action, default_policy


class ToolBlocked(Exception):
    """Raised (in raise-on-block mode) when ADOM refuses a tool call."""
    def __init__(self, name: str, reason: str, signals):
        super().__init__(f"ADOM blocked tool '{name}': {reason}")
        self.tool = name
        self.reason = reason
        self.signals = list(signals or [])


def _call_args(args, kwargs) -> Any:
    if kwargs and not args:
        return kwargs
    if len(args) == 1 and isinstance(args[0], dict) and not kwargs:
        return args[0]
    return {"positional": list(args), "keyword": kwargs}


def guard_callable(fn: Callable, name: Optional[str] = None,
                   policy: Optional[ModelProxyPolicy] = None,
                   on_decision: Optional[Callable[[str, ProxyVerdict], None]] = None,
                   raise_on_block: bool = True,
                   block_message: Optional[str] = None) -> Callable:
    """Wrap a tool function so ADOM screens every call before it executes."""
    tool_name = name or getattr(fn, "__name__", "tool")
    pol = policy or default_policy()

    def wrapped(*args, **kwargs):
        try:
            args, kwargs = snapshot_args((args, kwargs))
            _, verdict = screen_action(pol, tool_name, _call_args(args, kwargs))
        except Exception:
            verdict = ProxyVerdict(action="block", reason="invalid tool arguments")
        if on_decision:
            try: on_decision(tool_name, replace(verdict, signals=list(verdict.signals)))
            except Exception: pass
        if verdict.action == "block":
            if raise_on_block:
                raise ToolBlocked(tool_name, verdict.reason, verdict.signals)
            return block_message or f"[ADOM blocked tool '{tool_name}': {verdict.reason}. Not executed.]"
        result = fn(*args, **kwargs)
        if inspect.isawaitable(result):
            async def observed():
                return observe_result(pol, tool_name, _call_args(args, kwargs), await result)
            return observed()
        return observe_result(pol, tool_name, _call_args(args, kwargs), result)

    if inspect.iscoroutinefunction(fn):
        synchronous_check = wrapped
        async def async_wrapped(*args, **kwargs):
            result = synchronous_check(*args, **kwargs)
            return await result if inspect.isawaitable(result) else result
        wrapped = async_wrapped
    wrapped.__name__ = tool_name
    wrapped.__doc__ = getattr(fn, "__doc__", None)
    wrapped.__adom_guarded__ = True
    wrapped.__wrapped__ = fn
    return wrapped


def guarded_function_tool(policy: Optional[ModelProxyPolicy] = None,
                          on_decision: Optional[Callable] = None,
                          raise_on_block: bool = True):
    """Decorator for plain function tools (OpenAI Agents SDK @function_tool style).

    Apply ADOM first, then the SDK's own decorator:
        @function_tool
        @guarded_function_tool(policy=pol)
        def send_email(to, body): ...
    """
    def deco(fn):
        return guard_callable(fn, getattr(fn, "__name__", "tool"),
                              policy, on_decision, raise_on_block)
    return deco


def guard_langchain_tool(tool, policy: Optional[ModelProxyPolicy] = None,
                         on_decision: Optional[Callable] = None):
    """Wrap a LangChain Tool / StructuredTool / BaseTool in place; returns the tool."""
    name = getattr(tool, "name", None) or getattr(tool, "__name__", "tool")
    found = False
    for attribute in ("func", "coroutine", "_run", "_arun"):
        original = getattr(tool, attribute, None)
        if callable(original):
            setattr(tool, attribute, guard_callable(original, name, policy, on_decision))
            found = True
    if not found:
        raise TypeError("unrecognized LangChain tool")
    return tool


def guard_llamaindex_tool(tool, policy: Optional[ModelProxyPolicy] = None,
                          on_decision: Optional[Callable] = None):
    """Wrap a LlamaIndex FunctionTool in place; returns the tool."""
    meta = getattr(tool, "metadata", None)
    name = getattr(meta, "name", None) or getattr(tool, "__name__", "tool")
    for attr in ("fn", "_fn"):
        if hasattr(tool, attr) and callable(getattr(tool, attr)):
            setattr(tool, attr, guard_callable(getattr(tool, attr), name, policy, on_decision))
            return tool
    raise TypeError("unrecognized LlamaIndex tool (no .fn/._fn)")


def guard_mcp_handler(handler: Callable, policy: Optional[ModelProxyPolicy] = None,
                      on_decision: Optional[Callable] = None):
    """Wrap an MCP tool-dispatch handler: handler(name, arguments) -> result.

    A blocked call returns a structured error instead of executing the tool.
    """
    pol = policy or default_policy()

    def wrapped(name, arguments=None, *a, **k):
        if a or k:
            return {"isError": True, "error": "Unscreened MCP dispatch arguments are not allowed"}
        arguments, verdict = screen_action(pol, name, arguments if arguments is not None else {})
        if on_decision:
            try: on_decision(name, replace(verdict, signals=list(verdict.signals)))
            except Exception: pass
        if verdict.action == "block":
            return {"isError": True,
                    "error": f"ADOM blocked tool '{name}': {verdict.reason}. Not executed.",
                    "signals": verdict.signals}
        result = handler(name, arguments, *a, **k)
        if inspect.isawaitable(result):
            async def observed():
                return observe_result(pol, name, arguments, await result)
            return observed()
        return observe_result(pol, name, arguments, result)

    wrapped.__adom_guarded__ = True
    return wrapped


def _resolve_handoff_agent(item: Any) -> Any:
    """Return the downstream Agent referenced by a handoff object, if resolvable."""
    ref = getattr(item, "_agent_ref", None)
    if callable(ref):
        return ref()
    if ref is not None:
        return ref
    return getattr(item, "agent", None) or item


def guard_openai_agent(agent: Any, policy: Optional[ModelProxyPolicy] = None,
                       on_decision: Optional[Callable] = None,
                       raise_on_block: bool = True,
                       _visited: Optional[set] = None) -> Any:
    """Recursively bind shared ADOM tool-boundary screening across an OpenAI Agents SDK
    agent and all reachable ``handoffs``.

    Closes the destination-agent ``input_guardrails`` skip on ``NextStepHandoff`` by
    enforcing ADOM screening and cross-turn taint tracking directly at every ``FunctionTool``
    invocation boundary.
    """
    import json as _json

    pol = policy or default_policy()
    seen = _visited if _visited is not None else set()
    if id(agent) in seen:
        return agent
    seen.add(id(agent))

    for tool in getattr(agent, "tools", ()) or ():
        orig_invoke = getattr(tool, "on_invoke_tool", None)
        if not callable(orig_invoke) or getattr(orig_invoke, "__adom_guarded__", False):
            continue
        tname = getattr(tool, "name", "tool")

        async def _guarded_invoke(ctx: Any, input_json: str = "", *a: Any,
                                  _orig=orig_invoke, _tname=tname, **k: Any) -> Any:
            if a or k:
                raise ToolBlocked(_tname, "unscreened OpenAI tool arguments are not allowed",
                                  ["tool_guard:unscreened_args"])
            if isinstance(input_json, str) and input_json.strip():
                try:
                    parsed = _json.loads(input_json)
                except ValueError:
                    parsed = {"raw": input_json}
            elif isinstance(input_json, dict):
                parsed = input_json
            else:
                parsed = {}
            _, verdict = screen_action(pol, _tname, parsed if parsed is not None else {})
            if on_decision:
                try:
                    on_decision(_tname, replace(verdict, signals=list(verdict.signals)))
                except Exception:
                    pass
            if verdict.action == "block":
                if raise_on_block:
                    raise ToolBlocked(_tname, verdict.reason, verdict.signals)
                return f"ADOM blocked tool '{_tname}': {verdict.reason}. Not executed."
            res = _orig(ctx, input_json)
            if inspect.isawaitable(res):
                res = await res
            return observe_result(pol, _tname, parsed, res)

        _guarded_invoke.__adom_guarded__ = True  # type: ignore[attr-defined]
        object.__setattr__(tool, "on_invoke_tool", _guarded_invoke)

    for hop in getattr(agent, "handoffs", ()) or ():
        target = _resolve_handoff_agent(hop)
        if target is not None and hasattr(target, "tools"):
            guard_openai_agent(target, pol, on_decision, raise_on_block, seen)

    return agent


if __name__ == "__main__":
    pol = ModelProxyPolicy(taint_values=["sk-live-DEADBEEF"])

    @guarded_function_tool(policy=pol, raise_on_block=False)
    def send_email(to, body):
        return f"SENT to {to}"

    print(send_email("ops@corp.com", "status ok"))               # allowed
    print(send_email("evil@x.com", "key sk-live-DEADBEEF"))      # blocked, not sent
