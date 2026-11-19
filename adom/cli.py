#!/usr/bin/env python3
"""Unified CLI entry point for ADOM agent enforcement."""
from __future__ import annotations

import argparse
import signal
import sys
import time
from pathlib import Path
from typing import List, Optional


def _cmd_hook(argv: List[str]) -> int:
    from cursor_hook import adom_agent_hook

    return adom_agent_hook.main(argv)


def _cmd_mcp_stdio(argv: List[str]) -> int:
    from adom.integrations import mcp_gateway

    return mcp_gateway.main(argv)


def _cmd_mcp_http(argv: List[str]) -> int:
    from adom.integrations.mcp_http_proxy import McpHttpProxyServer

    ap = argparse.ArgumentParser(prog="adom mcp-http")
    ap.add_argument("--name", required=True, help="Logical server name (e.g. notes)")
    ap.add_argument("--upstream", required=True, help="Upstream HTTP(S) JSON-RPC MCP endpoint")
    ap.add_argument("--bind", default="127.0.0.1", help="Local listen host (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8765, help="Local listen port (default: 8765)")
    ap.add_argument("--registry", type=Path, default=None, help="Path to tool_tiers.json")
    ap.add_argument("--mode", choices=("enforce", "observe"), default="enforce")
    ap.add_argument("--client-prompts-confirmed", action="store_true")
    ap.add_argument("--allow-loopback", action="store_true")
    ap.add_argument("--timeout", type=float, default=10.0)
    opts = ap.parse_args(argv)

    srv = McpHttpProxyServer(
        opts.upstream,
        opts.name,
        registry_path=opts.registry,
        client_prompts_confirmed=opts.client_prompts_confirmed,
        mode=opts.mode,
        allow_loopback=opts.allow_loopback,
        bind_host=opts.bind,
        bind_port=opts.port,
        timeout=opts.timeout,
    )
    srv.start()
    print(f"ADOM MCP HTTP proxy ({opts.mode}) listening on {srv.url} -> {opts.upstream}", flush=True)
    stop = False

    def _handle_sig(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)
    try:
        while not stop:
            time.sleep(0.25)
    finally:
        srv.close()
    return 0


def _cmd_verify_chain(argv: List[str]) -> int:
    from adom.enforcement.audit_chain import load_key, read_anchor, verify_chain

    ap = argparse.ArgumentParser(prog="adom verify-chain")
    ap.add_argument("log_path", type=Path, help="Path to hash-chained JSONL audit log")
    ap.add_argument("--key-file", type=Path, default=None, help="Optional HMAC key file")
    ap.add_argument("--anchor", type=Path, default=None, help="Optional COUNT:HASH anchor file")
    opts = ap.parse_args(argv)

    key = load_key(opts.key_file) if opts.key_file else None
    head = read_anchor(opts.anchor) if opts.anchor else None
    ok, msg = verify_chain(opts.log_path, key=key, expected_head=head)
    print(msg)
    return 0 if ok else 1


def _cmd_bench(_argv: List[str]) -> int:
    from benchmarks.latency_and_encoding.run import main as bench_main

    return bench_main()


def _cmd_kong_guard(argv: List[str]) -> int:
    from adom.enforcement.audit_chain import load_key
    from adom.integrations.kong_guardrail import (
        KongGuardrailEngine,
        KongGuardrailServer,
        generate_deck_config,
    )

    ap = argparse.ArgumentParser(prog="adom kong-guard")
    ap.add_argument("--bind", default="127.0.0.1", help="Listen host (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8780, help="Listen port (default: 8780)")
    ap.add_argument("--allowed-tool", action="append", default=[], help="Grant an exact tool name (repeatable)")
    ap.add_argument("--approved-outbound", action="append", default=[], help="Allowlist an outbound host/domain (repeatable)")
    ap.add_argument("--audit-log", type=Path, default=None, help="Path to hash-chained JSONL audit log")
    ap.add_argument("--audit-key-file", type=Path, default=None, help="Optional HMAC key file for ChainLog")
    ap.add_argument("--emit-deck", action="store_true", help="Print Kong decK (_format_version 3.0) YAML and exit")
    opts = ap.parse_args(argv)

    guardrail_url = f"http://{opts.bind}:{opts.port}/v1/kong/guardrail"
    if opts.emit_deck:
        print(generate_deck_config(guardrail_url=guardrail_url), end="")
        return 0

    audit_path = opts.audit_log or (Path.home() / ".adom" / "kong" / "decisions.jsonl")
    # Always fail closed on unknown tools. An empty --allowed-tool list means deny every
    # tool call (operators must grant exact names). Previously deny-unknown was gated on
    # whether any --allowed-tool was passed, so the README quickstart ran fail-open.
    engine = KongGuardrailEngine(
        allowed_tools=opts.allowed_tool,
        approved_outbound=opts.approved_outbound,
        strict_deny_unknown=True,
        audit_log_path=audit_path,
        audit_key=load_key(opts.audit_key_file) if opts.audit_key_file else None,
    )
    srv = KongGuardrailServer(engine, bind_host=opts.bind, bind_port=opts.port)
    srv.start()
    print(f"ADOM Kong guardrail service listening on {srv.guardrail_url}", flush=True)
    stop = False

    def _handle_sig(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)
    try:
        while not stop:
            time.sleep(0.25)
    finally:
        srv.close()
    return 0


def _cmd_inspect_policy(argv: List[str]) -> int:
    from adom.integrations.inspect_approver import generate_inspect_policy_yaml

    ap = argparse.ArgumentParser(prog="adom inspect-policy")
    ap.add_argument(
        "--mode",
        choices=("enforce", "control_prefilter", "observe"),
        default="enforce",
        help="Approval mode: enforce (standalone), control_prefilter (Stage-1 before LLM/human monitor), or observe",
    )
    ap.add_argument("--allowed-tool", action="append", default=[], help="Grant an exact tool name (repeatable)")
    ap.add_argument("--approved-outbound", action="append", default=[], help="Allowlist an outbound host/domain (repeatable)")
    ap.add_argument("--downstream-approver", default="human", help="Stage-2 approver when mode=control_prefilter")
    ap.add_argument("--audit-log", default="~/.adom/inspect/decisions.jsonl", help="Audit ChainLog path")
    opts = ap.parse_args(argv)

    tools = tuple(opts.allowed_tool) if opts.allowed_tool else ("read_file", "search_docs", "http_post")
    hosts = tuple(opts.approved_outbound) if opts.approved_outbound else ("api.internal.example",)
    print(
        generate_inspect_policy_yaml(
            mode=opts.mode,
            allowed_tools=tools,
            approved_outbound=hosts,
            downstream_approver=opts.downstream_approver,
            audit_log_path=opts.audit_log,
        ),
        end="",
    )
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="adom",
        description="ADOM assume-breach enforcement CLI (coding-agent hooks, MCP proxies, Kong AI Gateway guardrail, UK AISI Inspect approver, audit verification).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hook", help="Run fail-closed coding-agent hook (cursor|claude-code|codex|github-copilot)", add_help=False)
    sub.add_parser("mcp-stdio", help="Run fail-closed stdio MCP gateway", add_help=False)
    sub.add_parser("mcp-http", help="Run SSRF-pinned HTTP MCP JSON-RPC proxy", add_help=False)
    sub.add_parser("kong-guard", help="Run HTTP guardrail backend for Kong AI Gateway (ai-custom-guardrail)", add_help=False)
    sub.add_parser("inspect-policy", help="Emit UK AISI Inspect (inspect_ai) approval policy YAML", add_help=False)
    sub.add_parser("verify-chain", help="Verify tamper-evident JSONL audit chain", add_help=False)
    sub.add_parser("bench", help="Run deterministic latency & multi-encoding exfiltration benchmark", add_help=False)

    ns, rest = parser.parse_known_args(args)
    dispatch = {
        "hook": _cmd_hook,
        "mcp-stdio": _cmd_mcp_stdio,
        "mcp-http": _cmd_mcp_http,
        "kong-guard": _cmd_kong_guard,
        "inspect-policy": _cmd_inspect_policy,
        "verify-chain": _cmd_verify_chain,
        "bench": _cmd_bench,
    }
    return dispatch[ns.cmd](rest)


if __name__ == "__main__":
    raise SystemExit(main())
