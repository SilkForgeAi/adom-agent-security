#!/usr/bin/env python3
"""Turn ADOM's generated decK config into the smoke-test config.

Starts from exactly what `adom kong-guard --emit-deck` produces (the thing being tested) and
changes only what a local test needs:
  * the guardrail URL points at the capture proxy on the host (host.docker.internal)
  * ai-proxy-advanced sends model traffic to the local mock instead of api.openai.com
  * the MCP route is dropped (this run tests the LLM plane only)

usage: prepare_deck.py GUARDRAIL_PORT MOCK_LLM_PORT OUT_FILE
"""
import sys
from pathlib import Path

from adom.integrations.kong_guardrail import generate_deck_config

guard_port, mock_port, out = int(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3])
cfg = generate_deck_config(
    guardrail_url=f"http://host.docker.internal:{guard_port}/v1/kong/guardrail",
    llm_model="gpt-4o",
)

model_block = "                  model:\n                    provider: openai\n                    name: gpt-4o\n"
if cfg.count(model_block) != 1:
    sys.exit("prepare_deck: generated config changed shape (model block not found)")
cfg = cfg.replace(model_block, model_block + (
    "                    options:\n"
    f"                      upstream_url: http://host.docker.internal:{mock_port}/v1/chat/completions\n"))

mcp_marker = "\n  # Kong `ai-mcp-proxy` documents"
if cfg.count(mcp_marker) != 1:
    sys.exit("prepare_deck: generated config changed shape (MCP service not found)")
cfg = cfg[: cfg.index(mcp_marker)] + "\n"

out.write_text(cfg)
print(f"wrote {out}")
