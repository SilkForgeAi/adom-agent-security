"""ADOM as a defense inside AutoDojo's AgentDojo fork.

Load it with the fork's plugin variable, then select it like any defense:

    AGENTDOJO_DEFENSE_PLUGINS=adom.evaluation.agentdojo.autodojo_plugin \\
        python -m agentdojo.scripts.benchmark --defense adom ...

The fork's `register_defense` places an element after the stock ToolsExecutor,
which is after the tools have already run. ADOM has to decide before a call
runs, so for `adom` this module builds the pipeline itself with
AdomToolsExecutor in place of ToolsExecutor, the same way the fork wires
Progent. The fork's files are not modified.

Not parallel-safe: the executor keeps per-episode provenance state, so `adom`
is not added to PARALLEL_EVAL_SAFE_DEFENSES.
"""
from __future__ import annotations

import json
from functools import partial
from pathlib import Path

import agentdojo.agent_pipeline.agent_pipeline as fork
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, tool_result_to_str
from agentdojo.task_suite.load_suites import get_suite

from adom.evaluation.agentdojo.executor import AdomToolsExecutor
from adom.evaluation.agentdojo.measure import BENCHMARK_VERSION, check_frozen, freeze_user_policies

NAME = "adom"
ROOT = Path(__file__).resolve().parents[3]
FREEZES = ROOT / "runs" / "agentdojo"

# Suites with a frozen policy compiler. The blind suites are added only after
# their policies are authored and frozen under the pre-registration.
COMPILERS = {"banking": freeze_user_policies}


def frozen_policies_by_prompt(suite_name: str) -> dict:
    if suite_name not in COMPILERS:
        raise SystemExit(f"ADOM has no frozen policy for suite '{suite_name}'.")
    suite = get_suite(BENCHMARK_VERSION, suite_name)
    policies = COMPILERS[suite_name](suite)
    check_frozen(policies, FREEZES / suite_name / "policies.json")
    return {suite.user_tasks[task_id].PROMPT: policy for task_id, policy in policies.items()}


def build_pipeline(config):
    if not config.suite_name:
        raise ValueError("The adom defense needs PipelineConfig.suite_name to load frozen policies.")
    llm = fork.get_llm(config.llm) if isinstance(config.llm, str) else config.llm
    llm_name = config.llm if isinstance(config.llm, str) else llm.name
    if config.model_id is not None:
        llm_name = config.model_id.replace("/", "_")
    formatter = tool_result_to_str
    if config.tool_output_format == "json":
        formatter = partial(tool_result_to_str, dump_fn=json.dumps)
    executor = AdomToolsExecutor(frozen_policies_by_prompt(config.suite_name), formatter)
    loop = ToolsExecutionLoop([executor, llm], max_input_tokens=config.max_input_tokens)
    pipeline = fork.AgentPipeline([SystemMessage(config.system_message), InitQuery(), llm, loop])
    pipeline.name = f"{llm_name}/{NAME}"
    pipeline.adom_executor = executor
    return pipeline


def _placement_guard(config):
    raise RuntimeError("adom is built by build_pipeline, never as a post-execution filter")


_original_from_config = fork.AgentPipeline.from_config.__func__


def _from_config(cls, config):
    if config.defense == NAME:
        return build_pipeline(config)
    return _original_from_config(cls, config)


if not getattr(fork.AgentPipeline, "_adom_wrapped", False):
    fork.register_defense(NAME, _placement_guard)
    fork.AgentPipeline.from_config = classmethod(_from_config)
    fork.AgentPipeline._adom_wrapped = True
