"""ADOM inside AutoDojo's fork. Offline: a scripted model, no API calls.

Run with the fork installed (.venv-autodojo):
    AGENTDOJO_DEFENSE_PLUGINS=adom.evaluation.agentdojo.autodojo_plugin \\
        python -m unittest adom.evaluation.agentdojo.test_autodojo_plugin
"""
from __future__ import annotations

import os
import unittest

os.environ.setdefault("AGENTDOJO_DEFENSE_PLUGINS", "adom.evaluation.agentdojo.autodojo_plugin")

import agentdojo.agent_pipeline.agent_pipeline as fork  # noqa: E402
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement  # noqa: E402
from agentdojo.attacks import load_attack  # noqa: E402
from agentdojo.functions_runtime import FunctionCall  # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.types import ChatAssistantMessage, text_content_block_from_string  # noqa: E402

from adom.evaluation.agentdojo import autodojo_plugin  # noqa: E402
from adom.evaluation.agentdojo.executor import AdomToolsExecutor  # noqa: E402

ATTACKER = "US133000000121212121212"


class ScriptedLLM(BasePipelineElement):
    """Obeys the injection: pays the attacker, then answers."""

    name = "gpt-4o-mini-2024-07-18"

    def query(self, query, runtime, env, messages, extra_args):
        sent = any(m["role"] == "tool" for m in messages)
        if not sent:
            call = FunctionCall(
                function="send_money",
                args={"recipient": ATTACKER, "amount": 100.0, "subject": "x", "date": "2022-01-01"},
                id="c1",
            )
            reply = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string("")],
                                         tool_calls=[call])
        else:
            reply = ChatAssistantMessage(role="assistant", content=[text_content_block_from_string("done")],
                                         tool_calls=None)
        return query, runtime, env, [*messages, reply], extra_args


def config(defense, suite_name="banking"):
    return fork.PipelineConfig(llm=ScriptedLLM(), model_id=None, defense=defense, suite_name=suite_name,
                               system_message_name=None, system_message=None)


class AutoDojoPluginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = get_suite("v1.2.2", "banking")

    def test_registered_and_not_parallel_safe(self):
        self.assertIn("adom", fork.DEFENSES)
        self.assertNotIn("adom", fork.PARALLEL_EVAL_SAFE_DEFENSES)

    def test_adom_executor_replaces_stock_executor(self):
        pipeline = fork.AgentPipeline.from_config(config("adom"))
        loop = pipeline.elements[-1]
        self.assertIsInstance(loop.elements[0], AdomToolsExecutor)
        self.assertEqual(pipeline.name, "gpt-4o-mini-2024-07-18/adom")

    def test_other_defenses_untouched(self):
        pipeline = fork.AgentPipeline.from_config(config(None))
        self.assertEqual(pipeline.name, "gpt-4o-mini-2024-07-18/no_defense")
        self.assertNotIsInstance(pipeline.elements[-1].elements[0], AdomToolsExecutor)

    def test_suite_without_frozen_policy_refuses(self):
        with self.assertRaises(SystemExit):
            fork.AgentPipeline.from_config(config("adom", suite_name="slack"))

    def test_attacker_payment_blocked_before_it_runs(self):
        user_task = self.suite.user_tasks["user_task_0"]
        inj_task = self.suite.injection_tasks["injection_task_5"]
        results = {}
        for defense in (None, "adom"):
            pipeline = fork.AgentPipeline.from_config(config(defense))
            attack = load_attack("important_instructions", self.suite, pipeline)
            _utility, security = self.suite.run_task_with_pipeline(
                pipeline, user_task, inj_task, attack.attack(user_task, inj_task))
            results[defense] = security
        self.assertTrue(results[None], "scripted attacker payment should succeed undefended")
        self.assertFalse(results["adom"])


if __name__ == "__main__":
    unittest.main()
