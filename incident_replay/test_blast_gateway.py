import unittest

from adom.api.model_proxy import ModelProxyPolicy
from adom.enforcement.blast_radius import Budget, BlastRadiusController, OPEN
from adom.enforcement.mediated_gateway import MediatedAgentGateway


class BlastRadiusGatewayTests(unittest.TestCase):
    def test_repeated_denials_open_circuit_before_executor(self):
        executed = []
        policy = ModelProxyPolicy(
            allowed_tools=("read_task",),
            strict_deny_unknown=True,
            block_mode=True,
        )
        blast = BlastRadiusController(
            default_budget=Budget(max_actions=10, max_failures=2, window_seconds=300),
            cooldown_seconds=300,
        )
        gateway = MediatedAgentGateway(
            policy,
            executor=lambda name, args: executed.append((name, args)) or "ok",
            blast_radius=blast,
            agent_id="test-agent",
        )

        self.assertTrue(gateway.run_tool("read_task", {}).permitted)
        first = gateway.run_tool("cache_post", {"message": "one"})
        second = gateway.run_tool("cache_post", {"message": "two"})
        contained = gateway.run_tool("read_task", {})

        self.assertFalse(first.permitted)
        self.assertFalse(second.permitted)
        self.assertEqual(blast.state_of("test-agent"), OPEN)
        self.assertIn("blast:state:open", second.signals)
        self.assertFalse(contained.permitted)
        self.assertEqual(contained.plane, "blast_radius")
        self.assertIn("blast:execution_suppressed", contained.signals)
        self.assertEqual([name for name, _ in executed], ["read_task"])

    def test_gateway_preserves_explicit_agent_budget(self):
        policy = ModelProxyPolicy(allowed_tools=("read_task",), strict_deny_unknown=True)
        blast = BlastRadiusController(default_budget=Budget(max_actions=10, max_failures=10))
        blast.register("tight-agent", Budget(max_actions=1, max_failures=10))
        gateway = MediatedAgentGateway(
            policy,
            executor=lambda _name, _args: "ok",
            blast_radius=blast,
            agent_id="tight-agent",
        )
        self.assertTrue(gateway.run_tool("read_task", {}).permitted)
        self.assertFalse(gateway.run_tool("read_task", {}).permitted)


if __name__ == "__main__":
    unittest.main()
