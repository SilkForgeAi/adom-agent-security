import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import run_paid


@unittest.skipUnless(importlib.util.find_spec('agentdojo'), 'Install requirements.lock for runtime checks')
class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / 'run'
        self.network = patch.object(socket.socket, 'connect', side_effect=AssertionError('No network permitted in tests'))
        self.network.start(); self.addCleanup(self.network.stop)
        run_paid.freeze(ROOT / 'validation.json', self.output)

    def test_freeze_needs_no_real_key_and_records_identical_payloads(self):
        frozen = json.loads((self.output / 'freeze.json').read_text())
        self.assertEqual(len(frozen['attack_payloads']), 4)
        self.assertTrue(frozen['system_prompt'])
        with self.assertRaises(ValueError): run_paid.execute(self.output, False)

    def test_modified_freeze_rejected_before_dispatch(self):
        with (self.output / 'freeze.json').open('a') as f: f.write(' ')
        with self.assertRaisesRegex(ValueError, 'Freeze changed'): run_paid.execute(self.output, True)

    def test_budget_exhaustion_prevents_provider_dispatch(self):
        from openai.resources.chat.completions import Completions
        from budget import BudgetExceeded
        config = json.loads((ROOT / 'validation.json').read_text()); config['budget_usd'] = .01
        config_path = Path(self.temp.name) / 'small-budget.json'; config_path.write_text(json.dumps(config))
        output = Path(self.temp.name) / 'small-budget'; run_paid.freeze(config_path, output)
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'offline-test-placeholder', 'OPENAI_BASE_URL': 'https://api.openai.com/v1'}), patch.object(Completions, 'create') as provider:
            with self.assertRaises(BudgetExceeded): run_paid.execute(output, True)
            provider.assert_not_called()
        progress = json.loads((output / 'progress.json').read_text())
        self.assertEqual(progress['status'], 'INCONCLUSIVE')
        self.assertEqual(progress['budget']['requests'], 0)

    def test_failed_clean_gate_prevents_attacks(self):
        from openai.resources.chat.completions import Completions
        from openai.types.chat import ChatCompletion
        def fixture(client, **kwargs):
            self.assertEqual(client._client.max_retries, 0)
            return ChatCompletion.model_validate(dict(id='fixture-response', model=run_paid.MODEL, object='chat.completion', created=0,
                choices=[dict(index=0, finish_reason='stop', message=dict(role='assistant', content='Fixture response.'))],
                usage=dict(prompt_tokens=100, completion_tokens=20, total_tokens=120)))
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'offline-test-placeholder', 'OPENAI_BASE_URL': 'https://api.openai.com/v1'}), patch.object(Completions, 'create', fixture):
            result = run_paid.execute(self.output, True)
        self.assertEqual(result['status'], 'CLEAN_GATE_FAILED')
        records = [json.loads(p.read_text()) for p in (self.output / 'episodes').glob('*.json')]
        self.assertEqual(len(records), 4)
        self.assertTrue(all(r['phase'] == 'clean' for r in records))
        from verify_run import verify_run
        self.assertEqual(verify_run(self.output)['status'], 'CLEAN_GATE_FAILED')
        with self.assertRaises(FileExistsError):
            with patch.dict(os.environ, {'OPENAI_API_KEY': 'offline-test-placeholder'}): run_paid.execute(self.output, True)

    def test_transport_failure_retains_reservation_and_inconclusive_record(self):
        from openai.resources.chat.completions import Completions
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'offline-test-placeholder', 'OPENAI_BASE_URL': 'https://api.openai.com/v1'}), patch.object(Completions, 'create', side_effect=TimeoutError('fixture')):
            with self.assertRaises(TimeoutError): run_paid.execute(self.output, True)
        progress = json.loads((self.output / 'progress.json').read_text())
        self.assertEqual(progress['status'], 'INCONCLUSIVE')
        self.assertGreater(progress['budget']['unknown_reserved_usd'], 0)
        row = json.loads(next((self.output / 'episodes').glob('*.json')).read_text())
        self.assertEqual(row['status'], 'INCONCLUSIVE')

    def test_complete_fixture_run_records_only_agent_dispatches(self):
        from openai.resources.chat.completions import Completions
        from openai.types.chat import ChatCompletion
        from agentdojo.task_suite.load_suites import get_suite
        suite = get_suite('v1.2.2', 'banking')
        by_prompt = {t.PROMPT: t for t in suite.user_tasks.values()}
        def fixture(client, **kwargs):
            user = next(m for m in kwargs['messages'] if m['role'] == 'user')
            prompt = ''.join(c['text'] for c in user['content'])
            task = by_prompt[prompt]
            message = dict(role='assistant', content='Fixture completion.')
            if not any(m['role'] == 'tool' for m in kwargs['messages']):
                calls = task.ground_truth(suite.load_and_inject_default_environment({}))
                message['tool_calls'] = [dict(id=f'fixture-{i}', type='function', function=dict(name=c.function, arguments=json.dumps(c.args))) for i, c in enumerate(calls)]
            return ChatCompletion.model_validate(dict(id='fixture-response', model=run_paid.MODEL, object='chat.completion', created=0,
                choices=[dict(index=0, finish_reason='tool_calls' if message.get('tool_calls') else 'stop', message=message)],
                usage=dict(prompt_tokens=100, completion_tokens=20, total_tokens=120)))
        # This is a fixture integration test, not an evaluated model result.
        config = json.loads((ROOT / 'validation.json').read_text()); config['minimum_clean_utility'] = .01
        config_path = Path(self.temp.name) / 'fixture-config.json'; config_path.write_text(json.dumps(config))
        output = Path(self.temp.name) / 'fixture-run'; run_paid.freeze(config_path, output)
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'offline-test-placeholder', 'OPENAI_BASE_URL': 'https://api.openai.com/v1'}), patch.object(Completions, 'create', fixture):
            result = run_paid.execute(output, True)
        self.assertEqual(result['status'], 'COMPLETE')
        episodes = [json.loads(p.read_text()) for p in (output / 'episodes').glob('*.json')]
        self.assertEqual(len(episodes), 12)
        from verify_run import verify_run
        self.assertEqual(verify_run(output)['status'], 'COMPLETE')
        for episode in episodes:
            native = json.loads((output / episode['trace']).read_text())
            if episode['condition'] == 'baseline':
                actual = [m for m in native['messages'] if m['role'] == 'tool']
            else:
                actual = [r for r in episode['adapter_audit'] if r.get('event') == 'tool' and r.get('allowed') and r.get('outcome') in ('RETURNED', 'ERROR')]
            self.assertEqual(len(episode['execution_outcomes']), len(actual), episode['id'])


if __name__ == '__main__':
    unittest.main()
