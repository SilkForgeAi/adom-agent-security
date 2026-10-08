import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import verify
from budget import Budget, BudgetExceeded, WORST_REQUEST_NANOUSD


class EvidenceTests(unittest.TestCase):
    def test_complete_historical_bank_records(self):
        result = verify.verify(ROOT / 'evidence/banking-v6')
        self.assertEqual(result['episodes'], 320)
        self.assertFalse(result['clean_gate_passed'])
        self.assertEqual(result['tables']['baseline']['attack']['raw_attack_successes'], 87)
        self.assertEqual(result['tables']['adom']['attack']['raw_attack_successes'], 0)

    def changed_archive(self, change):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        target = Path(temp.name)
        source = ROOT / 'evidence/banking-v6'
        manifest = json.loads((source / 'manifest.json').read_text())
        with zipfile.ZipFile(source / 'records.zip') as z:
            members = {n: z.read(n) for n in z.namelist()}
        change(members)
        with zipfile.ZipFile(target / 'records.zip', 'w') as z:
            for name, data in members.items(): z.writestr(name, data)
        # Recompute transport hashes so semantic checks, rather than only checksums, are exercised.
        manifest['archive_sha256'] = verify.sha((target / 'records.zip').read_bytes())
        manifest['files'] = {n: verify.sha(data) for n, data in members.items()}
        (target / 'manifest.json').write_text(json.dumps(manifest))
        return target

    def test_missing_episode_rejected_even_with_new_archive_hash(self):
        def change(members): del members[next(n for n in members if n.startswith('episodes/'))]
        with self.assertRaisesRegex(ValueError, 'episodes'):
            verify.verify(self.changed_archive(change))

    def test_record_trace_score_disagreement_rejected(self):
        def change(members):
            name = next(n for n in members if n.startswith('episodes/'))
            record = json.loads(members[name]); record['utility'] = not record['utility']
            members[name] = json.dumps(record).encode()
        with self.assertRaisesRegex(ValueError, 'utility mismatch'):
            verify.verify(self.changed_archive(change))

    def test_archive_bytes_tampered(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp); source = ROOT / 'evidence/banking-v6'
            (target / 'manifest.json').write_bytes((source / 'manifest.json').read_bytes())
            (target / 'records.zip').write_bytes((source / 'records.zip').read_bytes() + b'changed')
            with self.assertRaisesRegex(ValueError, 'Archive hash'):
                verify.verify(target)


class BudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'budget.sqlite'

    def test_unknown_outcome_keeps_full_reservation(self):
        budget = Budget(self.path, .03); budget.reserve()
        with self.assertRaises(BudgetExceeded): budget.reserve()
        self.assertEqual(budget.summary()['unknown_reserved_usd'], WORST_REQUEST_NANOUSD / 1e9)

    def test_returned_usage_releases_unused_reservation(self):
        budget = Budget(self.path, .03); token = budget.reserve(); budget.settle(token, 100, 20)
        budget.reserve()
        self.assertEqual(budget.summary()['requests'], 2)

    def test_restart_cannot_restore_budget(self):
        Budget(self.path, .03).reserve()
        with self.assertRaises(BudgetExceeded): Budget(self.path, .03).reserve()
        with self.assertRaises(ValueError): Budget(self.path, .04)

    def test_duplicate_or_invalid_settlement_rejected(self):
        budget = Budget(self.path, .03); token = budget.reserve()
        with self.assertRaises(ValueError): budget.settle(token, -1, 0)
        budget.settle(token, 100, 20)
        with self.assertRaises(ValueError): budget.settle(token, 100, 20)

    def test_concurrent_reservations_cannot_overspend(self):
        from concurrent.futures import ThreadPoolExecutor
        budget = Budget(self.path, .03)
        def attempt(_):
            try: budget.reserve(); return True
            except BudgetExceeded: return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(attempt, range(2))), 1)


if __name__ == '__main__':
    unittest.main()
