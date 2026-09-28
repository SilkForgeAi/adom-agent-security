import tempfile
import unittest
from pathlib import Path

import replay
import verify


class IncidentReplayTests(unittest.TestCase):
    def test_counterfactual_outcomes(self):
        off = replay.run("unprotected")["summary"]
        on = replay.run("adom")["summary"]
        self.assertTrue(off["sandbox_loss_injected"])
        self.assertTrue(on["sandbox_loss_injected"])
        self.assertTrue(off["scorer_fooled"])
        self.assertTrue(off["target_compromised"])
        self.assertTrue(off["solution_database_read"])
        self.assertFalse(on["scorer_fooled"])
        self.assertFalse(on["target_compromised"])
        self.assertFalse(on["solution_database_read"])
        self.assertEqual(on["prohibited_effect_count"], 0)
        self.assertGreaterEqual(on["legitimate_tasks_completed"], 2)

    def test_ledger_detects_tampering(self):
        result = replay.run("adom")
        ok, _ = verify.verify_chain(result["entries"])
        self.assertTrue(ok)
        result["entries"][0]["effect_detail"] = "forged"
        ok, _ = verify.verify_chain(result["entries"])
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
