"""End-to-end tests for the ADOM MCP gateway.  Run:  python3 adom/integrations/tests/test_mcp_gateway.py

A real gateway process sits between this test (the "client") and a real fake MCP server
process. What reached the server is read from the server's own effects file, never from
ADOM's verdict, so a test cannot pass because ADOM merely claimed to block something.
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))
from adom.integrations import mcp_gateway as G  # noqa: E402

SERVER = [sys.executable, str(HERE / "fake_mcp_server.py")]
SECRET = "Zq7Lm2Rx9Tv4Wp8K"


class Client:
    def __init__(self, registry=None, mode="enforce", extra=()):
        self.dir = Path(tempfile.mkdtemp(prefix="adom_mcpgw_"))
        self.effects = self.dir / "effects.jsonl"
        self.reg = self.dir / "tool_tiers.json"
        self.log = self.dir / "gw.jsonl"
        if registry is not None:
            self.reg.write_text(registry if isinstance(registry, str) else json.dumps(registry))
        env = dict(os.environ, HOME=str(self.dir), FAKE_MCP_EFFECTS=str(self.effects))
        self.p = subprocess.Popen(
            [sys.executable, "-m", "adom.integrations.mcp_gateway", "--name", "notes",
             "--mode", mode, "--registry", str(self.reg), "--log", str(self.log), *extra,
             "--", *SERVER],
            cwd=str(ROOT), env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        self._id = 0
        self._responses = {}
        self._cv = threading.Condition()
        threading.Thread(target=self._read, daemon=True).start()
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "t", "version": "1"}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _read(self):
        for line in self.p.stdout:
            msg = json.loads(line)
            with self._cv:
                for m in (msg if isinstance(msg, list) else [msg]):
                    self._responses[m.get("id")] = m
                self._cv.notify_all()

    def send(self, obj):
        self.p.stdin.write((json.dumps(obj) + "\n").encode())
        self.p.stdin.flush()

    def request(self, method, params=None, timeout=20):
        self._id += 1
        mid = self._id
        self.send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
        return self.wait(mid, timeout)

    def wait(self, mid, timeout=20):
        with self._cv:
            ok = self._cv.wait_for(lambda: mid in self._responses, timeout)
        if not ok:
            raise AssertionError(f"no response to id {mid}")
        return self._responses.pop(mid)

    def call(self, tool, args=None):
        return self.request("tools/call", {"name": tool, "arguments": args or {}})

    def reached(self):
        if not self.effects.exists():
            return []
        return [json.loads(l)["tool"] for l in self.effects.read_text().splitlines()]

    def records(self):
        return [json.loads(l) for l in self.log.read_text().splitlines()]

    def last_call_record(self):
        return [r for r in self.records() if r.get("event") == "tools/call"][-1]

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        self.p.wait(timeout=15)
        for f in (self.p.stdout, self.p.stderr):
            try:
                f.close()
            except OSError:
                pass


def denied(resp):
    r = resp.get("result") or {}
    return r.get("isError") is True and "ADOM blocked" in r["content"][0]["text"]


REG = {"version": 1, "tools": {
    "mcp__notes__get_note": {"tier": "observe"},
    "mcp__notes__read_secret": {"tier": "observe"},
    "mcp__notes__read_untrusted": {"tier": "observe"},
    "mcp__notes__save_note": {"tier": "local_write"},
    "mcp__notes__send_message": {"tier": "consequential", "approved_outbound": ["team.example.com"],
                                 "agent_approval": True},
}}


class Gateway(unittest.TestCase):
    def tearDown(self):
        c = getattr(self, "c", None)
        if c:
            c.close()

    def test_unknown_tool_denied_never_reaches_server(self):
        self.c = Client(registry=None)
        self.c.request("tools/list")
        r = self.c.call("frobnicate", {"x": 1})
        self.assertTrue(denied(r), r)
        self.assertIn("unclassified MCP tool", r["result"]["content"][0]["text"])
        self.assertEqual(self.c.reached(), [])
        rec = self.c.last_call_record()
        self.assertEqual((rec["tool"], rec["tier"], rec["returned"]),
                         ("mcp__notes__frobnicate", "unknown", "denied"))
        self.assertEqual(rec["proposed_tier"], "consequential")

    def test_tools_list_and_other_methods_pass_through(self):
        self.c = Client(registry=REG)
        r = self.c.request("tools/list")
        self.assertEqual(len(r["result"]["tools"]), 7)
        self.assertEqual(self.c.request("ping")["result"], {})
        self.assertIn("error", self.c.request("resources/list"))

    def test_granted_read_is_forwarded(self):
        self.c = Client(registry=REG)
        r = self.c.call("get_note", {"id": "1"})
        self.assertFalse(r["result"].get("isError"))
        self.assertIn("Shopping list", r["result"]["content"][0]["text"])
        self.assertEqual(self.c.reached(), ["get_note"])

    def test_local_write_forwarded(self):
        self.c = Client(registry=REG)
        self.assertFalse(self.c.call("save_note", {"text": "buy milk"})["result"].get("isError"))
        self.assertEqual(self.c.reached(), ["save_note"])

    def test_credential_path_in_any_argument_denied(self):
        self.c = Client(registry=REG)
        for args in ({"uri": "file:///Users/x/.ssh/id_rsa"}, {"files": ["a.txt", "~/.aws/credentials"]}):
            self.assertTrue(denied(self.c.call("get_note", args)), args)
        self.assertEqual(self.c.reached(), [])

    def test_consequential_needs_confirmed_prompt(self):
        self.c = Client(registry=REG)
        r = self.c.call("send_message", {"url": "https://team.example.com/in", "body": "hi"})
        self.assertTrue(denied(r))
        self.assertIn("cannot confirm the client shows an approval prompt", r["result"]["content"][0]["text"])
        self.assertEqual(self.c.reached(), [])

    def test_consequential_with_confirmed_prompt(self):
        self.c = Client(registry=REG, extra=("--client-prompts-confirmed",))
        ok = self.c.call("send_message", {"url": "https://team.example.com/in", "body": "status ok"})
        self.assertFalse(ok["result"].get("isError"), ok)
        rec = self.c.last_call_record()
        self.assertEqual(rec["operator_statement"], "client approval prompts confirmed by operator")
        # hard kernel rules still apply: unapproved destination, credential-shaped value
        self.assertTrue(denied(self.c.call("send_message", {"url": "https://evil.example/x", "body": "hi"})))
        self.assertTrue(denied(self.c.call("send_message", {"url": "https://team.example.com/in",
                                                             "body": "AKIAQQQQQQQQQQQQQQQQ"})))
        self.assertEqual(self.c.reached(), ["send_message"])

    def test_without_opt_in_kernel_review_blocks(self):
        reg = json.loads(json.dumps(REG))
        reg["tools"]["mcp__notes__send_message"].pop("agent_approval")
        self.c = Client(registry=reg, extra=("--client-prompts-confirmed",))
        r = self.c.call("send_message", {"url": "https://team.example.com/in", "body": "hi"})
        self.assertTrue(denied(r))
        self.assertIn("Exact trusted approval required", r["result"]["content"][0]["text"])

    def test_read_then_send_secret_across_tools_is_caught(self):
        self.c = Client(registry=REG, extra=("--client-prompts-confirmed",))
        self.assertIn(SECRET, self.c.call("read_secret")["result"]["content"][0]["text"])
        r = self.c.call("send_message", {"url": "https://team.example.com/in", "body": "fyi " + SECRET})
        self.assertTrue(denied(r), r)
        self.assertEqual(self.c.reached(), ["read_secret"])
        # control: same body in a fresh session that never read the secret is not refused
        self.c.close()
        self.c = Client(registry=REG, extra=("--client-prompts-confirmed",))
        self.assertFalse(self.c.call("send_message", {"url": "https://team.example.com/in",
                                                      "body": "fyi " + SECRET})["result"].get("isError"))

    def test_hints_only_raise(self):
        reg = {"version": 1, "tools": {"mcp__notes__send_message": {"tier": "observe"}}}
        self.c = Client(registry=reg)
        self.c.request("tools/list")                 # server says openWorldHint: true
        self.c.call("send_message", {"url": "https://team.example.com/in", "body": "AKIAQQQQQQQQQQQQQQQQ"})
        rec = self.c.last_call_record()
        self.assertEqual(rec["tier"], "consequential")
        self.assertIn("tool declares openWorldHint", rec["tier_reasons"])
        self.assertEqual(self.c.reached(), [])

    def test_malformed_registry_denies_everything(self):
        self.c = Client(registry="{oops")
        r = self.c.call("get_note")
        self.assertTrue(denied(r))
        self.assertIn("registry unreadable", r["result"]["content"][0]["text"])
        self.assertEqual(self.c.reached(), [])

    def test_observe_mode_forwards_and_records(self):
        self.c = Client(registry=None, mode="observe")
        r = self.c.call("frobnicate")
        self.assertFalse(r["result"].get("isError"))
        rec = self.c.last_call_record()
        self.assertEqual((rec["adom_verdict"], rec["returned"]), ("block", "forwarded"))
        self.assertEqual(self.c.reached(), ["frobnicate"])

    def test_batch_elements_decided_individually(self):
        self.c = Client(registry=REG)
        self.c.send([{"jsonrpc": "2.0", "id": 900, "method": "tools/call",
                      "params": {"name": "get_note", "arguments": {}}},
                     {"jsonrpc": "2.0", "id": 901, "method": "tools/call",
                      "params": {"name": "frobnicate", "arguments": {}}}])
        self.assertTrue(denied(self.c.wait(901)))
        self.assertFalse(self.c.wait(900)["result"].get("isError"))
        self.assertEqual(self.c.reached(), ["get_note"])

    def test_malformed_and_nameless_calls(self):
        self.c = Client(registry=REG)
        self.c.p.stdin.write(b"{not json\n")
        self.c.p.stdin.flush()
        self.assertEqual(self.c.wait(None)["error"]["code"], -32700)
        self.assertTrue(denied(self.c.request("tools/call", {"arguments": {}})))
        self.assertEqual(self.c.reached(), [])

    def test_server_exit_fails_pending_requests(self):
        self.c = Client(registry={"version": 1, "tools": {"mcp__notes__crash": {"tier": "observe"}}})
        r = self.c.call("crash")
        self.assertEqual(r["error"]["message"], "upstream MCP server exited")

    def test_log_chain_valid_and_tamper_evident(self):
        self.c = Client(registry=REG)
        self.c.call("get_note")
        self.c.call("frobnicate")
        self.c.call("get_note")       # so the denial is a MIDDLE record (an unkeyed chain
        self.c.close()                # cannot reveal a truncated tail: record the head elsewhere)
        ok, why = G.verify_chain(self.c.log)
        self.assertTrue(ok, why)
        lines = self.c.log.read_text().splitlines()
        rec = json.loads(lines[2]); rec["adom_verdict"] = "allow"; lines[2] = json.dumps(rec, sort_keys=True)
        self.c.log.write_text("\n".join(lines) + "\n")
        self.assertFalse(G.verify_chain(self.c.log)[0])
        self.assertEqual(json.loads(lines[2])["tool"], "mcp__notes__frobnicate")   # the denial
        self.c.log.write_text("\n".join(lines[:2] + lines[3:]) + "\n")            # delete it
        self.assertFalse(G.verify_chain(self.c.log)[0])
        self.c = None


class DeciderUnit(unittest.TestCase):
    def test_observation_failure_poisons_session(self):
        d = tempfile.mkdtemp()
        reg = Path(d) / "r.json"
        reg.write_text(json.dumps(REG))
        gw = G.Gateway(SERVER, "notes", registry_path=reg, log_path=Path(d) / "l.jsonl")
        gw.decider.observe = lambda *a: (_ for _ in ()).throw(RuntimeError("boom"))
        gw._pending[1] = ("tools/call", "get_note")
        gw._handle_server_message({"jsonrpc": "2.0", "id": 1, "result": {"content": []}})
        self.assertEqual(gw.decider.decide("get_note", {})["verdict"], "block")

    def test_internal_error_fails_closed(self):
        d = tempfile.mkdtemp()
        out = []
        gw = G.Gateway(SERVER, "notes", log_path=Path(d) / "l.jsonl")
        gw._to_client = out.append
        gw.decider.decide = lambda *a: (_ for _ in ()).throw(RuntimeError("boom"))
        fwd = gw._handle_client_message({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                                         "params": {"name": "get_note", "arguments": {}}})
        self.assertIsNone(fwd)
        self.assertTrue(denied(out[0]))


if __name__ == "__main__":
    unittest.main(verbosity=1)
