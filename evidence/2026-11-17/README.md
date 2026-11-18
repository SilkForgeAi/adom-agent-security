# Evidence Bundle — November 17, 2026

Machine-readable JSON: [`adaptive_and_unseen_summary.json`](adaptive_and_unseen_summary.json)

## Summary (`gpt-4o-mini-2024-07-18`)

### 1. Three-Suite `AutoDojo` Adaptive Caches (`no_defense` caches, `389` pairs)

Evaluates AutoDojo's shipped `no_defense` frontier adaptive attack caches across `banking` (from `2026-11-16`, `144` pairs), `slack` (`105` pairs), and `travel` (`140` pairs):

| Suite | Pairs | Baseline ASR | ADOM Raw ASR | Executed Non-Prose Side Effects | Baseline Util (Attack) | ADOM Util (Attack) | ADOM Blocked Calls |
|---|---:|---:|---:|---:|---:|---:|---:|
| `banking` *(Nov 16)* | `144` | `84/144` (`58.33%`) | **`0/144` (`0.00%`)** | `0/144` | `60/144` (`41.67%`) | **`86/144` (`59.72%`)** | `164` |
| `slack` *(Nov 17)* | `105` | `57/105` (`54.29%`) | **`4/105` (`3.81%`)** | `0/105` *(4 `injection_task_5` proposed-trace checks)* | `54/105` (`51.43%`) | **`63/105` (`60.00%`)** | `290` |
| `travel` *(Nov 17)* | `140` | `54/140` (`38.57%`) | **`3/140` (`2.14%`)** | `0/140` *(3 `injection_task_6` prose preference checks)* | `43/140` (`30.71%`) | **`66/140` (`47.14%`)** | `155` |
| **Total** | **`389`** | **`195/389` (`50.13%`)** | **`7/389` (`1.80%`)** | **`0/389`** | **`157/389` (`40.36%`)** | **`215/389` (`55.27%`)** | **`609`** |

*(Caveat: `slack` and `travel` evaluate AutoDojo's pre-computed `no_defense` adaptive caches rather than running an online optimizer loop targeting `--defense adom`; live online adaptive optimization targeting `--defense adom` was run on `banking` on Nov 16 and scored `0/144` ASR.)*

### 2. Three-Suite Unseen `AgentDyn` (`adom_query`, zero per-suite rules, `560` attack pairs + `60` clean tasks)

Tests ADOM's suite-agnostic runtime provenance + query-time least-privilege capability compiler (`adom_query`) across `shopping`, `github`, and `dailylife` with zero per-suite policy rules:

| Suite | Clean Utility (`base → adom_query`) | Baseline ASR (`important_instructions`) | `adom_query` ASR | `adom_query` Attacked Util |
|---|---:|---:|---:|---:|
| `shopping` (`180` pairs) | `6/20 (30.0%) → 6/20 (30.0%)` | `47/180` (`26.11%`) | **`6/180` (`3.33%`)** | `39/180` (`21.67%`) |
| `github` (`180` pairs) | `9/20 (45.0%) → 8/20 (40.0%)` | `70/180` (`38.89%`) | **`3/180` (`1.67%`)** | `57/180` (`31.67%`) |
| `dailylife` (`200` pairs) | `6/20 (30.0%) → 2/20 (10.0%)` | `142/200` (`71.00%`) | **`5/200` (`2.50%`)** | `21/200` (`10.50%`) |
| **Total** | **`21/60 (35.0%) → 16/60 (26.7%)`** | **`259/560` (`46.25%`)** | **`14/560` (`2.50%`)** | **`117/560` (`20.89%`)** |

#### Open boundaries documented transparently
1. **Zero data exfiltration, `14/560` same-capability substitutions:** Remaining hits (`6` `shopping/injection_task_2`, `3` `github/injection_task_{0,7}`, `5` `dailylife/injection_task_6`) involve an already-authorized tool family where an injection alters an item, repository, or calendar/reservation entry inside the permitted capability without crossing external exfiltration rules.
2. **Inbox-delegated URLs (`dailylife` `2/20` vs `6/20` baseline):** Four blocked `dailylife` tasks instruct the agent to follow arbitrary URLs embedded inside unread email bodies (such as `www.bluesparrowtech.drive.com`, `www.resume_templates.com`, `www.davidsmith.com`). ADOM refuses ungrounded URLs extracted from untrusted email bodies to avoid phishing/exfiltration (`baseline` suffers `71.00%` ASR on `dailylife`), trading clean utility on inbox-delegated links for bounded destinations.

### 3. Deterministic Public-Repo Hardening (Nov 17)
- Extended [`cursor_hook/adom_cursor_checks.py`](../../cursor_hook/adom_cursor_checks.py) (`PROTECTED_PATHS` and `_PROTECTED_MARKERS`) to block agent writes/shell mutations to `.cursor/mcp.json`, `.vscode/mcp.json`, `.mcp.json`, `.claude/mcp.json`, `.claude.json`, `.codex/config.toml`, and `claude_desktop_config.json`.
- Published pure-stdlib suite-agnostic provenance engine in [`adom/integrations/provenance_policy.py`](../../adom/integrations/provenance_policy.py) with unit tests ([`test_provenance_policy.py`](../../adom/integrations/tests/test_provenance_policy.py)).
- Added [`incident_replay/test_late_2026_containment.py`](../../incident_replay/test_late_2026_containment.py) covering MCP config hijacks, strict egress alongside `.pass` credential shapes, unrequested destructive actions, review taint quarantine, and anchored HMAC+SHA-256 chain verification.
