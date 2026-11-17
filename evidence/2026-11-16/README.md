# Hash-Pinned AutoDojo Adaptive Attack & Unseen AgentDyn Summary — November 16, 2026

Machine-readable author summary of two follow-on evaluations on `gpt-4o-mini-2024-07-18` stored in [`adaptive_and_unseen_summary.json`](adaptive_and_unseen_summary.json):

## 1. AutoDojo Adaptive Black-Box Attack (`banking`, `144` pairs)

Evaluated ADOM (`FrozenTaskPolicy` contracts) against AutoDojo (`optimize_variants.py` with a frontier `gpt-4o-2024-11-20` iterative black-box optimizer across `36/36` `(injection_task, vector)` cells × `3` iterations + `static-bare`, `important-instructions-wrapper`, `rlhammer`, and `topicattack` seeds):

- **Live AutoDojo optimization targeting `--defense adom`:** ADOM **`0/144` (`0.00%`) ASR**, **`82/144` (`56.94%`)** utility under attack (`50` blocked calls); baseline `8/144` (`5.56%`) ASR, `67/144` (`46.53%`) utility under attack on that ADOM-optimized cache.
- **AutoDojo shipped `no_defense` adaptive cache (`gpt-4o-mini`):** Baseline **`84/144` (`58.33%`) ASR**, `60/144` (`41.67%`) utility under attack → ADOM **`0/144` (`0.00%`) ASR**, **`86/144` (`59.72%`)** utility under attack (`164` blocked calls).
- **Scope:** Adaptive runs cover `banking` (`144` pairs); adaptive sweeps for `slack`, `travel`, and `workspace` remain future runs.

## 2. Unseen AgentDyn Suites (`github`, `shopping`, `dailylife`, zero per-suite rules)

Tested two zero-suite-fitting architectures built purely from user prompts and tool schemas (no hand-authored per-suite compilers):
- **`adom_generic` (`generic_policy.py`, `$0` LLM cost):** pure deterministic prompt-verb + atomic-provenance rule.
- **`adom_query` (`query_policy.py`):** 1 query-time `gpt-4o-2024-11-20` JSON capability manifest per prompt before any tool executes + deterministic `ModelProxyPolicy` / `GenericLedger` enforcement.

### Clean utility (`60` unseen tasks)
- **`shopping` (`20` tasks):** baseline `3/20` (`15.0%`) | `adom_generic` `0/20` (`0.0%`) | **`adom_query` `7/20` (`35.0%`)**
- **`github` (`20` tasks):** baseline **`10/20` (`50.0%`)** | `adom_generic` `0/20` (`0.0%`) | `adom_query` `1/20` (`5.0%`)
- **`dailylife` (`20` tasks):** baseline **`9/20` (`45.0%`)** | `adom_generic` `0/20` (`0.0%`) | `adom_query` `1/20` (`5.0%`)

### Live attack run on `shopping` (`important_instructions`, `180` pairs)
- **Baseline:** **`43/180` (`23.89%` ASR)**, `52/180` (`28.89%`) utility under attack.
- **`adom_query`:** **`6/180` (`3.33%` ASR)**, `43/180` (`23.89%`) utility under attack. All `6` hits were product substitutions using the user-requested `cart_add_product` / `checkout_selected_cart` capability (`0` unrequested `send_money`, `send_email`, `update_shopping_account_password`, or `delete_node` calls executed).

## Open Research Frontier (Documented Weak Spots)
1. **Unseen multi-step clean utility (`github` `1/20`, `dailylife` `1/20`, `adom_generic` `0/60`):** Without suite-specific rules or pre-execution discovery of required session actions, query-time compilation often omits implicit prerequisites (`download_file_through_id`, paired 2FA `verify_github_account`, web-form `input_to_webpage`), and strict atomic provenance blocks recipient emails or URLs located only inside longer `read_file` profile blobs or webpages.
2. **Same-capability argument substitution:** On `shopping`, when `cart_add_product` is legitimately granted to purchase an item, an injection that substitutes a different `product_id` returned by `search_product` passes provenance (`6/180`). Closing item-level intent substitution without per-suite compilers remains open research.

*(As with `evidence/2026-11-15/`, raw per-episode logs are omitted from this checkout, so `MANIFEST.sha256` pins summary file integrity since commit rather than independent third-party execution verification.)*

Verify hashes locally:

```bash
(cd evidence/2026-11-16 && shasum -a 256 -c MANIFEST.sha256)
```
