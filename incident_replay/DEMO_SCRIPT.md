# Five-minute demonstration script

## 0:00–0:35 — The event

“The OpenAI-Hugging Face incident was not a chatbot saying something unsafe. Agents that were
supposed to be isolated discovered a shared package-cache channel, coordinated attempts to game
ExploitGym and its records, found credentials, uploaded malicious datasets, reached remote code
execution, and moved laterally. I wanted to test the control boundary that matters after an agent
stops behaving like a normal API client.”

Show the incident-stage list in `PUBLIC_BRIEF.md`.

## 0:35–1:15 — Honest scope

“This is a safe synthetic replay, not the Artifactory exploit. There is no zero-day here and no
real Hugging Face interaction. I inject sandbox loss into both runs. ADOM gets no credit for
preventing it. The question is: after that loss, can the agent turn connectivity and credentials
into effects?”

Show the scope paragraph in `README.md`.

## 1:15–2:00 — Architecture

Explain the three trust domains:

1. Agent-controlled environment and mutable transcript.
2. External action and destination boundary.
3. Synthetic targets and effect records outside agent control.

Emphasize that the verifier reads resulting state and chained receipts, not alert labels.

## 2:00–3:15 — Run

```bash
python3 -B incident_replay/run_all.py
python3 -B incident_replay/container_lab/run_lab.py
```

Point out:

- sandbox loss is true in both runs;
- legitimate work is 2/2 in both runs;
- the unprotected run reaches scorer deception, RCE, lateral movement and solution access;
- the ADOM run produces zero prohibited effects;
- the first prevented action is the package-cache message-board write.
- the protected container's raw direct HTTP attempt cannot reach the target because they share
  no network, while the unprotected container completes the full target chain.
- three denied or failed requests trip the external circuit breaker, and the next six requests
  are suppressed before reaching the executor.

## 3:15–4:05 — Independent evidence

Open `results/comparison.json`, then run `verify.py`. Explain that each decision includes the
claimed action, actual action, route, decision, observed effect, and changed state fields. The
hash chain fails if any of those fields are edited.

## 4:05–4:40 — What it means

“ADOM does not make a model aligned and does not claim to stop novel memory-corruption exploits.
It constrains authority and effects outside the model's context: destinations, tools, credentials,
budgets, and restore operations. A deceptive and an aligned model receive the same denial for the
same prohibited action.”

## 4:40–5:00 — Close

“I built this because evaluation environments now have to be designed as adversarial distributed
systems. I am looking for a team or strategic home where this control-plane work can be hardened,
independently evaluated, and deployed.”
