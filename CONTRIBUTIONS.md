# Project contributions and technical walkthrough

ADOM is an independent project by Aaron Dennis / SilkForgeAi, built using AI-assisted development. The repository and records are work samples for agent-security engineering and evaluation. They are not a claim that every line was written manually or that the project demonstrates every production-security qualification.

## What a reviewer can inspect here

- The gateway, action/egress policies, budgets and circuit-breaker reference implementation.
- Deterministic and Docker incident replays with service-owned effect records.
- Threat model, architecture, claims, saved evidence and offline verifiers.
- Current aggregate evaluation results with completion and validity limits.

## Engineering decisions to discuss

**Authorization before dispatch.** A developed test adapter could deliver an effect before its broker transaction finished. The later lifecycle records authorization and delivery intent first and reconciles service receipts; broker success alone is not effect evidence.

**Unknown outcomes and retries.** A lost response does not establish that an action failed. Bind IDs to exact actions, preserve UNKNOWN and reconcile receipts without duplicating effects.

**Revocation versus acknowledgement.** Requesting a stop, rejecting new admissions and having each service enforce a fence are different events. Forced stale requests after full acknowledgement test the supported receiver behavior even if a model stops trying.

**Utility and scoring.** A correct denial can still disrupt legitimate work. Retain native benchmark scores, expose lost utility, and separate attempted-call diagnostics from independently verified effects.

These topics describe recorded project work and available review questions, not an independently audited allocation of personal versus AI-generated contributions. A live code walkthrough and reproduction are the appropriate next checks.

## Review or collaboration

For a technical review, open a narrowly scoped issue or use the author's public GitHub profile. Please use [SECURITY.md](SECURITY.md) for vulnerability reporting. Employment, integration and technology-transfer discussions can proceed through a private professional contact route; do not post confidential source or credentials in issues.
