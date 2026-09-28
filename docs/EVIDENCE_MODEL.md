# Evidence model

ADOM distinguishes an attempted action, a policy decision, and an observed effect.

## Evidence producers

- The agent records what it attempted.
- The gateway records policy and blast-radius decisions with version identifiers.
- Synthetic services record effects they actually performed.
- Docker inspection records network membership.
- The host verifier joins those records and evaluates explicit invariants.

## Why this separation matters

A compromised agent can claim success or delete its local transcript. A buggy policy can claim it
blocked an action even if the executor ran. Service-owned effect evidence answers the stronger
question: did protected state actually change?

## Integrity

Deterministic receipts are hash chained. Release artifacts and saved container evidence are covered
by SHA-256 manifests. Hashes provide tamper evidence, not trusted timestamping or signer identity;
future releases should add signed tags and provenance attestations.

