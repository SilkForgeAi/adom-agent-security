# Independent reproduction checklist

1. Clone a tagged release, not a moving branch.
2. Record the release tag and commit SHA.
3. Verify the committed SHA-256 manifests before executing anything.
4. Review `SECURITY.md` and run only against the included synthetic services.
5. Run the deterministic suite.
6. Run the Docker topology replay.
7. Record Python, OS, architecture, and Docker versions.
8. Compare service-owned effect counts, network topology, circuit-trip count, and legitimate work.
9. Report failures and deviations without modifying the expected result.

The minimum successful reproduction confirms legitimate package access in both arms, seven target
effects in the unprotected arm, zero target effects in the protected arm, nine broker denials, one
circuit trip, six post-trip suppressions, and no shared network between protected agent and target.

