# Security policy

## Supported release

Security fixes are applied to the latest release on `main`.

## Reporting a vulnerability

Do not publish exploit details, credentials, or sensitive logs in a public issue. Use GitHub's
private vulnerability-reporting flow for this repository when available. If that option is not
visible, open a minimal issue requesting a private contact channel without including the finding.

Useful reports include the affected commit, threat model, reproduction steps using synthetic
targets, observed effect, and whether the enforcement boundary or only the agent workload was
compromised.

## Safe research

The included scenarios use fake credentials, synthetic services, and isolated networks. Do not
point the harness at third-party systems without authorization. ADOM's maintainers do not endorse
testing against infrastructure you do not own or have explicit permission to assess.

