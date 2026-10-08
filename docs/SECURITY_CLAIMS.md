# Security claims and limitations

## Supported claims

- The committed deterministic replay runs the same 18-step plan with and without ADOM.
- In the saved protected deterministic result, legitimate work completes and prohibited effects
  are zero.
- In the saved Docker replay, the protected target records zero effects, all nine brokered attack
  requests are denied, one circuit trip occurs, and six later requests are suppressed.
- The container verifier checks service-owned effect records and saved network membership rather
  than trusting an agent- or policy-authored success label.
- The enforcement core is independent of the model provider when an action is mediated through it.

## Unsupported claims

- ADOM does not reproduce, discover, patch, or prevent the Artifactory zero-day.
- The injected sandbox-loss condition is not evidence that ADOM survives every real escape.
- A Docker topology on one daemon is not proof against a kernel, hypervisor, or daemon compromise.
- Historical frontier-model reports are not equivalent to the sealed container evidence.
- A finite scenario set cannot establish universal containment.

## Correct public wording

> ADOM contained every prohibited effect in a reproducible synthetic incident replay after a
> declared sandbox compromise, while preserving the tested legitimate operation.

Avoid wording such as “ADOM stops zero-days,” “unhackable,” or “guaranteed containment.”


## Later local experiments

The [results page](RESULTS.md) records later workflow-lab and AgentDojo experiments with
explicit limits. Their implementation is not part of this reference checkout. Zero observed
attack successes in a finite developed configuration is not proof of general security.
No zero-false-positive, full adaptive AgentDojo, external reproduction or competitor-superiority
claim is established. Source availability is detailed in [engineering status](ENGINEERING_STATUS.md).
