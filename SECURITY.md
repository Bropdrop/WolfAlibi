# Security status and responsible reports

**WolfAlibi is experimental. Do not use it to protect real secrets, certify universal AI nonaccess, or make compliance decisions.** Stage 1 addresses the four reproduced WolfTrap broker defects, but the project remains blocked for operational deployment because real-agent confinement, complete mediation, external witness anchoring, and code-execution attestation are not established. See [the architecture](docs/ARCHITECTURE.md), [threat model](docs/security/THREAT_MODEL.md), [WolfTrap review](docs/security/WOLFTRAP_ALIBI_001.md), and [Codex acceptance gates](CODEX_MISSION.md).

## Scope and reporting

- Run research tests only on your own synthetic directories and systems you are authorized to control. Do not test third-party services.
- Reproducible security failures should include affected commit SHA, the smallest synthetic test case, kernel/Python version and observed vs expected result.
- Avoid publicly posting real secrets or exploit details for vulnerabilities in unrelated third-party systems. This repo has no configured private reporting channel yet; the owner should enable GitHub private vulnerability reporting before inviting external disclosure.
- An absence proof is valid only for explicitly scoped mediated operations under the documented trust model. It is **not proof of no access through any channel**.
- `BROKER_ONLY` receipts are not authorization tokens. A verifier must independently supply the expected keys, fresh challenge, policy, scope, run ID, code digest, and epoch range.
- The optional Linux launcher reports `BLOCKED` assurance even when it runs; it is not a production sandbox or an attestation service.

## Release state

No production release is authorized. The only valid current verdict is **BLOCKED** for operational security deployment. Passing synthetic unit tests alone cannot change that verdict.
