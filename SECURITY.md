# Security status and responsible reports

**WolfAlibi is experimental and has known security defects. Do not use it to protect real secrets, certify AI nonaccess, or make compliance decisions.** The original security boundary is incomplete; see [WolfTrap's reproduced findings](docs/security/WOLFTRAP_ALIBI_001.md) and [Codex acceptance gates](CODEX_MISSION.md).

## Scope and reporting

- Run research tests only on your own synthetic directories and systems you are authorized to control. Do not test third-party services.
- Reproducible security failures should include affected commit SHA, the smallest synthetic test case, kernel/Python version and observed vs expected result.
- Avoid publicly posting real secrets or exploit details for vulnerabilities in unrelated third-party systems. This repo has no configured private reporting channel yet; the owner should enable GitHub private vulnerability reporting before inviting external disclosure.
- An absence proof is valid only for explicitly scoped mediated operations under the documented trust model. It is **not proof of no access through any channel**.

## Release state

No production release is authorized. The only valid current verdict is **BLOCKED** for operational security deployment. Passing synthetic unit tests alone cannot change that verdict.
