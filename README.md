# 🐺 WolfAlibi

**The proof is not what an AI says. The proof is what a confined, independently witnessed system can demonstrate.**

WolfAlibi is an experimental open-source research project exploring **cryptographic negative provenance** for AI agents: externally verifiable evidence that specified resources were not touched **through a defined, monitored access boundary** during a bounded run.

> **STATUS: SECURITY RESEARCH PROTOTYPE — NOT PRODUCTION-READY.**
> The supplied ALIBI baseline passes its original 21 tests, but four independently reproduced WolfTrap tests expose flaws that can invalidate nonaccess evidence or create a prohibited filesystem side effect. Unmodified ALIBI does **not** confine a real agent, and its current witness state is not durable. Do not rely on it to protect secrets or make regulatory, financial, or compliance claims.

## Handoff to Codex

**Start with [CODEX_MISSION.md](CODEX_MISSION.md)**, which includes the complete project story, source and evidence index, threat boundaries, four reproduced failures, architecture targets, acceptance gates, and local development restrictions.

Important artifacts:
- [Baseline implementation](alibi.py) · [21 original tests](test_alibi.py) · [8 mutation checks](mutation_test.py)
- [4 WolfTrap hostile regression tests](test_wolftrap_alibi.py)
- [WolfTrap report](docs/security/WOLFTRAP_ALIBI_001.md)
- [Original reported output](docs/evidence/ORIGINAL_RESULTS.txt) · [Independent hostile run output](docs/evidence/WOLFTRAP_ALIBI_TEST_RESULTS.txt)

## Local reproducibility

Python 3.9+ with `cryptography` is required:

```bash
python3 -m pip install cryptography
python3 -m unittest -v test_alibi.py
python3 -m unittest -v test_wolftrap_alibi.py
python3 mutation_test.py
python3 alibi.py demo
```

The original 21 tests should pass on baseline; **the four WolfTrap regression tests should fail until the defects are actually repaired**. This is a deliberate failing baseline.

## What 'proof of nonaccess' really means

Current ALIBI proves: a witness co-signed a broker-produced, ordered commitment that contains no recorded keys in a queried interval for certain epochs. This does **not** prove the agent had no direct, unmonitored path to those keys, that a compromised broker logged honestly, or that the epochs describe a complete authorized run.

The long-term target is a **run-bound negative-access receipt** with an actual enforced boundary, signed authorization and confinement scope, durable independent witnessing, and a fail-closed offline verifier. Unsupported claims must return `BLOCKED`, not a reassuring certificate.

## Safety and costs

- Synthetic local files and sandboxed tests only; no live testing on third-party services.
- No credentials, personal documents, or private companion-project code in this public repo.
- No paid CI or GitHub Actions activation without owner approval.
- No release or merge until the owner authorizes it and the security gates pass.
- A public repository remains publicly viewable, even without an announcement.

## License

No open-source license has been selected yet. Public visibility is **not** a grant of reuse rights. Choose a license only with the owner's approval.
