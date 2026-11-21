# Contributing to WolfAlibi

WolfAlibi welcomes careful reviews, reproducible counterexamples, implementation proposals and documentation improvements. It is **an experimental prototype with known failures**, not yet a production security product.

## Before you contribute

1. Read [CODEX_MISSION.md](CODEX_MISSION.md), [Threat model](docs/THREAT_MODEL.md), [Claims & evidence](docs/CLAIMS_AND_EVIDENCE.md) and [WolfTrap's review](docs/security/WOLFTRAP_ALIBI_001.md).
2. Use your own synthetic temporary directories only. Do not scan or touch external systems, personal documents or third-party infrastructure.
3. Run the baseline locally with Python 3.9+ and the `cryptography` package:

```bash
python3 -m unittest -v test_alibi.py
python3 -m unittest -v test_wolftrap_alibi.py
python3 mutation_test.py
python3 alibi.py demo
```

**Expected on the original baseline:** 21 authored unit tests pass, four WolfTrap regressions fail, and eight chosen mutants are detected. A regression is complete only when it first reproduces on the old revision and passes after the underlying repair.

## Good first contributions

- Add a minimal, deterministic synthetic reproducer for a concrete assumption or boundary mismatch.
- Define exact `read`, `attempt`, `denied`, `effect`, `start` and `end` semantics.
- Review canonicalization and Unicode/path representations across platforms.
- Document Linux isolation prerequisites and exactly which accesses remain outside its coverage.
- Propose an independent verifier acceptance test using caller-supplied keys, challenge and scope.
- Improve evidence reports so a stranger can reproduce results without secrets or cloud services.

## Pull-request checklist

- [ ] Small, clearly scoped branch and explanation of the violated invariant.
- [ ] Synthetic regression that fails before the fix and passes after it.
- [ ] No test deletion or weakening without a documented stronger substitute.
- [ ] Reproducible commands with actual test counts and environment details.
- [ ] No third-party security testing; no real credentials or customer data.
- [ ] No GitHub Actions/paid CI enabled without maintainer approval.
- [ ] Claims & evidence and threat model updated if an assurance boundary changes.
- [ ] Explicit `PASS`, `CONDITIONAL` or `BLOCKED` engineering verdict with remaining gaps.

Please avoid claims that the system proves universal nonaccess, is 'unbreakable', is first of its kind, or is ready for enterprise compliance without independent evidence.

## Licensing and contributor rights

**There is no license file yet. Public visibility does not automatically make a repository open-source under an OSI license.** Maintainers must choose a license and confirm rights to the inherited prototype before broad code reuse. Until then, contributions should be treated as review proposals; contributors should not assume their patches may be redistributed under a specific license.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Current problems are deliberately public because the repository is a synthetic research prototype; do not publish third-party vulnerabilities, sensitive data or attacks against live services.

## Engineering culture

A reproducible counterexample is valuable research. A refusal to sign insufficient evidence is a successful security outcome. We care more about correct boundaries than impressive badges.
