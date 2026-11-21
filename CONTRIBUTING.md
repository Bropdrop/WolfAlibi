# Contributing to WolfAlibi

WolfAlibi explores a difficult, testable question: **can we independently verify that a confined software agent did *not* use specified protected resources during an explicitly bounded run?**

The repository is public **research code**, not a production security control. Its present receipts are `BROKER_ONLY`: they verify signed commitments to broker-mediated events, **not universal resource nonaccess**.

## Before opening a pull request

Read:

- [Start here](docs/START_HERE.md) — prerequisites, local reproduction and code entry points.
- [Claims and evidence](docs/CLAIMS_AND_EVIDENCE.md) — historical results versus independently established facts.
- [Threat model](docs/security/THREAT_MODEL.md) — current Stage 2 security scope.
- [Stage 2 engineering report](docs/ENGINEERING_REPORT_STAGE2.md) — actual Stage 2 changes and remaining gaps.
- [Reviewer challenges](docs/REVIEWER_CHALLENGE.md) — seven worthwhile research questions.

## Local setup and test contract

Use a throwaway Linux development environment with Python and `cryptography`. Check the repository README for supported kernel/architecture, `openat2` and Bubblewrap requirements.

```bash
python3 -m unittest discover -v
python3 -m unittest -v test_wolftrap_alibi.py
python3 -u mutation_test.py
python3 alibi.py demo
python3 wolfalibi_cli.py isolation-status
```

The Stage 2 implementation report records **51/51 local tests** and **8/8 selected mutants detected** at commit `37b277521041d68fa81748d41824e4c8bb66a592`. These are reported local results, not substitute evidence of production confinement or a third-party audit. Capture your own exact HEAD, commands, environment and outputs.

A strong review supplies a synthetic test that fails against a specific revision, shows the violated invariant, and demonstrates what changes in a repaired revision. Test **effects**, **released data**, and **proof acceptance**, not just exceptions.

## Useful contribution areas

- Broker-only IPC between a genuinely confined worker and the durable broker
- Lifecycle/quiescence and total mediation of declared resource surfaces
- Independent witness custody, rollback/fork evidence and separately retained heads
- Freshness and execution binding in a challenge-based offline verifier
- Auditable event semantics and real-world Linux isolation assumptions
- Cryptographic proof soundness, privacy leakage and reproducible performance

Please keep PRs focused. Small independent tests and design counterexamples are welcome. When adding new protocol behavior, document the threat model, all trusted components, fail-closed behavior, versioning and how old receipts verify.

## Security and operational rules

- **Only synthetic, local, authorized fixtures.** No live accounts, personal records, service scans or testing against unrelated organizations.
- Do not commit API keys, secrets, private companion-project code, or proprietary datasets.
- Do not enable GitHub Actions or any paid CI, publish a release, or deploy services as part of a contribution without maintainer approval.
- Do not silently remove hostile tests or relabel skipped checks as PASS.
- When an assurance prerequisite cannot be checked, return `BLOCKED` rather than issuing a stronger receipt.
- No merge to `main` without explicit owner review.

## Licensing

**No open-source license has been selected yet.** The repository being public does not automatically grant redistribution or modification rights. Contributors should not assume a particular license applies. The maintainer must choose a license and confirm provenance/rights before accepting broad third-party code contributions.

## Review checklist

- [ ] Exact commit and environment recorded
- [ ] Synthetic reproducer included; no live target
- [ ] All old tests and new hostile regression pass
- [ ] No weaker proof claim or incompatible silent fallback
- [ ] Risk and threat model updated for any new assurance
- [ ] Measured claims separate from aspirations
- [ ] No paid CI or public release triggered

A rigorous `BLOCKED` is a successful security decision. A convincing false proof is not.
