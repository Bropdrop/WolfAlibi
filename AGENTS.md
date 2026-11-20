# Repository instructions for coding agents

This is **WolfAlibi**, an experimental negative-provenance research prototype. Treat code security and evidence precision as more important than speed or novelty claims.

**Read [CODEX_MISSION.md](CODEX_MISSION.md) completely before starting.** It is the authoritative assignment and acceptance criteria. Read the actual reproduction tests and WolfTrap report; do not rely on summaries alone.

## Operating rules

- Work on `feat/wolfalibi-v0-1` or a newly created child branch. **Never merge to `main`, publish releases, deploy, or enable GitHub Actions/paid CI** without explicit owner approval.
- Start by reproducing the 21/21 original tests, 4/4 intentionally failing WolfTrap tests, and 8/8 caught mutants. Log real results and exact commands.
- First fix the four WolfTrap violations. Only afterward work on OS-enforced process confinement, durable witnesses, run-bound signed negative-access receipts, and any experimental adapters.
- Every proof must explicitly name its actor, resources, operations, interval, trusted broker/witness keys and assurance level. If confinement or completeness is unknown, output `BLOCKED`, not `VERIFIED`.
- Never silently weaken tests to obtain a passing badge. Preserve old reproducers or replace them with stronger ones and document why.
- Use synthetic test data only. Never access live bank, police, government, provider, or third-party resources.
- No private source/keys/credentials from Ground Truth, HERCULES, MobiPute/TruthPute or other projects.
- No unmeasured claims (including 'world first', production readiness, real sandbox coverage, compliance, or speed). Explicitly separate demonstrated, conditional and future work.
- Favor minimal dependencies and reproducible local tests; avoid introducing cost-generating workflows.

## Baseline commands

```bash
python3 -m unittest -v test_alibi.py
python3 -m unittest -v test_wolftrap_alibi.py
python3 mutation_test.py
python3 alibi.py demo
```

## Required delivery

Produce code, adversarial regressions, local test evidence, a threat model, exact commit SHA, and a verdict `PASS`, `CONDITIONAL` or `BLOCKED`. Do not merge or claim production readiness.
