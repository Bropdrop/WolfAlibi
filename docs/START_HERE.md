# WolfAlibi: start here

**Question:** Could an AI finish a task and give an independent verifier credible, privacy-conscious evidence of what it *did not* access?

**Research answer so far:** WolfAlibi can generate a cryptographically verifiable **broker-scoped** exclusion receipt for a limited monitored filesystem API. It **cannot** yet prove that a real AI has no other access routes.

### Current published milestone

- Stage 1: [exact commit](https://github.com/Bropdrop/WolfAlibi/commit/dd7c5c76cadc49ab464f14abdbf77269ca735291) — the historical four WolfTrap defects were repaired and the author reported 44 local tests passing.
- Stage 2: [exact commit](https://github.com/Bropdrop/WolfAlibi/commit/37b277521041d68fa81748d41824e4c8bb66a592) · [draft PR #5](https://github.com/Bropdrop/WolfAlibi/pull/5) — signed witness-state continuity anchors, opt-in receipt v2, Bubblewrap manifest/probe, hard-link refusal, additional adversarial tests; **51 tests and eight mutants reported locally**.
- Community documentation: this branch is only a proposed public onramp. Neither the code nor these docs have been merged into default `main`.
- **Operational deployment: BLOCKED**. Confinement, exclusive mediation, attested code execution and independent witness custody remain incomplete.

### Five-minute local reproduction

On a suitable Linux host with Python 3.9+, `cryptography`, and a kernel supporting `openat2`:

```bash
git clone https://github.com/Bropdrop/WolfAlibi.git
cd WolfAlibi
git switch feat/wolfalibi-stage2-foundations
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install cryptography
python3 -m unittest discover -v
python3 -m unittest -v test_wolftrap_alibi.py
python3 -u mutation_test.py
python3 alibi.py demo
python3 wolfalibi_cli.py isolation-status
```

Bubblewrap is optional, required only for the limited launcher/probe. Its `READY` or synthetic `DEMONSTRATED` status **does not upgrade assurance**. Availability and passing tests vary by host; report unsupported states honestly.

### Produce a *synthetic* receipt

```bash
python3 wolfalibi_cli.py demo-receipt \
  --output /tmp/wolfalibi-receipt.json \
  --inputs /tmp/wolfalibi-inputs.json \
  --state-dir /tmp/wolfalibi-witness
```

The demo's input file is provided solely for reproducibility, **not** as an independently trusted verifier challenge or witness anchor. For meaningful verification, expected public keys, challenge, run, policy, resource scope, boundary and retained witness state must come from outside the untrusted receipt.

### Understand the design

| Start here | Why |
|---|---|
| [Stage 2 foundations](STAGE2_FOUNDATIONS.md) | What was actually implemented |
| [Stage 2 report](ENGINEERING_REPORT_STAGE2.md) | Reported test environment, commands, limitations |
| [Architecture](ARCHITECTURE.md) | Broker, WAL, witness and isolation design |
| [Threat model](security/THREAT_MODEL.md) | Trusted components and bypasses |
| [Claims and evidence](CLAIMS_AND_EVIDENCE.md) | Exact boundary between verified and proposed |
| [Reviewer challenges](REVIEWER_CHALLENGE.md) | Contributions that could move the research forward |
| [Roadmap](ROADMAP.md) | Stage 3 milestones and release criteria |

### The engineer's question

If the ledger says a resource was not touched, **what actually forced every relevant operation to appear in the ledger?**

That is the next frontier. We welcome constructive counterexamples and reproducible tests from systems engineers, Linux isolation specialists, cryptographers, and distributed-systems reviewers.

Before contributing, read [CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md).
