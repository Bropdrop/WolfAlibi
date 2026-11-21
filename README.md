# 🐺 WolfAlibi

WolfAlibi is an experimental Python research project for cryptographically checkable evidence that specified filesystem resources were not accessed **through a named, mediated broker** during a sealed interval.

> **Security research prototype — operational deployment is BLOCKED.**
> A valid proof is not evidence that an AI, user, or host had no other path to the resource.

## What is implemented

- A signed, witnessed Merkle absence proof for broker-mediated reads, writes, directory listings, and denied attempts.
- Stage 1 reliability hardening: completed-operation epoch barriers, a single-writer journal lease, framed/fsynced WAL recovery, short-write handling, and Linux root-fd/`openat2` path resolution.
- `DurableWitness`, which persists checkpoint heads and receipt digests before signatures leave the process, plus v2 signed state anchors for externally retained rollback detection.
- `NEGATIVE_ACCESS_RECEIPT_V1` compatibility and opt-in `NEGATIVE_ACCESS_RECEIPT_V2` bindings for resource identity, execution-boundary metadata, and witness-state continuity; both remain **`BROKER_ONLY`**.
- An optional Bubblewrap Linux process-launch demonstration with a machine-readable policy manifest and synthetic exclusion probe; it always reports `BLOCKED` assurance.
- Conservative hard-link alias refusal before bytes are released or an existing file is truncated.
- Proposal-only adapter interfaces for future APIs, tools, and databases; no such adapter is active.

Read [the architecture](docs/ARCHITECTURE.md), [threat model](docs/security/THREAT_MODEL.md), [Stage 2 foundations](docs/STAGE2_FOUNDATIONS.md), and [engineering report](docs/ENGINEERING_REPORT.md) before using the code.

## What it cannot prove

WolfAlibi does not confine a real agent to the broker, attest code execution, establish every direct filesystem/network/API route is closed, create an external witness transparency log, or authorize a downstream effect. It must not be used for real secrets, compliance, financial, regulatory, or safety decisions.

## Agent Lab

Test an authorized agent with `wolfalibi agent test --manifest agent.json`. The runner requires consent before importing agent code and writes a local report of explicitly observed tool callbacks. [Setup, pinned adapters and synthetic examples](docs/AGENT_LAB_RUNNER.md)

For the separate Solitary experiment, run `wolfalibi byoa doctor` to check Linux prerequisites. The fixed synthetic worker produces `BROKER_ONLY` evidence that can be verified offline with separate expectations. [Solitary setup, control pairs and limitations](docs/BYOA_SOLITARY_V1.md)

[Alibi Clearance V1](docs/ALIBI_CLEARANCE_V1.md) combines a fresh Solitary trial and a separately signed resource-owner grant to gate one offline synthetic read. The gateway produces a local signed decision report.

[Stage 5 Solitary integration](docs/STAGE5_BYOA_SOLITARY.md) runs the fixed Stage 4 Python callback inside the measured cell and records its observation separately from the broker and owner decisions.

[VOIDCELL Experiment 001](docs/VOIDCELL_EXPERIMENT_001.md) moves the authorization decision to an offline synthetic target that records its own effect and signed receipt.

[VOIDCELL Experiment 002](docs/VOIDCELL_EXPERIMENT_002.md) adds a target-owned signing key, a UID-gated daemon, and a separately retained ledger checkpoint.

## Local test matrix

Python 3.9+ and `cryptography` are required. Linux `openat2(2)` and POSIX `fcntl` are required for the hardened broker; the optional launcher also needs Bubblewrap (`bwrap`). No dependency is auto-installed.

```bash
python3 -m unittest -v test_alibi.py
python3 -m unittest -v test_wolftrap_alibi.py
python3 -m unittest -v test_stage1_hardening.py
python3 -m unittest -v test_receipts.py
python3 -m unittest -v test_extensions.py
python3 -m unittest -v test_stage2_adversarial.py
python3 mutation_test.py
python3 alibi.py demo
python3 alibi.py bench 1000000
```

All fixtures are synthetic and local. The WolfTrap tests were deliberately red on the supplied baseline and are acceptance regressions for the Stage 1 fixes.

## Receipt CLI

The demo creates synthetic evidence only. It writes no private key; the generated receipt remains `BROKER_ONLY`. Its ephemeral demo signer is intentionally not restartable—applications that need durable witness continuity must supply and protect their own persistent signer key when constructing `DurableWitness` through the Python API.

```bash
python3 wolfalibi_cli.py demo-receipt \
  --output /tmp/receipt.json \
  --inputs /tmp/verification-inputs.json \
  --state-dir /tmp/witness-state

python3 wolfalibi_cli.py isolation-status

# Synthetic directories/files only; this is not a host-security test.
python3 wolfalibi_cli.py confinement-probe \
  --workdir /tmp/wolfalibi-work \
  --synthetic-marker /tmp/wolfalibi-protected/synthetic-marker.txt
```

For `verify`, supply expected keys, challenge, policy, scope, run ID, code digest, and epochs independently. Receipt v2 also requires expected resource identity, execution boundary, and a pre-run witness-state digest retained independently. The synthetic CLI output is only a reproducible roundtrip aid; it is not an independent anchor workflow.

## Project status

This branch is a development branch. Do not merge, release, deploy, enable paid CI, or represent it as production-ready without owner authorization. See [CODEX_MISSION.md](CODEX_MISSION.md), [AGENTS.md](AGENTS.md), and [SECURITY.md](SECURITY.md) for the project gates.

## License

No open-source license has been selected yet. Public visibility is not a grant of reuse rights. Choose a license only with the owner's approval.
