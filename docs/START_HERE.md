# New here? Five-minute technical orientation

**WolfAlibi asks a hard question:** can an AI agent independently demonstrate that it **did not access a designated resource** during a particular task?

The baseline has an interesting answer for a **limited, broker-mediated event set**: digitally signed checkpoints and compact cryptographic non-membership proofs. The much harder question—and still open research challenge—is proving that the recorded event set is complete.

## What has actually been demonstrated?

- **Research prototype:** a signed, independently verified Merkle commitment to broker-reported resource operations.
- **Known historical defects:** an in-flight epoch boundary, shared-broker journal omission, a directory-swap write side effect, and positive short-write journal loss. All four have reproducible synthetic tests.
- **Work underway:** a reported Codex local implementation fixed the four defects and passed 44 unit tests and eight original mutations. That revision must be pushed and independently reviewed before promoting the evidence matrix.
- **Not yet demonstrated:** universal confinement of an AI process, external witness anchoring and a receipt proving all possible access channels were covered.
- **Security-sensitive deployment:** **BLOCKED**.

Start with the [claims matrix](CLAIMS_AND_EVIDENCE.md) and [threat model](THREAT_MODEL.md). This page never substitutes a claim of proof for an actually verified commit.

## Reproduce the published research baseline

Use Python 3.9+ and `cryptography` in a disposable environment:

```bash
git clone https://github.com/Bropdrop/WolfAlibi.git
cd WolfAlibi
git switch feat/wolfalibi-v0-1
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install cryptography
python3 -m unittest -v test_alibi.py
python3 -m unittest -v test_wolftrap_alibi.py
python3 mutation_test.py
python3 alibi.py demo
```

**Historical unmodified baseline:** 21 authored tests passed, four WolfTrap regression tests failed, eight intentional mutants were caught. If the branch has since advanced, report the exact checkout SHA and observed output rather than expecting the historical results.

## Pick an issue worth solving

Read [reviewer challenges](REVIEWER_CHALLENGE.md), [test matrix](TEST_MATRIX.md) and [roadmap](ROADMAP.md). The most valuable contributions challenge completeness assumptions, produce small executable counterexamples or improve independent verification.

## How to report

A useful issue or PR explains the claim/invariant, minimum synthetic reproduction, operating-system and Python versions, whether an unauthorized **effect** actually occurred, and the relevant commit. Use **only** files and systems you own or control.

Read [CONTRIBUTING.md](../CONTRIBUTING.md). The project does **not** currently have an explicit open-source license; maintainers should choose one before accepting unrestricted code contributions.

## A question for every reviewer

*Does this certificate prove the agent didn't do something, or only that nobody recorded the agent doing it?*

A truthful `BLOCKED` answer can be more meaningful than an attractive green badge.
