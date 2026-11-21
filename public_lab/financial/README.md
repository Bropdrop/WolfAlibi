# Financial Security Challenge · Quorvane Public Lab 002

A financial security reviewer can check two different questions here. Did the original synthetic target sign this exact payment intent? What does the record establish about a later inquiry or settlement? The portable experiment uses the published intent and audit records. A separate Linux experiment counts durable effects at a disposable synthetic target.

## Executive summary for financial security engineers

| Observation | What the reviewer can conclude |
| --- | --- |
| 36 matrix entries, 34 matched observations | Six verified only an expected historical claim. The historical verifiers rejected 22 changed records or verification inputs. One payment validity check and one inventory check rejected their inputs. Four malformed formats were refused at intake. |
| Two explicitly unqualified entries | Independent cross-UID custody was unsupported. Rolling back every local copy together was unassessed. Neither entry counts as a passing security observation. |
| Eight disposable Linux target controls | Concurrent deliveries shared one pending intent. After a lost reply and restart, reconciliation returned the archived receipt twice. Two concurrent historical reads left the stopped ledger and its checkpoint byte-identical. |
| Current authority and rollback | The live target denied expired, revoked and auditor-only permissions. Reopening an older ledger failed against the retained newer checkpoint. Both files were under the same operating-system account. |

The ordinary profile produced no evidence of settlement or present operational authority. Receipt-only review can be repeated after a grant expires. A payment effect requires a separate target decision. Some inherited signature and expiry diagnostics use the word “education” because the finance verifier calls shared record-validation code. The report retains those original diagnostics alongside the financial case ID and verification phase.

## Start a review

Extract the entire Lab 002 ZIP into a new directory. Run commands from the directory containing `scripts/`. Open `public_lab/financial/index.html` to choose a challenge, inspect the evidence, compare a local result and export a finding. The original three-experiment explorer is included. If your browser restricts local files, run `python -m http.server 8765 --bind 127.0.0.1 --directory public_lab` and visit `http://127.0.0.1:8765/financial/`. [Financial Security Challenge](index.html) · [Original evidence explorer](../index.html) · [Review scope](../REVIEW_SCOPE.md)

The HTML works offline. Python verification needs Python 3.11+ with the existing WolfAlibi dependency `cryptography==50.0.0` available locally. Use a preprovisioned Python environment. No accounts, downloaded JavaScript or new runtime packages are required.

```sh
python scripts/finance_challenge.py run > local-results.json
python scripts/public_lab.py verify
```

The first command compares observations with the fixed matrix. Each selected case has a reproduction command. The second command reproduces the three genuine records and three original controls from Lab 001. Open the matrix and results as JSON to audit the expected and observed values directly. [Challenge matrix](cases.json) · [Recorded run](results.json) · [Package inventory](inventory.json)

To check your own disposable copy of a **fictional** envelope against the original public finance pins, run the following. Use `history` in place of `finance` for an auditor's disclosure. The command reports the submitted byte digest, the decision and its scope.

```sh
python scripts/financial_receipt_check.py finance public_lab/vectors/finance/genuine.json
```

The submitted-file checker uses the fixed Lab 001 keys and first runs the genuine positive control. Exit 0 means the original historical claim verified. Exit 1 records a named verifier rejection or an input-format refusal, with its phase. Exit 2 means the check is inconclusive, including an unfamiliar verifier diagnostic. Exit 3 flags an unexpected canonical result for review. Insignificant JSON whitespace can change the file digest while preserving the signed content.

## What to inspect

| Category | Question for review |
| --- | --- |
| A · Authorization substitution | Is the signed owner grant bound to the original tenant, account, payee, amount, operation and request? |
| B · Replay and duplicate effects | Can a receipt be read repeatedly? How many durable intents does the disposable target record after duplicate delivery? |
| C · Historical authority | Which grant and time authorized the original effect or the later disclosure? Does the result confer present authority? |
| D · Settlement | Does the evidence establish anything beyond a pending intent? What source would a settlement observation require? |
| E · Evidence substitution | Do the selected keys, challenge, signed record and input encoding agree with the verifier's expected profile? |
| F · Rollback and completeness | What changes can a checker detect against its retained reference, and who controls that reference? |

WolfAlibi's finance and history Python verifiers check the signed material against the original pins and challenges. The portable runner also checks its prescribed inputs and wire format. A format rejection establishes only the named input rule. A verified financial intent establishes `PENDING_EXTERNAL_SETTLEMENT`. The ordinary profile records settlement as `UNESTABLISHED`. A valid historical disclosure conveys the auditor's observation at the signed time. It supplies no authority to initiate a payment. The inherited synthetic settlement experiment has its own source, authority and pins and is outside the ordinary profile.

For target-side behavior run the following separately. This command uses local disposable fixtures and measures the target's effect count. It requires the Linux fixture prerequisites.

```sh
python scripts/financial_effect_controls.py
```

A positive control must establish the precise historical claim. A negative case must produce the specified decision and reason. An unexpected acceptance is a finding. A missing fixture, unavailable verifier, incomplete run or unhandled exception cannot count as a security rejection. Browser checks and imported reports cannot attest that the canonical verifier ran on the reviewer's machine.

## Reproduce from source

The baseline is PR #35, commit `1d6dddd654489ebdc3ddc028dc23b59d8d407281`, tree `20f161ffa00045d795fc7ee76740002d89c9506f`. Its original archive SHA-256 is `0d14aeca661a8c01318ee55258e9198fb27cc1d8772e146b6dd296f7673342c7`. The Lab 002 draft PR records the new commit, tree, archive digest and qualification results. Obtain those identifiers independently. Set the two variables below to the candidate commit and tree before starting in a clean checkout.

```sh
git rev-parse HEAD 'HEAD^{tree}'
python scripts/build_financial_lab.py --check
python scripts/qualify_financial_lab.py --expect-commit "$EXPECTED_COMMIT" --expect-tree "$EXPECTED_TREE" > ../financial-qualification.json
```

Source qualification also needs the inherited suite's Linux prerequisites and pinned Agent Lab test packages. It checks the archived verifier and records the Git identifiers outside the qualified tree. This avoids a circular dependency between the report and the tree hash it records.

**Assurance.** The profile is `SIMULATED_POLICY_ONLY`. Cross-UID custody is `UNSUPPORTED`, production and confinement are `BLOCKED`, and certification is `NOT_ISSUED`. Reviewers trust the selected verifier, pins, Python runtime and local operating system. The fixtures cannot establish current bank state, independent administration, general agent confinement or regulatory compliance. [Threat model and reporting](../REVIEW_SCOPE.md)
