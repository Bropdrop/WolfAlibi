# Quorvane Evidence Explorer

**Public Lab 001** is an offline research preview of three signed, fictional experiments. Each pairs an original record with a copy containing one deliberate change. You can trace the receipt to its public inputs, run the corresponding verifier, and save a reproducible finding on your own machine.

**Open the explorer.** From the repository, download the review ZIP and extract it. Inside the ZIP or in a checkout, open `public_lab/index.html` in a modern browser with JavaScript enabled. The page embeds the vectors, saved results and interface. It can also travel as a single HTML file. [Open the standalone HTML](index.html) · [Download the review ZIP from the development branch](https://github.com/Bropdrop/WolfAlibi/raw/refs/heads/feat/quorvane-public-lab-001/public_lab/quorvane-public-lab-001.zip)

If a managed browser blocks `file:` navigation, run `python -m http.server 8765 --bind 127.0.0.1 --directory public_lab` from the extracted root and open `http://127.0.0.1:8765/`. This optional server serves local files on loopback. The explorer itself sends no requests and requires no sign-in.

[![The offline explorer showing three experiments and the education record fingerprint](preview.jpg)](index.html)

## Try an evidence pair

| Experiment | Genuine record | Deliberate change |
| --- | --- | --- |
| Education admission | One owner-approved fictional student support read with a target-signed response digest | Change the response’s support level |
| Financial intent | One target-signed pending intent for CAD 45.00 | Increase the amount to CAD 46.00 |
| Historical audit | A separately authorized auditor recovers an earlier pending intent receipt | Replace the inquiry challenge |

Choose an experiment and switch between **Genuine** and **Tampered**. Inspect its JSON, public keys, challenge and recorded verifier result. **Check signed record** makes a fresh browser Ed25519 check of the signature and the selected record’s content bindings. A browser lacking the required Web Crypto support reports `UNSUPPORTED`. The Python verifier additionally checks the original grants, witness and caller signatures, scope and validity at the signed historical time. The ordinary audit reports `settlement=UNESTABLISHED`. The finance and audit examples come from separate synthetic runs.

## Run the canonical verifiers

Start at the directory containing `scripts/`. Use Python 3.11+ with `cryptography==50.0.0` already installed. The browser requires neither Python nor a package installation. For a new offline Python environment, an operator with a compatible local wheelhouse can install the verifier dependency with `python -m pip install --no-index --find-links /path/to/wheelhouse cryptography==50.0.0`. No dependencies are downloaded by the lab. The Python commands were qualified on Linux.

```sh
python scripts/public_lab.py verify
python scripts/public_lab.py verify --case history
python -m unittest -v test_public_lab test_public_lab_finding
```

A passing run returns exit 0 with three genuine `VERIFIED` results and three expected `REJECTED` results. The lab returns exit 2 for a missing artifact, digest mismatch or unexpected verifier outcome. To run a verifier directly, copy the command shown for a variant in the explorer. For example, from a POSIX shell:

```sh
python -m wolfalibi.education_verify \
  --expectations public_lab/vectors/education/pins.json \
  --challenge "$(cat public_lab/vectors/education/challenge.txt)" \
  --evidence public_lab/vectors/education/tampered.json
```

That individual verifier returns `REJECTED` and exit 2. The deliberate alteration is itself included in the file inventory. Matching its published SHA-256 authenticates which test file you received. Executing the verifier checks whether the signed claim survives the alteration. [Qualification manifest and file hashes](manifest.json) · [Recorded canonical results](reports/verification.json) · [Published-source and fixture privacy review](reports/provenance.json)

## Submit a local finding

In **Findings**, select the experiment and variant, describe the environment, steps, expected result and observed result, then download the finding JSON. Include only fictional data and public evidence references. Review free text yourself for sensitive details. From the extracted root, submit the file to a local review inbox:

```sh
python scripts/public_lab_finding.py submit finding.json --inbox review-inbox
```

On the qualified Linux host the intake creates a private inbox, validates the manifest and artifact digest, and returns a content-addressed receipt. Resubmitting the same finding returns `DUPLICATE`. The finding stays on disk. A reviewer can receive the reviewed JSON by a separately agreed offline handoff. There is no public submission endpoint or automatic upload.

## What the evidence establishes

The manifest records each condition separately. `TESTED` applies to the named synthetic control. `UNSUPPORTED` marks the outstanding two-UID custody gate. `BLOCKED` applies to production operation and confinement. `NOT_ASSESSED` covers, among other things, independent witness custody, power loss, coordinated rollback and real settlement. Formal certification remains `NOT_ISSUED`. The published experiments use `SIMULATED_POLICY_ONLY`.

All three sets of public inputs and original signed records were published with their respective source revisions. The manifest gives each source Git commit and tree. The public pins retain the original synthetic-run process measurements, including PID, UID and boot ID, because the historical signatures depend on them. Historical signatures can be replayed for review long after a run ends. They confer no current authorization. Pin distribution and custody are trusted. Replacing the whole bundle, including its reference keys and manifest, is outside a self-check. A portable disclosure also cannot independently establish the current revocation and challenge-use state. [Education source](https://github.com/Bropdrop/WolfAlibi/pull/32) · [Financial intent source](https://github.com/Bropdrop/WolfAlibi/pull/33) · [Historical disclosure source and review](https://github.com/Bropdrop/WolfAlibi/pull/34)

## Reproduce the candidate from a source checkout

```sh
python scripts/build_public_lab.py --check
python scripts/qualify_public_lab.py > ../public-lab-qualification.json
```

The first command verifies the vectors and compares the standalone page, recorded report and reproducible ZIP with the checked-in bytes. `python scripts/build_public_lab.py --archive ../review.zip` writes a fresh archive. The full-tree qualifier also requires the pinned `agent-all` extras and inherited Linux fixture prerequisites. It records the exact commit, Git tree, commands, test counts, skips, verifier outcomes and all eight original mutation checks. Reviewers with an existing Chromium and Python Playwright installation can also run `python scripts/check_public_lab_browser.py --output ../public-lab-browser` from the checkout. This separate check reports native signature checks, network observations, desktop and mobile controls, and any browser policy restriction on local files. The full test suite, browser QA tooling and build sources live in the repository. The compact review ZIP includes the two public review commands, their tests, the canonical verifier sources they import, all public inputs, the HTML and the recorded results.

No open-source license has been selected for the repository. Its existing licensing status also applies to this preview.
