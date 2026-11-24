# WT-SIREN-002 — Independent Boundary Assurance

**Reviewed 2026-11-24. Result: PASS for the final ten-trial series, within BROKER_ONLY assurance. General confinement remains BLOCKED.**

This is a research publication for the fixed synthetic Solitary worker, not a general-agent sandbox-escape benchmark, an Anthropic Siren reproduction, or a production security certification. WT-SIREN-001 remains incomplete. No claim of endorsement or affiliation with Anthropic is made.

## Tested revision and environment

- Source commit: `774ea270ee00ea5728e8400f54c2fd70f8c467be`.
- Source tree: `0b43d17c4b64e5bed82d9797143e4995c8089911`.
- Worker SHA-256: `b13774ab95033f91fb0204e058c2755edd15942f257c837f473730db4633fbfc` (independently matched against the pinned GitHub file).
- Reported host: Debian 13.7, Linux 6.18.57, Bubblewrap 0.12.0, supervisor Python 3.12.14, worker Python 3.13.5.
- Reported clean source before and after the experiment, with the unchanged shipped worker. One lab operator controlled the trusted components, key generation, expected inputs and verifier. Separate processes are not independent administrative custody.

See [the pinned Solitary operating guide](https://github.com/Bropdrop/WolfAlibi/blob/774ea270ee00ea5728e8400f54c2fd70f8c467be/docs/BYOA_SOLITARY_V1.md) and [PR #21](https://github.com/Bropdrop/WolfAlibi/pull/21).

## Experiment

The runner generated a distinct 32-byte challenge for each trial and used the supported Solitary CLI on a disposable synthetic fixture. A separate process verified each receipt against retained expectations. The evaluator compared runtime hashes, the signed measurement, journal framing and the fixture postcondition; it checked recorded process exit and removed disposable state. Verification controls used copies or isolated stores, not additional protected operations.

| Final-series check | Result |
|---|---|
| Live completion with fresh store acceptance | 10/10 |
| Historical verification in separate process | 10/10 |
| Altered signed payload rejected | 10/10 |
| Missing supervisor signature blocked (exit 2) | 10/10 |
| Historical expiry rejection | 10/10 |
| Unconsumed challenge expiry rejection in separate newly issued stores, with genesis head intact | 10/10 |
| Paired in-window store acceptance | 10/10 |
| Consumed challenge replay rejected, witness head unchanged | 10/10 |
| Receipt/journal reconciliation | 10/10; one recorded authorized fixture read per trial; zero recorded protected writes |
| Fixture postcondition | 10/10; exported bytes match pinned digest; evaluator reports mode 0400 and sole resource directory entry |
| Signed identity and isolation measurements | 10/10 reported |
| Process termination and disposable-state cleanup | 10/10 reported |

The signed transcript contains a synthetic run-marker event and one protected-fixture read, not two protected-fixture reads. No provider model, API expenditure or deployment was reported.

### Single-host latency (milliseconds)

| Operation | Min | Median | Max |
|---|---:|---:|---:|
| Live execution with fresh acceptance | 278.208 | 323.360 | 361.565 |
| Historical verification | 105.698 | 125.605 | 144.491 |
| Altered evidence | 104.692 | 123.785 | 141.597 |
| Incomplete evidence | 99.184 | 115.539 | 186.267 |
| Expired historical verification | 103.375 | 121.612 | 127.675 |
| Consumed-challenge replay | 0.064 | 0.074 | 0.275 |

CLI timings include subprocess launch, startup and JSON output. Replay timing excludes database open and copy. The figures are descriptive, not general performance bounds. See [trial-index.csv](trial-index.csv) for exact execution and historical-verification samples in nanoseconds.

## Initial series retained

The original ten trials all returned BLOCKED for incomplete evidence, but the runner expected a more specific diagnostic than the verifier's actual “supervisor record lacks required fields” message. The initial aggregate outcome was INCONCLUSIVE and every row was marked FAIL for the diagnostic mismatch. The final series corrected the expectation and added an unconsumed fresh-store expiry check. It used ten fresh challenges; the initial series is not pooled into the final statistics. The original archive retains both series.

## Independent offline artifact review

The reviewer separately parsed the uploaded archive, matched the external and embedded manifests, verified exact manifest coverage, and checked every listed file digest. Using the pinned source's canonical JSON and domain-separated Ed25519 signature conventions, the reviewer independently verified signatures and decoded the journal bytes, rather than relying on the producer's PASS labels.

| Offline check across both series | Verified |
|---|---:|
| Manifest-listed files | 558/558 |
| Distinct 32-byte challenges bound to planned IDs, contracts and result rows | 20/20 |
| Supervisor signatures | 20/20 |
| Broker/witness receipt signatures | 40/40 |
| Witness-state anchor signatures and previous-digest links | 60/60 |
| Broker/witness checkpoint signatures | 80/80 |
| WAL framing and SHA-256 frame checksums | 80/80 |
| Journal bytes, receipt hash, recorded fixture read and exported fixture hash binding | 20/20 |
| Altered supervisor payload fails signature verification | 20/20 |
| SQLite integrity and exactly one accepted challenge record per original store, accepted witness head matches the signed chain | 20/20 |
| Command outcomes, exit codes and timings reconcile with per-run results | 100/100 |
| Final-series fresh-store expiry/in-window recorded outcomes | 10/10 |

The signature count is 200 (20 + 40 + 60 + 80), excluding failed altered-signature checks. The supplied public keys are lab-generated and do not establish independent external trust roots. The reviewer inspected stored negative-control results and did not re-run the complete WolfAlibi verifier or the live Linux isolation trials. Signed process measurements, mode checks and cleanup reports are retained observations, not fresh independent kernel measurements. No external clock or witness custody, proof of absence of transient access, arbitrary-agent confinement, kernel-wide teardown inventory, or production readiness is established.

## Original evidence commitments and publication status

The original uploaded ZIP contains 559 files, including its manifest. The reviewer checked all 558 entries. The separately supplied manifest is byte-identical to the embedded manifest.

- Original `WT-SIREN-002-evidence.zip` SHA-256: `c2aec383d6a97c7c649910c9820ba735cbda8eac4791139ea7d031098d78bb0c`.
- Embedded and separately supplied `SHA256SUMS` SHA-256: `978f565b08c21247f2a6b726afe9e6bdabc47d527165a9dd0b670cefdb0ca182`.
- Original ZIP size: 726402 bytes.

This commit publishes a reviewed summary and a derived per-trial hash index, **not the original archive, original manifest or runner**. The full archive remains in owner custody; direct binary transfer from the review environment to GitHub was unavailable. These commitments identify the precise archive reviewed. They cannot substitute for access to its bytes. Publish the exact original ZIP and manifest in a follow-up evidence-only commit before describing the complete evidence as publicly accessible. Do not regenerate or silently edit the original evidence.

## Reproduction

With the original verified archive and a separate clean checkout of the exact source commit above, extract the archive in a disposable working directory and validate `sha256sum -c SHA256SUMS`. Use the original `run.py` and `REPORT.md` from that archive. The reported procedure is:

```sh
python3 -m venv /tmp/wt-siren-002-venv
cd /path/to/pinned/WolfAlibi
/tmp/wt-siren-002-venv/bin/python -m pip install -e '.[agent-all]'
cd /path/to/extracted/wt-siren-002
sha256sum -c SHA256SUMS
unshare --user --map-current-user --net /tmp/wt-siren-002-venv/bin/python \
  run.py /path/to/pinned/WolfAlibi /tmp/wt-siren-002-repeat --runs 10
```

The live reproduction requires the pinned dependencies, Bubblewrap, libseccomp, the system worker Python and supported Linux namespaces. Use a new output directory. Fresh runs must not be represented as identical historical artifacts.

**Interpretation:** behavioural compliance and enforceable runtime controls are complementary security properties. The experiment supports repeatable, broker-scoped execution and verifiable recorded effects for the shipped fixed worker on the tested host; it supplies no comparative Siren success rate.
