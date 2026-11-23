# Shirudo evidence adapter

This adapter checks an already captured Shirudo attestation against an operator's independently approved policy. It records a fresh challenge, runs an explicitly pinned offline verifier, and preserves the result in a signed local receipt.

**Current qualification: synthetic fixtures only.** A successful synthetic assessment returns outcome `SIMULATED_POLICY_ONLY` with assurance `SYNTHETIC`. No positive verification using a real pinned Shirudo binary and valid target evidence has yet been qualified. Production use remains blocked.

The adapter is read-only toward targets. It has no target connection, deployment, shield loading or unloading, target key management, or network API. It does write its own local challenge journal, signing key, policy records, and receipts. A locally issued challenge is a freshness request; it is not a TPM enrollment credential challenge and does not enroll a target.

This feature branch starts from WolfAlibi's documentation-only main commit `a7fabefe0c27abf328828a257f3fbce1796dadef`. The older WolfAlibi engine and research labs remain on their existing draft branches. Their historical test counts and assurance claims are not inherited by this adapter.

## What an accepted result means

`EVIDENCE_ACCEPTED` records that this adapter accepted the supplied evidence for the named target, policy, and single-use challenge under the recorded verifier configuration. Its meaning is limited by the execution profile and the operator's trust assumptions.

It does not establish current target safety, shield correctness, complete agent confinement, absence of unobserved activity, or permission to perform a later action. `verify-receipt` authenticates a historical adapter record and reports `current_authorization: false`; it does not issue a grant or rerun TPM verification.

A digest of an approved policy is useful only if the policy's expected values were approved independently. Copying the received evidence's keys and measurements into a policy would allow that evidence to choose its own trust anchors.

## Requirements

- Python 3.11 or newer and `cryptography==50.0.0`.
- Linux for the verifier runner's sealed executable and evidence snapshots.
- A local state directory controlled by the trusted operator.
- For an upstream verification attempt, an explicitly supplied ELF executable whose SHA-256 and reported version match the policy.

The runner trusts the operator host, kernel, interpreter, dynamic loader, and libraries. Executing a pinned verifier is not a process or network sandbox. See [the threat model](THREAT_MODEL.md).

The supported source reference is Shirudo commit `fb97c1ec5908c8bdbd46760c29e57677977fce74`. Recording that commit beside a binary digest is an operator assertion; it does not prove that the binary was reproducibly built from that source. [Upstream contract and sources](UPSTREAM.md).

## Policy contract

Register a complete policy before issuing a challenge. The policy is strict JSON with the following fields; values below describe the schema and are not a runnable trust policy.

| Field | Required value or meaning |
| --- | --- |
| `schema` | `wolfalibi.shirudo.policy.v1` |
| `policy_id`, `target_id` | Explicit policy and enrolled-target identifiers |
| `assurance` | `SYNTHETIC`, `LAB_VTPM`, or `HARDWARE_TPM` |
| `enrollment.method` | `synthetic_fixture`, `trusted_builder`, or `manufacturer_chain`, as appropriate to the assurance profile |
| `enrollment.record_sha256` | Digest of the independently retained enrollment record |
| `enrollment.ak_name`, `enrollment.ek_name` | Independently pinned SHA-256 TPM key names: 68 lowercase hexadecimal characters beginning `000b` |
| `expected.chain` | Approved measurement-register value; 64 lowercase hexadecimal characters |
| `expected.config_root` | Approved configuration image root; 64 lowercase hexadecimal characters |
| `expected.binding_pcrs` | Explicit expected PCR `9` and `11` values |
| `expected.quote_pcrs` | Additional quoted PCR expectations; an empty object is permitted |
| `expected.config_pcr` or `expected.config_nvpcr` | Exactly one configuration measurement location: integer PCR 0–15 excluding 9/11, or a 68-character SHA-256 TPM name beginning `000b` |
| `verifier.source_commit` | The pinned source commit named above |
| `verifier.sha256` | Digest of the exact approved verifier executable |
| `verifier.version_id` | Expected value reported by that executable's `version --version-id` |
| `verifier.timeout_seconds` | Integer from 1 through 30 |
| `challenge_ttl_seconds` | Integer from 1 through 300 |

`SYNTHETIC` selects the fixture path. The other labels describe the operator's intended enrollment trust; setting a label does not create, verify, or certify that trust. In particular, the adapter does not contact a manufacturer or validate an endorsement-certificate chain as part of policy registration. The enrollment-record digest binds an external record without supplying an independent witness to its truth.

## Local workflow

Run commands from the checkout with its dependencies available. The installed `wolfalibi-shirudo` command is equivalent to `python3 -m shirudo_adapter`.

### 1. Initialize and register an approved policy

```bash
python3 -m shirudo_adapter init --state ./shirudo-state
python3 -m shirudo_adapter register-policy \
  --state ./shirudo-state --policy ./approved-policy.json
```

Retain the returned public key through a trusted channel. Receipt verification must receive that expected public key separately; a key supplied by a receipt is not an authority. Keep the signing private key in the protected local state directory.

Use the policy digest returned by registration for the following commands. The placeholders in this guide must be replaced with actual command results and independently approved identifiers.

### 2. Issue a fresh challenge

```bash
python3 -m shirudo_adapter challenge \
  --state ./shirudo-state --policy-sha256 POLICY_SHA256
```

The signed challenge binds the adapter instance, challenge ID, 32-byte random nonce, policy digest, target ID, issue time, and expiry. An authorized external collection workflow must obtain target evidence for that nonce. The adapter neither connects to the target nor performs collection. A static attestation file cannot answer a newly issued random nonce.

### 3. Verify a captured evidence file once

```bash
python3 -m shirudo_adapter verify \
  --state ./shirudo-state \
  --challenge-id CHALLENGE_ID \
  --evidence ./captured-evidence.json \
  --verifier /absolute/path/to/shirudo
```

The evidence envelope must identify schema `1`, kind `shirudo-attestation`, the `sha256` PCR bank, the expected nonce, pinned AK/EK names, and expected register value. Additional upstream evidence fields are allowed within the bounded JSON document. These preliminary bindings do not replace the upstream cryptographic checks.

Inputs reject duplicate JSON members, floating-point or non-finite numbers, and excessive nesting. The model bounds policy input to 64 KiB, evidence to 1 MiB, and a signed-record input to 256 KiB. The runner also bounds the executable, subprocess output, and shared deadline for version discovery and verification.

Once the local state, identity, policy, and clock checks permit reservation, the assessment consumes its challenge before reading or parsing the evidence file or invoking the verifier. Rejection, unreadable input, timeout, malformed input, and process failure do not make that challenge reusable. Failures before reservation, such as corrupt verifier state or a detected clock rollback, can block without making a claim. Obtain a new challenge for another assessment attempt.

An unexpected exception or interruption, including `RuntimeError` or `KeyboardInterrupt`, can leave a reserved challenge without a completed receipt. That challenge remains spent; the adapter does not fabricate a receipt or resume it as a fresh attempt. A completed nonaccepted receipt can have `evidence_sha256: null` when no evidence bytes were read. An accepted result always requires an evidence digest.

The runner snapshots the executable and evidence into sealed memory-backed files. It checks the executable digest and version, then invokes only the offline `attest verify` command with explicit key, chain, configuration, and PCR expectations. It requires the pinned structured report contract; process success alone is insufficient.

### 4. Retrieve and check the historical receipt

```bash
python3 -m shirudo_adapter receipt \
  --state ./shirudo-state --challenge-id CHALLENGE_ID > receipt.json

python3 -m shirudo_adapter verify-receipt \
  --receipt ./receipt.json \
  --public-key EXPECTED_ADAPTER_PUBLIC_KEY \
  --expected-target TARGET_ID \
  --expected-policy-sha256 POLICY_SHA256 \
  --expected-challenge-id CHALLENGE_ID
```

Receipt retrieval does not rerun verification. It is the recovery path when a completed verification's reply was lost. A valid historical receipt remains historical after policy revocation or challenge expiry.

Offline receipt verification checks the signed record's nested schema, supported source reference, expected and observed executable pins, report digest, recorded assertion contract, and outcome consistency. It receives the expected policy digest rather than the full policy. It cannot recover omitted optional PCR expectations from that digest, compare their original values independently, rerun TPM verification, or prove that the signed account of execution is true without trusting the adapter signer.

A receipt with execution profile `NO_VERIFIED_RESULT` records that no validated completed runner result is available. A verifier process may have started and timed out, failed, or produced invalid output. The label does not claim that execution never began and cannot accompany an accepted outcome.

### 5. Revoke a local policy

```bash
python3 -m shirudo_adapter revoke-policy \
  --state ./shirudo-state --policy-sha256 POLICY_SHA256
```

Revocation prevents further acceptance under that policy. Before a verification is finalized, the adapter checks expiry and policy revocation again, then commits the receipt and completed challenge status together. This does not revoke any shield or permission on a target.

## Test and qualification boundaries

```bash
python3 -m unittest discover -s tests -v
```

Run the local end-to-end demonstration with:

```bash
python3 scripts/demo_shirudo.py
```

The demo creates temporary private state and a self-generated, SHA-pinned synthetic executable. It uses actual CLI subprocesses to issue a challenge, assess a structural fixture, retrieve and verify the signed receipt, reject replay and a tampered signature, and check local policy revocation. It prints a compact JSON summary without key material and removes its temporary state. It performs no target connection or deployment and does not use an upstream Shirudo executable.

The suite uses synthetic local fixtures and a synthetic verifier to exercise the adapter's policy, challenge, subprocess, journal, and receipt behavior. The test transcript from the actual checkout determines which cases ran and passed. This guide does not claim a test count or a real TPM result.

The remaining integration gate is a positive run using the approved upstream ELF binary, its recorded build/version, independently enrolled target pins, and valid evidence for a fresh adapter challenge, followed by deliberately altered controls. Synthetic success cannot close that gate. No target provisioning or collection is performed by this adapter.

### Reproduce the recorded qualification

```bash
python3 scripts/qualify_shirudo.py \
  --output ./qualification.json --log ./qualification-tests.txt
```

This runs the tests and CLI demo, then records their results, environment, and exact source-file SHA-256 values. [The checked-in report](evidence/synthetic-qualification.json) and [test transcript](evidence/tests.txt) contain the actual run. The report is a local execution record, not an independently witnessed attestation. CI is configured to run the synthetic checks on Python 3.11 and 3.12; the report itself records the interpreter actually used locally.

### Actual upstream startup attempt

Official static and Debian artifacts were retrieved from [Shirudo's successful build for the pinned commit](https://github.com/shirudo-dev/shirudo/actions/runs/45269604356). Their archive digests were checked against artifact metadata. The static binary exited before `version --version-id`: its mandatory memory locking could not fit this environment's 8 MiB locked-memory limit. The Debian operator binary could not load `libtss2-esys.so.0`. Neither reached attestation verification, and no runtime version ID was obtained. The [startup diagnostic record](evidence/upstream-startup.json) includes the exact artifact and binary hashes, commands, exits, and limitations.

The next integration environment must satisfy Shirudo's startup requirements, provide an approved verifier build, and obtain real evidence for the adapter's fresh nonce from an independently enrolled target. The offline verifier itself does not require a local TPM. Historical corpus files cannot answer a newly issued challenge and are not live enrollment data.

This repository has no selected open-source license. No upstream source is copied into the adapter; [UPSTREAM.md](UPSTREAM.md) records references and the separately licensed upstream project.
