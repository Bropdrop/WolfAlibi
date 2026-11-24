# Shirudo adapter threat model

## Scope and claim

The adapter verifies already captured evidence against a registered policy and records its historical decision. Its security objective is to make substitution, replay, incomplete verification reports, and reuse of a local challenge fail closed within the trusted operator environment.

The adapter does not enforce target behavior, discover a safe shield, establish a target's complete execution history, or authorize a downstream effect. `EVIDENCE_ACCEPTED` is a bounded evidence decision. It must not be converted into a claim that a host is currently safe or an AI agent is fully confined.

Genuine historical verification and fresh `LAB_VTPM` evidence passed in
[Gate B](evidence/ci-45290603342/qualification.json). The separate target counter
gate passed [Gate C](evidence/ci-45298950620/qualification.json). Those records
retain their exact executed revisions and assumptions. `SIMULATED_POLICY_ONLY`
remains synthetic, and a policy's `LAB_VTPM` or `HARDWARE_TPM` label alone is not
evidence that its stated trust assumptions were met.

The [prototype extension](PROTOTYPE.md) adds a separate immutable gate image
and a [terminal owner approval component](OWNER_APPROVAL.md). Its
[separate laboratory qualification](evidence/ci-45318855750/qualification.json)
records 19 passing cases, five fresh genuine assessments and two counter
effects. Approval was driven by `SCRIPTED_PTY`; actual human approval remains
`NOT_RUN`. The trusted builder, initrd and launcher connect the configuration's
image root to the observed process. This does not establish continuous process
identity, isolation from the administrator or production readiness. This
document describes the evidence adapter's continuing trust assumptions.

## Trusted components and inputs

The operator, adapter signing key, state directory, SQLite implementation, local clock, Python runtime, dependency environment, and host kernel are trusted. The operator approves the complete policy and obtains its enrollment and expected measurements through an independent trusted process.

The selected upstream executable is trusted to implement the pinned verification contract. The runner verifies its digest and version and executes a sealed snapshot. That protects the selected bytes from pathname replacement between hashing and execution. It does not attest the dynamic loader, shared libraries, process environment outside the runner's controls, interpreter, or kernel. The verifier is not placed in a network or process sandbox.

The upstream source-commit field documents the operator's claimed source relationship. A matching binary SHA-256 and version string do not prove a reproducible build or the absence of malicious code in an operator-approved executable.

The TPM trust boundary is supplied by the approved enrollment process. AK/EK names taken only from incoming evidence do not establish target identity. The adapter binds an enrollment-record digest but does not independently establish manufacturer trust or perform enrollment.

## Untrusted inputs

- Captured evidence, including its claimed keys, nonce, measurements, and additional fields.
- Verifier report data until the pinned report contract and required checks pass.
- A receipt supplied for offline verification until its signature and independently supplied expectations match.
- Filesystem pathnames presented to the runner until the selected bytes have been bounded, snapshotted, and pinned.

Policy files are operator-approved authority inputs. Schema checks prevent malformed or incomplete policies; they cannot determine whether the operator selected trustworthy or correct values.

## Threats and defenses

| Threat | Adapter behavior | Remaining limit |
| --- | --- | --- |
| Evidence chooses its own signer or target | Mandatory independent target ID, AK name, and EK name in the registered policy | An incorrectly enrolled policy can trust an attacker's TPM |
| Internally consistent evidence is mistaken for expected state | Mandatory expected chain, configuration root and measurement location, plus PCR 9/11 binding values | The operator must approve the right measurements; a digest is not a judgment that a shield is correct |
| Old evidence is replayed for a fresh request | Random 32-byte nonce, explicit challenge binding, short policy-defined expiry | The local clock is trusted; coordinated clock and state rollback is not solved |
| A known challenge is submitted repeatedly or concurrently | Once reservation succeeds, evidence reading, parsing, and invocation cannot make the challenge reusable | State, identity, policy, or clock failures can block before reservation; an actor able to reserve a challenge can deny its use |
| Verifier fails or its output is incomplete | Bounded execution and output, strict report schema, required checks, explicit failure | A malicious approved verifier remains inside the trusted computing base |
| Executable or evidence pathname changes during verification | Read-only opening and sealed memory-backed snapshots; executable digest/version pins | Host compromise, mutable dynamic dependencies, and a hostile operator are outside this protection |
| Policy is revoked or time expires while verification runs | Recheck both before finalizing; commit receipt and final status atomically | Revocation is local policy state, not target revocation or a globally witnessed fact |
| Process dies after reserving the challenge | Reserved challenge remains nonreusable | A completed receipt may not exist; no automatic retry with the old challenge |
| Reply is lost after successful finalization | Retrieve the committed receipt using `receipt` | A receipt proves only the recorded historical decision |
| Receipt is edited or signed under an unexpected adapter key | Ed25519 signature verification with independently supplied key, target, policy, and challenge expectations | Compromise of the trusted signing key permits false adapter statements |
| Local state is restored from an old snapshot | No strong rollback-prevention claim | SQLite durability is not an external monotonic witness; restoring coordinated state can restore apparent authority |

## Local transaction boundary

The challenge state machine separates issuance, reservation, and completion. A reservation must be durable before untrusted evidence is read or assessed. State and clock checks can refuse an operation before a reservation exists. After reservation, the challenge never becomes available again merely because input reading or validation fails or a process restarts.

Unexpected exceptions and interruptions intentionally leave an incomplete spent claim rather than a fabricated receipt. Expected failures can complete a nonaccepted receipt; when no evidence bytes were read, that receipt records a null evidence digest. Null evidence digests are never valid for accepted outcomes.

Completion consists of the signed receipt and final challenge status stored together after the final expiry and revocation checks. This provides a local transactional recovery boundary. It does not create independent witness custody, prove storage-controller power-loss behavior, prevent privileged database modification, or stop restoration of the whole state directory.

Do not treat multiple files or multiple signatures under the same administrator as independent custody. Protecting against coordinated restoration requires a separately retained monotonic reference or independently controlled witness, which this adapter does not supply.

## Historical verification boundary

Offline receipt verification checks what the adapter signed for the exact expected target, policy, and challenge. It also checks the nested execution metadata, supported source pin, expected/observed executable identity, report digest, supported assertion contract, and consistency of an accepted outcome with a successful recorded report. An accepted outcome cannot use execution profile `NO_VERIFIED_RESULT`.

Those checks do not reconstruct the full original policy from its digest. Optional PCR values, the independent quality of the enrollment process, and the truth of the adapter's signed execution claim still depend on trusted inputs and the signer. Receipt verification does not rerun the upstream verifier or authenticate the TPM evidence again.

`NO_VERIFIED_RESULT` means no validated completed runner result was retained, including cases in which a process started but did not finish with a usable report. It does not mean the verifier process was never started. Receipt verification also does not know whether the target has changed, whether an operator has since revoked the policy, or whether the original adapter state was later restored.

Consequently, receipt verification always reports `current_authorization: false`. A consumer needing permission for a new effect must obtain fresh authorization through a separate policy and enforcement system. The adapter has no such effect API.

## Upstream limits remain in force

The upstream verifier checks its attestation model; it does not prove that the measured shield prevents every exploit or preserves every legitimate workload. The target kernel, boot chain, TPM assumptions, enrollment integrity, measurement coverage, and upstream residual risks remain relevant. Runtime changes after measurement are not converted into current-state guarantees by signing an adapter receipt.

See the [pinned upstream threat model](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/Documentation/security/threat-model.rst). This adapter adds no claim of complete monitoring, kernel correctness, hardware authenticity beyond enrollment, or independent witness custody.

## Qualification boundaries

Synthetic tests can demonstrate local policy handling, nonce binding, replay refusal, failure consumption, report validation, and receipt integrity. They cannot demonstrate TPM authenticity, deployment compatibility, a real shield's effectiveness, or successful execution of the actual upstream verification path.

The retained Gate B and Gate C records include exact binary/build/version
evidence, fresh attestations and independent pins, actual positive runs, and
altered-evidence controls. Subsequent runtime or deployment claims require their
own matching evidence. Do not relax required checks to make a convenient
archived fixture pass. Full production qualification, operational enrollment,
and independent rollback resistance remain outside this feature.
