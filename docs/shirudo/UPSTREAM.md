# Pinned Shirudo contract

## Reference revision

- Project: [shirudo-dev/shirudo](https://github.com/shirudo-dev/shirudo).
- Source reference: [`fb97c1ec5908c8bdbd46760c29e57677977fce74`](https://github.com/shirudo-dev/shirudo/tree/fb97c1ec5908c8bdbd46760c29e57677977fce74).
- Adapter base: WolfAlibi documentation-only main commit `a7fabefe0c27abf328828a257f3fbce1796dadef`.

The adapter does not download or build Shirudo. An operator supplies the verifier path, independently approved executable SHA-256, expected version ID, target enrollment record, and measurement expectations. The source reference is provenance metadata supplied by that operator, not a reproducible-build attestation.

No upstream implementation or test corpus is copied into this adapter. Shirudo's licensing is separate from this repository's unselected license; see the [upstream root at the pinned revision](https://github.com/shirudo-dev/shirudo/tree/fb97c1ec5908c8bdbd46760c29e57677977fce74) for the authoritative license notices.

## Offline verification surface

The integration uses `shirudo version --version-id` and `shirudo attest verify`. Both execute from the same immutable executable snapshot. It does not use `init`, shield load/unload, target enrollment, attestation collection, remote shell, or target-control APIs. The pinned [version command reference](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/Documentation/reference/cli/version.rst) describes the version ID as a digest over source and build-configuration inputs; the adapter still relies on the operator's separate executable hash pin.

The pinned [attest-verify reference](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/Documentation/reference/cli/attest-verify.rst) documents offline verification on the operator host without a TPM. It also explains that a successful bare invocation can establish only internal consistency when identity or expected state is absent. The adapter therefore requires independent policy pins instead of relying on an exit code or a top-level `ok` verdict alone.

| Upstream option | Source of value in this adapter |
| --- | --- |
| `--evidence` | Sealed snapshot of the supplied evidence file |
| `--nonce` | Locally issued, single-use challenge |
| `--ak-name`, `--ek-name` | Registered enrollment pins |
| `--expect-chain` | Approved register value |
| `--expect-bind-pcr` for 9 and 11 | Approved binding PCR values |
| `--expect-config-root` | Approved configuration root |
| `--expect-config-pcr` or `--expect-config-nvpcr` | Exactly one approved configuration measurement location |
| `--expect-pcr` | Additional quoted PCR expectations, when present |
| `--require-initrd` | Required by this adapter's supported profile |
| `--json` | Required structured report format |

The adapter does not expose a free-form argument passthrough. It does not use `--allow-runtime-events`, `--strict-anchor`, certificate-set prediction, or a trust-presented enrollment fallback. The exact expected chain commits to the operator-approved event history; the absence of `--strict-anchor` must not be described as proof that PCR 9 contains only the anchor.

The expected report is schema `1`, a verdict, and a list of labeled check results. The runner requires its supported labels and required successes. Unknown, missing, duplicated, failed, or structurally invalid required assertions must not be treated as an accepted attestation. An upstream rejection may legitimately stop before later checks; it is never promoted to acceptance.

The supported anchor alternatives include the upstream note that PCR 9 has further measurements after the anchor. Accepting that documented note is not a claim to have independently replayed those additional logs. The raw report is retained in the receipt so this limitation remains visible. Changing the upstream report contract requires a deliberate adapter update and renewed qualification.

Offline receipt checking revalidates this recorded report contract and its digest without launching Shirudo. It checks internal consistency with the claimed profile and pins; it does not reconstruct the original optional PCR values from a policy digest. When a completed valid runner report is unavailable, the receipt uses `NO_VERIFIED_RESULT`, which permits no accepted outcome and makes no claim that a process never started.

## Enrollment is a separate trust process

The adapter's `challenge` command generates a signed freshness nonce. It is different from upstream [`shirudo attest challenge`](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/Documentation/reference/cli/attest-challenge.rst), which creates a TPM credential activation challenge.

The pinned [attest-target guide](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/Documentation/start/guides/attest-target.rst) distinguishes presented key names from a trusted enrollment and explains its software-TPM demonstration. The operator must provide separately trusted AK/EK pins and an enrollment record. The adapter does not implement endorsement-certificate issuer validation or `--trust-presented-ek`.

Binding a target ID to an AK/EK pair is therefore an external operator responsibility. `HARDWARE_TPM` is a declared policy profile, not hardware certification conferred by this adapter.

## Source review versus executed qualification

The [operational attestation guide](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/Documentation/operate/run/attest.rst) and [threat model](https://github.com/shirudo-dev/shirudo/blob/fb97c1ec5908c8bdbd46760c29e57677977fce74/Documentation/security/threat-model.rst) were inspected to define the adapter's supported expectations and limitations. That review is evidence of a documented integration contract, not a successful runtime test.

Only synthetic verifier fixtures have been qualified in this feature's initial scope. An archived upstream corpus entry cannot answer an arbitrary newly generated nonce and must not be substituted for a fresh end-to-end trial. The real upstream positive path remains an explicit qualification gate.

When that gate is run, retain the executable SHA-256 and version ID, the claimed source revision and build evidence, the external policy digest, challenge, exact imported evidence digest, verification result, and hostile controls. Report the executed profile separately from `SIMULATED_POLICY_ONLY`; do not promote synthetic success into a TPM claim.
