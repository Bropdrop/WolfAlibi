# Quorvane Gate 002 — one fictional school-record read

A dedicated Linux target process authorizes a read of `fictional-aster` for `fictional-school` and the purpose `approved-support`. The target owns the resource decision, its signing key, the revocation table and the authorization journal. The response contains a fictional support-level label. The fixture is public test data. The experiment measures admission at the target API.

This implements the first education experiment from the [VOIDCELL integration design](QUORVANE_VOIDCELL_INTEGRATION.md) and [PR #31 engineering review](https://github.com/Bropdrop/WolfAlibi/pull/31). Finance integration is open.

## Reproduce locally

Use a clean checkout on Linux with procfs, Unix sequence-packet sockets, kernel peer credentials and pidfds. Use a Python environment with the pinned project dependencies, including the optional `agent-all` packages for the full regression suite. The trial uses local files, pipes, a Unix socket and ephemeral synthetic keys.

```sh
evidence_dir=$(mktemp -d)
python -m examples.quorvane_education_demo \
  --expectations-out "$evidence_dir/expectations.json" > "$evidence_dir/education-demo.json"
python -m wolfalibi.education_verify --expectations "$evidence_dir/expectations.json" \
  --evidence "$evidence_dir/education-demo.json"
python scripts/qualify_education_gate.py --evidence-dir "$evidence_dir/full-run" \
  > "$evidence_dir/qualification.json"
```

The fixture operator retains public keys, the run challenge, intended scope, enrolled process measurements, witness reference and expected response digest before dispatch. An independent reviewer needs an authentic copy of those expectations. The evidence file contains the signed inputs, response and target receipt. The verifier checks both authorities at the target's signed admission time. Its `VERIFIED` verdict covers that historical decision. Repeated offline verification confers no new access. A fence or denial is a local target outcome. The verifier issues no portable negative-access proof for it.

## Admission and delivery

1. The supervisor starts one fixed synthetic caller. The caller generates its signing key. The fixture enrolls the running process, a fresh challenge and an authorized request in the target's local configuration. The caller receives only public information about the target key.
2. A school-owner grant authorizes the exact student, tenant, purpose, operation, target key, policy version, run, challenge, caller key and request ID for a bounded interval. The supervisor signs the scoped process measurements and validity interval. These measurements bind PID, UID, GID, boot ID, process start ticks, interpreter digest, argument-vector digest and the digest of the fixed caller source on disk. A witness countersigns that qualification. The target consults a separately retained local witness reference at admission.
3. The caller signs its dispatch. The target obtains credentials from the connection and message, compares live observations with enrollment, and verifies the request and both authorities. It uses target time and a durable high-water mark. The resource owner controls grant revocation.
4. The target commits the signed decision and exact evidence to SQLite, then advances a signed logical checkpoint in a separate directory before handing a successful result to the transport. A second read for the enrolled operation is refused. The receipt binds the exact operation, request and response digest.
5. After an ambiguous response, the original, still-live caller can reconcile the exact dispatch while its original qualification and grant remain current. Reconciliation returns only the historical receipt. An authorized reconciliation that arrives before the read fences that operation against later dispatch. The target rechecks clock and witness reference after checkpointing. If either has invalidated an admission, it withholds the body and leaves the committed admission consumed. A client that loses the connection after dispatch returns `UNKNOWN` and can reconcile its original packet. The ledger's `release_count` counts committed admissions. Only the receiver can observe whether the original response arrived.

## Interpreting a result

| Claim | Boundary |
| --- | --- |
| Owner approval | A pinned fixture key signs an exact scope and validity interval. The operator enrolls the school authority. Legal consent and student eligibility are outside the fixture. |
| Live caller | The target compares Linux credentials and process measurements with the enrolled caller. It trusts the kernel, launcher, interpreter, source and clock. The source and argument digests identify observations at sampling time. Loaded Python module contents, subsequent memory changes, continuous execution integrity and confinement remain unqualified. |
| Qualification and authorization | Separate keys sign different records. A witness countersigns a qualification statement. One operator administers the synthetic keys and evidence stores. The qualification runner supplies and retains a fresh challenge before starting the experiment. A standalone run accepts an operator's 32-byte hexadecimal challenge via `--challenge` on both the demo and verifier commands. The local witness reference is a digest, with no independently retained monotonic history. |
| Restart and rollback | The original receipt survives restart. Divergence between SQLite and the separately retained target checkpoint stops service. Coordinated restoration of both stores lies outside the rollback check. |
| Delivery | The successful trial observes one response. A portable receipt authenticates the target's admission assertion and response digest. The verifier does not observe a disk commit, current revocation state, or network delivery. A lost reply leaves delivery uncertain. |
| Direct access | The local trial tests the Unix service with another process under the same UID. The host supplies one authorized account. Cross-UID custody is `UNSUPPORTED`. |

A program with the same OS identity may have filesystem access to the target key or ledger. The target holds its own checkpoint, and the fictional response is guessable from source. Independent key custody, confidentiality against that account, and independent witness administration are unestablished. Assurance remains `SIMULATED_POLICY_ONLY`, confinement and production are `BLOCKED`, and certification is `NOT_ISSUED`.
