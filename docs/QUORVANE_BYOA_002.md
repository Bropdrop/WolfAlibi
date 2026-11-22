# BYOA 002 · review a gateway's synthetic release

Use this offline trial to answer two questions. Did the approved Python decision function complete its measured BYOA 001 run? Did the owner of a second synthetic resource accept the exact operation from the currently enrolled gateway? The second service owns its disposition and ledger. A terminal cell report is one input to the owner's decision.

## Reproduce the local protocol

Use a trusted, clean WolfAlibi checkout on a disposable Linux x86-64 host. Supply the commit and tree obtained from an independent review of the candidate. The execution requirements include unprivileged Bubblewrap namespaces, the supported system Python and runtime mounts, libseccomp, pidfds, openat2, Linux Unix peer credentials and the necessary procfs access. Use the tested, already installed local dependencies. Do not submit unreviewed code, provider keys or real records.

```sh
umask 077
work=$(mktemp -d)
git rev-parse HEAD HEAD^{tree}
python -I scripts/byoa002_demo.py run --consent \
  --expect-commit "$EXPECTED_COMMIT" --expect-tree "$EXPECTED_TREE" \
  --output "$work/trial"
```

The demonstration runs two fresh local ceremonies. One returns the authorized response. The other discards the reply to its sole dispatch attempt and reconciles the original record after restart. Each produces a public package, detached expectations and operator observations. Inspect the first under `trial/` and the second under `trial/lost-reply/`. An operator controlling every role can check the protocol locally. The same operator also controls the keys, private state and system on which those records were produced. Preserve that limitation in every exported result. Transfer only explicitly public artifacts. Retain the run directory privately until reconciliation.

For exact-tree qualification, the harness checks the inherited and new suites, their combined count, mutations, historical packages and the actual demonstration. It signs the observations as an operator statement. The public output directory must be new and outside the checkout. Both measured ceremonies use fresh 001 witness roots. A sequence of real 001 cells over one advancing witness lineage remains unqualified.

```sh
python -I scripts/qualify_byoa002.py --consent --expect-commit "$EXPECTED_COMMIT" --expect-tree "$EXPECTED_TREE" \
  --public-dir "$work/qualification" > "$work/qualification-output.json"
```

To authenticate the detached qualification statement, provide the previously retained expectations and the operator attachment. The result attributes the observations to the enrolled operator. Its signature cannot establish independent administration.

```sh
python -I scripts/byoa002_demo.py verify --package "$work/qualification/package.json" \
  --expect "$RETAINED_EXPECTATIONS" --observations "$work/qualification/qualification.json" \
  --operator-attestation "$work/qualification/signed-qualification.json"
```

Public package, expectations and result files are published sequentially. Interruption can leave a prefix of those files. Retain the original state, reconcile the original operation, and independently verify any recovered evidence. Do not dispatch again to replace a missing report.

## Enroll independent principals

On a separately approved host, arrange independent control of the verifier, resource owner and operator. At minimum the gateway and target for the kernel custody test require two independently provisioned ordinary non-root accounts. Each operator should know which keys, files and Unix endpoint they control. Their real, effective, saved and filesystem identities must agree with that provisioning. Inspect actual group memberships and capabilities. A username, namespace mapping or successful same-UID trial cannot establish independent custody.

Keep private roots mode 0700 and signing material private to its respective role. Give the gateway and owner access to the trusted source checkout and interpreter required by the measured launch profile, with path and content protected against substitution. Choose a short socket path in an owner-controlled parent traversable by the enrolled gateway. Unix pathname limits, procfs restrictions and local account permissions can make the procedure unavailable on a particular host. Preserve those host settings.

1. **Exchange identity pins.** Each principal provisions its own identity and retains its signing key. Give the public role identities and approved source revision to the other principals through an authenticated channel. Verify the actual file digests or key values out of band. Keep the public packets distinct from each recipient's previously retained reference.
2. **Measure and enroll the gateway.** Start the trusted gateway under the assigned operator account. Keep that process live through authorization and dispatch. Give its public process coordinates and expected socket path to the owner. The owner observes the live process under the stated kernel policy and enrolls the exact role, code and operation. A new process cannot inherit a previous process's live dispatch approval.
3. **Issue a challenge and grant.** The verifier retains exact run expectations and its challenge. The owner separately authorizes the allowed synthetic effect. Each principal checks the other's authenticated inputs. The verifier retains its state and reference across the trial. The operator receives public packets, consents and executes the reviewed BYOA 001 decision package.
4. **Submit one operation.** The live gateway presents its operator-signed request and cell evidence. The owner independently checks the request, live peer, verifier response, current scope, expiry and revocation. Preserve the target decision and signed receipt together with the gateway outcome. Record these separately from the first cell read and wrapped callback.
5. **Reconcile an ambiguous response.** Retain the original request identity and signed inputs. Use a separately signed reconciliation request and the read-only disposition from the owner's authoritative record. A matching original receipt and stable effect count support a historical result. A missing or divergent retained record requires investigation. Do not replay a dispatch to resolve uncertainty.

If a genuinely provisioned pair is unavailable, record cross-UID custody as `UNSUPPORTED`. Independent administration additionally requires separately controlled verification and durable history. Separate directories under one operator cannot establish those conditions.

## Check historical evidence

The reviewer takes a public package and an independently retained expectations file. Inspect the selected revision, role keys, run/challenge, operation, policy epoch and retained history reference before invoking the verifier. A pin copied out of the package under examination cannot independently authenticate that package.

```sh
python -I scripts/byoa002_demo.py verify \
  --package "$PUBLIC_PACKAGE" --expect "$RETAINED_EXPECTATIONS"
```

Report the outcomes for observed callbacks, historical cell execution, verifier state, owner authorization, target effects and independent custody separately. A valid historical result under the trusted pins confers no current authority and creates no new effect. Keep `BROKER_ONLY` for scoped broker evidence and `OBSERVATIONAL_ONLY` for callback telemetry. Operational confinement and production remain blocked and certification is not issued.

[Trust boundary and open gates](QUORVANE_BYOA_002_BOUNDARY.md) · [Qualification controls](QUORVANE_BYOA_002_CONTROLS.md) · [Cell prerequisites and first read](QUORVANE_BYOA_001.md)

## Role-specific command reference

Each block runs as the named operator on the same approved offline host. Use the same immutable checkout and interpreter at the same absolute paths. Set `REPO`, `PYTHON`, `MANIFEST`, `TARGET_SOCKET` and `WITNESS_SOCKET` to agreed absolute paths. Give each principal its own `PRIVATE` and public-document workspace `P`. Each `$P` filename below means a local copy transferred and authenticated by the named recipient. Output filenames must be new. Choose owner-controlled socket parents traversable by authorized clients. Keys and databases stay private.

```bash
umask 077
cd "$REPO"
q() { "$PYTHON" -I "$REPO/scripts/byoa002_principal.py" "$@"; }
b() { "$PYTHON" "$REPO/wolfalibi_cli.py" byoa "$@"; }
role=(--keys "$PRIVATE/keys" --enrollment "$P/enrollment.json")
store=(--state "$PRIVATE/state")
```

**Provision.** Each principal runs only its own `q provision --role ROLE --keys "$PRIVATE/keys"`, using `operator`, `owner` or `verifier` for `ROLE`. Exchange their `keys/public.json` files as `operator.json`, `owner.json` and `verifier.json`. The owner creates distinct grant and target-receipt keys. The operator also prepares the inherited 001 trial and its bootstrap owner. Transfer their public files as `trial.json` and `boot-owner.json`. The 001 bootstrap owner and 002 resource owner have separate signing roles.

```bash
# Operator
b provision --role trial --output "$PRIVATE/trial"
b provision --role owner --output "$PRIVATE/boot-owner"
# Keep this process running in a dedicated terminal. Its stdin accepts compact JSON lines.
"$PYTHON" -I "$REPO/scripts/byoa002_gateway.py" "$TARGET_SOCKET"
```

**Owner.** Obtain the gateway's `READY.peer.pid` and the authorized operator UID separately. Independently measure the gateway and compare the interpreter, source and checkout revision with the reviewed artifacts. Enroll it and give the verifier and operator an authenticated enrollment digest and the public document.

```bash
"$PYTHON" -I scripts/byoa002_peer_control.py measure --gateway-pid "$GATEWAY_PID" \
  --gateway-uid "$OPERATOR_UID" --socket "$TARGET_SOCKET"
q enroll --manifest "$MANIFEST" --trial-pins "$P/trial.json" --bootstrap-owner "$P/boot-owner.json" \
  --operator-pin "$P/operator.json" --owner-pins "$P/owner.json" --verifier-pin "$P/verifier.json" \
  --gateway-pid "$GATEWAY_PID" --socket "$TARGET_SOCKET" --epoch 1 --approve-pins --output "$P/enrollment.json"
```

**Verifier.** Initialize once. Save the initial head independently. Reserve a random nonce and run ID and give `fresh.json` to the operator. Keep the original.

```bash
q init-verifier "${role[@]}" "${store[@]}"
q head "${role[@]}" "${store[@]}" --output "$P/prior.json"
q fresh "${role[@]}" "${store[@]}" --expect-head "$P/prior.json" --output "$P/fresh.json"
```

**Operator.** Set `RUN_ID` and `CHALLENGE` from the verifier's `fresh.json`. Use them in the inner 001 trial. Give the verifier and owner a public copy of `review/expected.json` named `expected.json`. The operator retains the inner runner's private review files. Coordinate the remaining steps before the short challenge window opens.

```bash
b enroll-owner --trial "$PRIVATE/trial" --owner-pin "$P/boot-owner.json" --approve-owner
b prepare --manifest "$MANIFEST" --trial-pins "$P/trial.json" --owner-pin "$P/boot-owner.json" \
  --run-id "$RUN_ID" --challenge "$CHALLENGE" --ttl 300 --output "$PRIVATE/review"
```

**Verifier.** Check the proposed identity, scope, keys, deadline, nonce and source. Approve the exact expectations. Transfer the signed challenge and authenticated digest. Start the verifier endpoint in a dedicated terminal against the independently retained prior head.

```bash
q approve "${role[@]}" "${store[@]}" --expect-head "$P/prior.json" --expected "$P/expected.json" \
  --consent --output "$P/challenge.json"
q serve-verifier "${role[@]}" "${store[@]}" --expect-head "$P/prior.json" --socket "$WITNESS_SOCKET"
```

**Owner.** Check the approved grant scope, target and live gateway, then give `grant.json` to the operator. Initialize the target once and run it in a dedicated terminal. Independently communicate its actual PID, UID and public key to the gateway. Leave `--single-account-control` off in the two-account procedure.

```bash
q grant "${role[@]}" --expected "$P/expected.json" --challenge "$P/challenge.json" \
  --consent --output "$P/grant.json"
q init-target "${role[@]}" "${store[@]}"
q serve-target "${role[@]}" "${store[@]}" --socket "$TARGET_SOCKET" --witness-socket "$WITNESS_SOCKET"
```

**Operator.** Issue the separately enrolled 001 bootstrap grant. Run the installed local LangChain driver and verify the 001 report. Assemble the operator-signed public packet for the second operation.

```bash
b grant-read --owner "$PRIVATE/boot-owner" --expect "$P/expected.json" --approve-read --output "$P/boot-grant.json"
b qualify --framework langchain --manifest "$MANIFEST" --trial "$PRIVATE/trial" --review "$PRIVATE/review" \
  --grant "$P/boot-grant.json" --consent --output "$PRIVATE/cell"
b verify-qualification --expect "$P/expected.json" --report "$PRIVATE/cell/report.json"
q request "${role[@]}" --action dispatch --expected "$P/expected.json" --challenge "$P/challenge.json" \
  --grant "$P/grant.json" --report "$PRIVATE/cell/report.json" --output "$P/dispatch.json"
```

**Two-account controls.** Each action requires the actual live peer and an independently pinned target identity.

- Give the gateway the signed `READY.inventory`. Send one compact JSON line to its stdin containing `action="custody"`, integer `expected_target_pid` and `expected_target_uid`, the pinned `target_pub` and the full `inventory` object. Require four separately recorded `EACCES` or `EPERM` outcomes for read/open-for-write attempts on the exact key and ledger. A protected ancestor can cause the denial. The owner supplies the signed identity of any inaccessible leaf.
- Transfer the public dispatch packet to the **owner**. As owner run `"$PYTHON" -I scripts/byoa002_peer_control.py wrong-peer --target-uid "$OWNER_UID" --target-pid "$TARGET_PID" --socket "$TARGET_SOCKET" --packet "$P/dispatch.json"`. Compare with the owner's unchanged authoritative effect count. An unavailable socket cannot demonstrate authorization denial.
- Send the enrolled gateway one JSON line with `action="dispatch"`, the two integer target identity fields and `packet` set to the contents of `dispatch.json`. Save its response. Compare its public receipt and acknowledgment with the owner's and verifier's retained records.
- Use a **fresh ceremony** for a deliberate lost response. Use `action="lose-reply"` for the one dispatch attempt. Retain target and verifier state, enrollment, signing keys and pinned inputs. Stop and restart the target on the same endpoint. Pin its new PID. Restart the gateway with the same command and retain the new `READY.peer` as `new-peer.json`. Use the original approval, grant and cell report with a new `q request --action reconcile --recovery-peer "$P/new-peer.json"` and the other original request arguments. Change the output filename. Send the newly signed packet with `action="reconcile"`. Success requires the original receipt and verifier acknowledgment, one commitment and no data body or fresh dispatch. A commit without witness retention must remain unresolved.
- For administrative revocation, stop the target, run `q revoke "${role[@]}" "${store[@]}" --witness-socket "$WITNESS_SOCKET" --grant "$P/grant.json" --expected "$P/expected.json" --challenge "$P/challenge.json"`, check the result, then restart on the same state. Do not rerun initialization. This CLI procedure uses the owner's exclusive state lease. The in-process target tests exercise revocation during dispatch separately.
- As verifier export the final retained head with `q head`. Preserve both the initial and final authenticated reference outside the gateway's custody. On verifier restart supply the latest **previously retained** head. Do not adopt whatever head a newly restored database claims.

For the wrong-principal and lost-response controls, the owner can take a read-only observation in its own terminal before and after each operation. Keep the signed receipt bytes, independent witness head and exact source revision with those observations. This local query does not sign or advance a checkpoint.

```bash
"$PYTHON" -I - "$PRIVATE/state/ledger/ledger.sqlite" <<'PY'
import hashlib, json, sqlite3, sys
from contextlib import closing
from pathlib import Path
uri = Path(sys.argv[1]).resolve(strict=True).as_uri() + "?mode=ro"
with closing(sqlite3.connect(uri, uri=True)) as db:
    rows = db.execute("SELECT operation_id, receipt FROM effects ORDER BY operation_id").fetchall()
print(json.dumps({"count": len(rows), "receipts": [
    {"operation_id": op, "sha256": hashlib.sha256(raw).hexdigest()} for op, raw in rows
]}, sort_keys=True))
PY
```

To assemble public evidence from the split-role trial, retain the original dispatch packet as `dispatch.json` and the successful dispatch or reconciliation response as `reply.json`. The reviewer supplies `enrollment.json`, original 001 `expected.json`, `prior.json` and independently exported `final-head.json`. Run from the trusted checkout with `P` pointing at that reviewer's public workspace.

```bash
"$PYTHON" - "$P" <<'PY'
import json, sys
from pathlib import Path
from scripts.byoa002_principal import read
from wolfalibi.byoa002_package import make_package, make_pins
public = Path(sys.argv[1])
packet, reply = read(public / "dispatch.json"), read(public / "reply.json")
package = make_package(**{k: packet[k] for k in ("challenge", "grant", "request", "report")},
                       receipt=reply["receipt"], ack=reply["ack"])
pins = make_pins(expected_trial=read(public / "expected.json"), enrollment=read(public / "enrollment.json"),
                 previous=read(public / "prior.json"), head=read(public / "final-head.json"))
for name, document in (("package.json", package), ("expectations.json", pins)):
    with (public / name).open("x", encoding="utf-8") as file:
        json.dump(document, file, sort_keys=True)
PY
"$PYTHON" -I scripts/byoa002_demo.py verify --package "$P/package.json" --expect "$P/expectations.json"
```
