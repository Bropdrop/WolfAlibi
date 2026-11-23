#!/usr/bin/env python3
"""Independent read-only inspection of one downloaded genuine Gate B artifact.

No adapter imports, target access, journal access, fixture generation or TPM
verifier execution. Ed25519 is checked locally; upstream TPM report statements
remain evidence of the recorded CI run, not newly executed cryptography.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SOURCE = "fb97c1ec5908c8bdbd46760c29e57677977fce74"
ELF = "be8b79cdd7efb8e635b7965bf34fa691e5e4a378957f3829530a529097abe9d2"
ARCHIVE = "e830f2384383adccba7c423e8afe81d1fd0b3d6e27e66ce2aed49eae632e989c"
VERSION = "7e222b2b27b2408615a4f5b20cb31215e185ee5d6f0ae0bee2910f7479f58c2d"
BASE_CHECKS = (
    "nonce matches the request",
    "attestation key: restricted, fixed to this TPM",
    "attestation key: name matches its public area",
    "attestation key: the pinned key",
    "endorsement key: name matches its public area",
    "endorsement key: TCG default template under the endorsement policy",
    "endorsement key: the pinned key",
    "quote: ECDSA signature by the attestation key",
    "quote: signed by the key as an endorsement primary",
    "quote: carries the nonce",
    "quote: covers the PCRs the document lists",
    "quote: PCR digest matches the listed values",
    "register: ECDSA signature by the attestation key",
    "register: signed by the key as an endorsement primary",
    "register: carries the nonce",
    "register: certification names the listed index",
    "register: certified contents match the listed value",
    "quote and certification are of one TPM boot",
    "eventlog: this boot has an init record",
    "register: the document names index 0x01818E00 and PCRs 9 and 11",
    "register: public area is bound to PCRs 9 and 11 as recorded",
    "binding: PCR 9 held the expected value",
    "binding: PCR 11 held the expected value",
    "binding: made while the initrd ran",
    "register: init record is of the TPM's current reset count",
    "anchor: record digest matches the index name",
    "state: register equals the expected value",
    "config: config root history matches the quoted PCR",
)
EPOCH = r"eventlog: one init record for this TPM reset \(([1-9][0-9]{0,3}) this boot\)"
REPLAY = r"eventlog: ([1-9][0-9]{0,3}) record(s?) replay to the certified value"
ANCHOR = "anchor: PCR 9 equals the recorded value extended by the anchor"
ANCHOR_NOTE = "anchor: PCR 9 carries further measurements after the anchor; replay the logs to confirm it"
CONTRACT = set(BASE_CHECKS) | {"regex:" + EPOCH, "regex:" + REPLAY,
                             "one-of:" + ANCHOR + "|note:" + ANCHOR_NOTE}
CASES = {
    "positive": ("EVIDENCE_ACCEPTED", "REQUIRED_CHECKS_PASSED", None),
    "new-nonce-stale-evidence": ("REJECTED", "NONCE_MISMATCH", None),
    "tampered-signature": ("REJECTED", "UPSTREAM_REJECTED", "quote: ECDSA signature by the attestation key"),
    "wrong-identity": ("REJECTED", "TARGET_MISMATCH", None),
    "wrong-chain": ("REJECTED", "STATE_MISMATCH", None),
    "wrong-config": ("REJECTED", "UPSTREAM_REJECTED", "config: config root was not approved by the operator"),
    "wrong-binding": ("REJECTED", "UPSTREAM_REJECTED", "binding: PCR 9 held the expected value"),
    "expired-challenge": ("REJECTED", "CHALLENGE_EXPIRED", None),
    "revoked-policy": ("REJECTED", "POLICY_REVOKED", None),
}
MUTATIONS = {
    "wrong-identity": ("enrollment", "ak_name"),
    "wrong-chain": ("expected", "chain"),
    "wrong-config": ("expected", "config_root"),
    "wrong-binding": ("expected", "binding_pcrs", "9"),
}
RECEIPT_KEYS = {
    "schema", "receipt_id", "instance_id", "challenge_id", "nonce", "target_id",
    "policy_sha256", "enrollment_record_sha256", "evidence_sha256", "assurance", "outcome",
    "reason_code", "issued_at_ms", "expires_at_ms", "started_at_ms", "completed_at_ms",
    "upstream", "scope", "authorization", "limitations",
}
CHALLENGE_KEYS = {"schema", "instance_id", "challenge_id", "nonce", "policy_sha256",
                  "target_id", "issued_at_ms", "expires_at_ms"}


class ReviewFailure(Exception):
    pass


def need(condition, label):
    if not condition:
        raise ReviewFailure(label)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON member")
            result[key] = value
        return result

    def no_float(_):
        raise ReviewFailure("floating point/nonfinite JSON is unsupported")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_float=no_float, parse_constant=no_float)


def expected_paths():
    names = {"artifact-manifest.json", "baseline-manifest.json", "public-key.json",
             "commands.json", "summary.json"}
    names |= {"inputs/" + name for name in (
        "enrollment.json", "target-build.txt", "runtime-template.txt", "config-root.txt",
        "primary.der", "boot.der", "verifier-version.txt", "prediction.json", "baseline-status.json")}
    names |= {f"cases/{case}/{name}.json" for case in CASES for name in (
        "policy", "challenge", "evidence", "receipt", "receipt-verification", "result")}
    names |= {"cases/tampered-signature/original-evidence.json", "cases/same-challenge-replay/result.json"}
    return names


def read_artifacts(root):
    need(root.is_dir() and not root.is_symlink(), "artifact directory missing or symlinked")
    found = {}
    for path in root.rglob("*"):
        info = path.lstat()
        need(not stat.S_ISLNK(info.st_mode), "symlink in downloaded artifact")
        if stat.S_ISDIR(info.st_mode):
            continue
        name = path.relative_to(root).as_posix()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "non-regular/shared artifact")
        need(name in expected_paths(), "unexpected or private artifact path: " + name)
        need(0 < info.st_size <= 2_097_152, "artifact file size bound")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(2_097_153)
        need(len(raw) == info.st_size, "artifact changed during read")
        need(re.search(rb"-----BEGIN(?: [A-Z]+)* PRIVATE KEY-----", raw) is None,
             "private-key PEM marker in public artifact")
        need(not raw.startswith(b"SQLite format 3\0"), "database in public artifact")
        found[name] = raw
    need(set(found) == expected_paths(), "incomplete public artifact path set")
    need(sum(map(len, found.values())) <= 16_777_216, "total artifact byte bound")
    manifest = parse(found["artifact-manifest.json"])
    need(manifest["schema"] == "wolfalibi.shirudo.public-artifacts.v1" and
         manifest["private_state_exported"] is False, "public artifact manifest scope")
    need(set(manifest["files"]) == set(found) - {"artifact-manifest.json"}, "manifest inventory mismatch")
    for name, pin in manifest["files"].items():
        need(pin == {"bytes": len(found[name]), "sha256": sha(found[name])}, "manifest hash: " + name)
    return found


def signed_payload(value, public_key):
    need(type(value) is dict and set(value) == {"schema", "payload", "signature"}
         and value["schema"] == "wolfalibi.signed-record.v1"
         and type(value["payload"]) is dict, "signed envelope schema")
    need(re.fullmatch(r"[0-9a-f]{128}", value["signature"]) is not None, "Ed25519 signature shape")
    public_key.verify(bytes.fromhex(value["signature"]), canonical(value["payload"]))
    return value["payload"]


def mutated(value):
    return value[:-1] + ("1" if value[-1] == "0" else "0")


def check_report(upstream, accepted, failure):
    need(upstream["execution_profile"] == "UPSTREAM_CLI", "genuine upstream execution profile")
    need(upstream["observed_binary_sha256"] == ELF and upstream["observed_version_id"] == VERSION,
         "observed upstream executable pins")
    report = upstream["report"]
    need(type(report) is dict and set(report) == {"schema", "verdict", "checks"}
         and type(report["schema"]) is int and report["schema"] == 1, "raw report schema")
    need(upstream["report_sha256"] == sha(canonical(report)), "raw report canonical digest")
    contract = upstream["required_checks"]
    need(type(contract) is list and len(contract) == len(CONTRACT) and set(contract) == CONTRACT,
         "reviewed required upstream check contract")
    checks = report["checks"]
    need(type(checks) is list and 1 <= len(checks) <= 4096, "upstream check count")
    index = {}
    for check in checks:
        need(type(check) is dict and set(check) == {"text", "result"} and
             check["result"] in {"ok", "fail", "note"} and type(check["text"]) is str,
             "upstream check schema")
        need(check["text"] not in index, "duplicate upstream check")
        index[check["text"]] = check["result"]
    failures = {text for text, result in index.items() if result == "fail"}
    if accepted:
        need(upstream["exit_code"] == 0 and report["verdict"] == "ok" and not failures,
             "positive upstream verdict")
        need(all(index.get(text) == "ok" for text in BASE_CHECKS), "positive mandatory upstream check")
        need(any(re.fullmatch(EPOCH, text) and result == "ok" for text, result in index.items()), "init epoch check")
        need(any(re.fullmatch(REPLAY, text) and result == "ok" for text, result in index.items()), "event replay check")
        need(index.get(ANCHOR) == "ok" or index.get(ANCHOR_NOTE) == "note", "anchor check")
    else:
        need(upstream["exit_code"] == 1 and report["verdict"] == "fail", "negative upstream verdict")
        need(failures == {failure}, "specific upstream failure without unrelated failures")
    return sorted(failures)


def review(root, expected_target):
    raw = read_artifacts(root)
    obj = {name: parse(value) for name, value in raw.items() if name.endswith(".json")}
    summary, baseline = obj["summary.json"], obj["baseline-manifest.json"]
    need(summary["schema"] == "wolfalibi.shirudo.real-lab.v1" and summary["result"] == "PASS",
         "Gate B did not record full success")
    need(summary["assurance"] == "LAB_VTPM" and summary["source_commit"] == SOURCE
         and summary["verifier_sha256"] == ELF and summary["positive_evidence_accepted"] is True
         and summary["target_contact"] is True and summary["private_adapter_state_removed"] is True,
         "Gate B summary scope and execution claims")
    need(all(summary[key] is False for key in ("current_authorization", "hardware_qualification",
                                              "measured_uki_qualification")), "unsupported authority/assurance claim")
    need(baseline["source_commit"] == SOURCE and baseline["verifier_sha256"] == ELF
         and baseline["verifier_archive_sha256"] == ARCHIVE
         and baseline["verifier_version_id"] == VERSION, "baseline upstream build pins")
    need(raw["inputs/verifier-version.txt"].decode().strip() == VERSION, "retained verifier version")
    need(baseline["baseline_before_all_challenges"] is True
         and baseline["expectations_from_submitted_evidence"] is False, "baseline trust chronology")
    enrollment = obj["inputs/enrollment.json"]
    need(enrollment["source"] == "test-vm" and len(enrollment["nodes"]) == 1, "builder enrollment schema")
    node = enrollment["nodes"][0]
    need(node["node_id"] == expected_target, "out-of-band CI target name")
    need(baseline["builder_record_sha256"] == sha(raw["inputs/enrollment.json"]), "builder enrollment digest")
    for name in ("inputs/primary.der", "inputs/boot.der"):
        x509.load_der_x509_certificate(raw[name])
    positive_policy = obj["cases/positive/policy.json"]
    expected = positive_policy["expected"]
    need(expected["chain"] == baseline["expected_chain"] == obj["inputs/prediction.json"]["register_at_boot"],
         "chain from retained host prediction")
    need(expected["config_root"] == baseline["config_root"] == raw["inputs/config-root.txt"].decode().strip(),
         "config root from retained host artifact")
    need(expected["config_pcr"] == baseline["config_pcr"] == 14 and expected["quote_pcrs"] == {}, "configuration PCR policy")
    need(baseline["config_prefix"] == "config-boot-keys" and
         b"config.pcr = 14\n" in raw["inputs/runtime-template.txt"], "retained host runtime template")
    status = obj["inputs/baseline-status.json"]
    need(expected["binding_pcrs"] == baseline["binding_pcrs"] == {
        "9": status["tpm"]["pcr_before"], "11": status["tpm"]["phase_before"]}, "trusted baseline PCR inputs")
    need(status["tpm"]["chain"] == expected["chain"] and
         status["config"]["root_hash"] == expected["config_root"] and
         status["config"]["activation_pending"] is False and status["tpm"]["bound_in"] == "initrd",
         "trusted baseline consistency")
    target_build = raw["inputs/target-build.txt"].decode().strip()
    need(status["version_id"] == target_build == baseline["target_build_id"], "target build metadata")
    need(positive_policy["enrollment"] == {"method": "trusted_builder", "record_sha256": baseline["builder_record_sha256"],
                                         "ak_name": node["ak_name"], "ek_name": node["ek_name"]}, "positive builder pins")
    key_record = obj["public-key.json"]
    need(re.fullmatch(r"[0-9a-f]{64}", key_record["public_key"]) is not None, "retained public key shape")
    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_record["public_key"]))
    commands = obj["commands.json"]
    collected = {item["stage"][8:]: item for item in commands if item["stage"].startswith("collect ")}
    need(len(collected) == 8 and len([x for x in commands if x["stage"].startswith("collect ")]) == 8,
         "exactly eight recorded target collection commands")
    need(set(collected) == set(CASES) - {"new-nonce-stale-evidence"}, "fresh collection case set")
    need(all(command["exit_code"] == 0 for command in commands), "failed recorded host/target command")
    results, nonces, ids, fresh_nonces, receipt_ids = [], set(), set(), set(), set()
    for case, (outcome, reason, crypto_failure) in CASES.items():
        prefix = f"cases/{case}/"
        policy = obj[prefix + "policy.json"]
        wanted = copy.deepcopy(positive_policy)
        wanted["policy_id"] = "fresh-lab-" + case
        if case == "expired-challenge":
            wanted["challenge_ttl_seconds"] = 1
        if case in MUTATIONS:
            selected = wanted
            for part in MUTATIONS[case][:-1]:
                selected = selected[part]
            last = MUTATIONS[case][-1]
            selected[last] = mutated(selected[last])
        need(policy == wanted, "case policy changed outside intended control: " + case)
        need(policy["target_id"] == expected_target and policy["assurance"] == "LAB_VTPM", "case target/assurance")
        need(policy["verifier"] == {"source_commit": SOURCE, "sha256": ELF, "version_id": VERSION,
                                     "timeout_seconds": 30}, "case verifier policy")
        challenge = signed_payload(obj[prefix + "challenge.json"], public_key)
        receipt = signed_payload(obj[prefix + "receipt.json"], public_key)
        need(set(challenge) == CHALLENGE_KEYS and challenge["schema"] == "wolfalibi.shirudo.challenge.v1", "challenge payload schema")
        need(set(receipt) == RECEIPT_KEYS and receipt["schema"] == "wolfalibi.shirudo.receipt.v1", "receipt payload schema")
        for field in CHALLENGE_KEYS - {"schema"}:
            need(receipt[field] == challenge[field], "signed challenge/receipt binding: " + case + ":" + field)
        need(challenge["instance_id"] == key_record["instance_id"] and challenge["target_id"] == expected_target
             and challenge["policy_sha256"] == sha(canonical(policy)), "challenge key/policy/target binding")
        need(re.fullmatch(r"[0-9a-f]{64}", challenge["nonce"]) is not None and
             re.fullmatch(r"[0-9a-f]{32}", challenge["challenge_id"]) is not None, "challenge randomness representation")
        need(challenge["nonce"] not in nonces and challenge["challenge_id"] not in ids, "duplicate issued challenge")
        nonces.add(challenge["nonce"]); ids.add(challenge["challenge_id"])
        need(receipt["receipt_id"] not in receipt_ids, "duplicate receipt identifier")
        receipt_ids.add(receipt["receipt_id"])
        need(receipt["outcome"] == outcome and receipt["reason_code"] == reason and receipt["assurance"] == "LAB_VTPM"
             and receipt["authorization"] == "NONE" and receipt["scope"] == "HISTORICAL_EVIDENCE_ONLY", "signed outcome: " + case)
        need(receipt["enrollment_record_sha256"] == baseline["builder_record_sha256"], "signed enrollment record digest")
        issued, expires = challenge["issued_at_ms"], challenge["expires_at_ms"]
        started, completed = receipt["started_at_ms"], receipt["completed_at_ms"]
        need(all(type(x) is int for x in (issued, expires, started, completed)), "timestamp types")
        need(issued >= baseline["baseline_recorded_at_ms"] and expires - issued == policy["challenge_ttl_seconds"] * 1000
             and issued <= started <= completed, "signed time chronology")
        if case == "expired-challenge":
            need(started >= expires, "expiry control did not actually expire")
        else:
            need(completed < expires, "non-expiry control elapsed past expiry")
        evidence = obj[prefix + "evidence.json"]
        need(evidence["schema"] == 1 and evidence["kind"] == "shirudo-attestation" and evidence["pcr_bank"] == "sha256",
             "evidence schema")
        if case in {"expired-challenge", "revoked-policy"}:
            need(receipt["evidence_sha256"] is None, "aborted-before-read evidence digest")
        else:
            need(receipt["evidence_sha256"] == sha(raw[prefix + "evidence.json"]), "signed exact evidence digest")
        if case == "new-nonce-stale-evidence":
            need(raw[prefix + "evidence.json"] == raw["cases/positive/evidence.json"] and evidence["nonce"] != challenge["nonce"],
                 "stale evidence control")
        else:
            need(evidence["nonce"] == challenge["nonce"], "fresh evidence nonce")
            fresh_nonces.add(evidence["nonce"])
            collection = collected[case]
            need(issued <= collection["started_at_ms"] <= collection["completed_at_ms"] <= started,
                 "collection after challenge and before assessment")
        need(evidence["ak"]["name"] == node["ak_name"] and evidence["ek"]["name"] == node["ek_name"]
             and evidence["register"]["value"] == expected["chain"], "unchanged real target state across controls")
        need(evidence["version_id"] == target_build, "collected target build metadata")
        upstream = receipt["upstream"]
        need(upstream["source_commit"] == SOURCE and upstream["expected_binary_sha256"] == ELF
             and upstream["expected_version_id"] == VERSION, "signed verifier expectations")
        if case == "positive" or crypto_failure:
            failures = check_report(upstream, case == "positive", crypto_failure)
        else:
            need(upstream["execution_profile"] == "NO_VERIFIED_RESULT" and upstream["required_checks"] == []
                 and all(upstream[x] is None for x in ("observed_binary_sha256", "observed_version_id", "exit_code",
                                                      "report", "report_sha256")), "preflight rejection execution profile")
            failures = []
        verification = obj[prefix + "receipt-verification.json"]
        need(verification == {"signature_valid": True, "historical_outcome": outcome,
                              "current_authorization": False, "current_target_state": "NOT_ESTABLISHED",
                              "assurance": "LAB_VTPM", "receipt_id": receipt["receipt_id"], "scope": "HISTORICAL_EVIDENCE_ONLY"},
             "retained verification-result consistency")
        result = obj[prefix + "result.json"]
        need(result["case"] == case and result["result"] == "PASS" and result["outcome"] == outcome
             and result["reason_code"] == reason and result["execution_profile"] == upstream["execution_profile"]
             and result["receipt_signature_valid"] is True and result["fresh_collection"] == (case != "new-nonce-stale-evidence")
             and result["evidence_mutated"] == (case == "tampered-signature"), "case result consistency")
        results.append({"case": case, "outcome": outcome, "reason": reason, "upstream_failures": failures})
    original = obj["cases/tampered-signature/original-evidence.json"]
    changed = copy.deepcopy(original)
    changed["quote"]["signature"] = mutated(changed["quote"]["signature"])
    need(changed == obj["cases/tampered-signature/evidence.json"], "signature control changes only the final signature nibble")
    replay = obj["cases/same-challenge-replay/result.json"]
    need(replay == {"case": "same-challenge-replay", "result": "PASS", "code": "CHALLENGE_SPENT",
                    "fresh_collection": False, "original_receipt_unchanged": True}, "recorded replay-control result")
    need(len(summary["cases"]) == 10 and {item["case"] for item in summary["cases"]} == set(CASES) | {"same-challenge-replay"},
         "ten summary control cases")
    for item in summary["cases"]:
        need(item == obj[f"cases/{item['case']}/result.json"], "summary/case equality")
    need(len(fresh_nonces) == 8 and len(nonces) == 9, "fresh collection/issued challenge counts")
    return {
        "schema": "wolfalibi.shirudo.independent-artifact-review.v1", "result": "PASS",
        "artifact_files": len(raw), "manifest_digests_verified": len(raw) - 1,
        "ed25519_signatures_verified": 18, "signed_receipts": 9, "issued_challenges": 9,
        "control_cases": 10, "distinct_fresh_collection_nonces": 8, "cases": results,
        "pcr11_is_zero": baseline["binding_pcrs"]["11"] == "0" * 64,
        "no_unexpected_or_private_artifact_files": True, "current_authorization": False,
        "tpm_verifier_reexecuted": False,
        "review_limits": [
            "Ed25519 signatures were independently verified against the retained CI public key; that key has no separate external identity anchor.",
            "TPM verification results are signed records of the genuine pinned verifier's CI execution; this review does not execute the TPM verifier again.",
            "Replay denial is an unsigned CI control result checked for artifact consistency; the private journal is intentionally absent.",
            "Revocation and private-state cleanup are recorded CI assertions; the deleted private state cannot be reexamined after download.",
            "Expiry/revocation assessments intentionally have no signed evidence digest because they stop before reading the evidence file.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--expected-target", required=True)
    args = parser.parse_args()
    try:
        result = review(args.artifact, args.expected_target)
    except Exception as exc:
        result = {"schema": "wolfalibi.shirudo.independent-artifact-review.v1", "result": "FAIL",
                  "error_type": type(exc).__name__, "error": str(exc)}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
