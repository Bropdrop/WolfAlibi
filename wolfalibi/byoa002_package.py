"""Offline historical verification of a measured trial and its separately authorized target record."""

from hashlib import sha256
import json
import re

from alibi import canon, verify_sig
from .byoa_attestation import verify_trial
from .byoa002_enrollment import check_expected, digest


PACKAGE = "quorvane.byoa002.public-package.v1"
PINS = "quorvane.byoa002.external-expectations.v1"
OBSERVATIONS = "quorvane.byoa002.operator-observations.v1"
_OBSERVATIONS_DOMAIN = b"quorvane/byoa002/operator-observations/v1"
_RECORDS = {"challenge", "grant", "request", "report", "receipt", "ack"}
_PIN_FIELDS = {"schema", "expected_trial", "enrollment", "previous", "head"}
_LIMITS = {"cross_uid_custody": "UNSUPPORTED", "independent_custody": "UNSUPPORTED",
           "production": "BLOCKED", "confinement": "BLOCKED", "certification": "NOT_ISSUED",
           "settlement": "UNESTABLISHED", "current_authority": "NOT_ISSUED",
           "assurance": "SIMULATED_POLICY_ONLY"}


class _Unavailable(ValueError):
    """An independent reference, required record or verification path is unavailable."""


def _json_bytes(obj, limit):
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(data) > limit:
        raise ValueError("public verification input exceeds the size limit")
    return data


def _clone(obj):
    return json.loads(_json_bytes(obj, 512 * 1024))


def _fields(obj, names, label):
    if obj is None or (type(obj) is dict and (names - obj.keys())):
        raise _Unavailable("missing " + label)
    if type(obj) is not dict or obj.keys() != names:
        raise ValueError("unexpected " + label + " fields")


def _head(obj):
    _fields(obj, {"generation", "digest"}, "retained history head")
    if (type(obj["generation"]) is not int or not 0 <= obj["generation"] < 2 ** 63
            or type(obj["digest"]) is not str or not re.fullmatch(r"[a-f0-9]{64}", obj["digest"])):
        raise ValueError("invalid independently retained head")


def _pins(expected):
    expected = _clone(expected)
    _fields(expected, _PIN_FIELDS, "external expectations")
    if expected["schema"] != PINS:
        raise ValueError("unsupported external expectations version")
    if type(expected["expected_trial"]) is not dict or type(expected["enrollment"]) is not dict:
        raise _Unavailable("missing measurement expectations or external enrollment")
    _head(expected["previous"])
    _head(expected["head"])
    if expected["head"]["generation"] != expected["previous"]["generation"] + 1:
        raise ValueError("expected heads do not describe one retention step")
    check_expected(expected["enrollment"], expected["expected_trial"])
    return expected


def make_pins(*, expected_trial, enrollment, previous, head):
    """Take public references from the reviewer and its independently retained history."""
    return _pins({"schema": PINS, "expected_trial": expected_trial, "enrollment": enrollment,
                  "previous": previous, "head": head})


def make_package(*, challenge, grant, request, report, receipt, ack):
    """Bundle already signed records. The package supplies no public trust pins."""
    return _clone({"schema": PACKAGE, "challenge": challenge, "grant": grant, "request": request,
                   "report": report, "receipt": receipt, "ack": ack})


def _verify(package, expected):
    from .byoa002_verifier import verify_ack, verify_challenge
    from .byoa002_target import verify_release

    pins = _pins(expected)
    docs = _clone(package)
    _fields(docs, {"schema", *_RECORDS}, "public package")
    if docs["schema"] != PACKAGE:
        raise ValueError("unsupported public package version")
    for name in sorted(_RECORDS):
        if docs[name] is None:
            raise _Unavailable("missing signed " + name)
        if type(docs[name]) is not dict:
            raise ValueError("malformed signed " + name)
    trial_expected = pins["expected_trial"]
    enrollment = pins["enrollment"]
    historical = verify_trial(docs["report"], trial_expected)
    if historical["outcome"] == "BLOCKED":
        raise _Unavailable(historical["reason"])
    if historical["outcome"] != "VERIFIED":
        raise ValueError(historical["reason"])
    # Check the signed challenge at the 001 target's signed pre-release instant.
    # No present clock, current revocation or current permission is inferred offline.
    q = verify_challenge(docs["challenge"], expected=trial_expected, enrollment=enrollment,
                         now=historical["authorization"]["read"]["authorized_at"])
    ack = verify_ack(docs["ack"], expected=trial_expected, enrollment=enrollment,
                     challenge=docs["challenge"], receipt=docs["receipt"])
    if canon(q["previous"]) != canon(pins["previous"]) or canon(ack["head"]) != canon(pins["head"]):
        raise ValueError("history differs from the supplied prior or final head")
    target = verify_release(expected=trial_expected, enrollment=enrollment,
                            **{name: docs[name] for name in _RECORDS})
    if (target.get("outcome") != "VERIFIED" or target.get("claim") != "HISTORICAL_RETAINED_RELEASE_COMMITMENT"
            or target.get("present_authority") != "NOT_ISSUED" or target.get("recipient_delivery") != "NOT_ESTABLISHED"):
        raise ValueError("signed target record did not verify")
    return {
        **_LIMITS, "outcome": "VERIFIED", "claim": "HISTORICAL_MEASURED_TRIAL_AND_RETAINED_TARGET_RECORD",
        "revision": enrollment["revision"], "run_id": historical["run_id"], "challenge": historical["challenge"],
        "observation": historical["observation"], "execution": historical["execution"],
        "bootstrap_read": {"authorization": historical["authorization"]["read"], "effect": historical["effect"]["broker_read"]},
        "authorization": {"owner_pub": enrollment["owner_pub"], "operator_pub": enrollment["operator_pub"],
                          "target_pub": enrollment["target_pub"], "verifier_pub": enrollment["verifier_pub"],
                          "owner_grant_sha256": digest(docs["grant"]), "operator_request_sha256": digest(docs["request"]),
                          "signed_challenge_sha256": digest(docs["challenge"])},
        "target": target, "history": {"previous": q["previous"], "head": ack["head"],
                                     "receipt_sha256": digest(docs["receipt"]), "ack_sha256": digest(docs["ack"])},
        "package_sha256": digest(docs), "expectations_sha256": digest(pins),
    }


def verify_package(package, expected):
    """Verify the evidence under the caller's public inputs without launching a process or service."""
    try:
        return _verify(package, expected)
    except (_Unavailable, ImportError) as exc:
        return {**_LIMITS, "outcome": "BLOCKED", "reason": str(exc)}
    except ValueError as exc:
        return {**_LIMITS, "outcome": "REJECTED", "reason": str(exc)}
    except Exception as exc:
        # A verification path which cannot run supplies no security decision.
        return {**_LIMITS, "outcome": "BLOCKED", "reason": "verification did not complete",
                "error_type": type(exc).__name__}


def _observation_payload(package, expected, observations):
    checked = verify_package(package, expected)
    if checked["outcome"] != "VERIFIED":
        raise _Unavailable("operator observations require a verified public package")
    encoded = _json_bytes(observations, 8 * 1024 * 1024)
    submitted = json.loads(encoded)
    if type(submitted) is not dict or submitted.get("tested_revision") != checked["revision"]:
        raise ValueError("operator report differs from the expected source revision")
    return {"type": OBSERVATIONS, "classification": "OPERATOR_REPORTED",
            "operator_pub": checked["authorization"]["operator_pub"],
            "revision": checked["revision"], "package_sha256": checked["package_sha256"],
            "expectations_sha256": checked["expectations_sha256"],
            "observations_sha256": sha256(encoded).hexdigest()}


def sign_observations(package, expected, observations, operator_signer):
    """Sign the canonical report digest after the run. The report remains a separate document."""
    payload = _observation_payload(package, expected, observations)
    if operator_signer.pub.hex() != payload["operator_pub"]:
        raise ValueError("operator key differs from the external enrollment")
    return {"payload": payload, "signature": operator_signer.sign(_OBSERVATIONS_DOMAIN, canon(payload)).hex()}


def verify_observations(attestation, package, expected, observations):
    """Authenticate the operator's attribution. No test result acquires independent custody."""
    try:
        attestation = _clone(attestation)
        _fields(attestation, {"payload", "signature"}, "operator observation signature")
        payload = _observation_payload(package, expected, observations)
        signature = attestation["signature"]
        if (canon(attestation["payload"]) != canon(payload) or type(signature) is not str
                or not re.fullmatch(r"[0-9a-f]{128}", signature)
                or not verify_sig(bytes.fromhex(payload["operator_pub"]), _OBSERVATIONS_DOMAIN,
                                  canon(payload), bytes.fromhex(signature))):
            raise ValueError("operator observation signature or document binding differs")
        return {**_LIMITS, "outcome": "VERIFIED", "claim": "OPERATOR_REPORTED_QUALIFICATION_RESULTS",
                "classification": "OPERATOR_REPORTED", "observations_sha256": payload["observations_sha256"]}
    except (_Unavailable, ImportError) as exc:
        return {**_LIMITS, "outcome": "BLOCKED", "reason": str(exc)}
    except ValueError as exc:
        return {**_LIMITS, "outcome": "REJECTED", "reason": str(exc)}
    except Exception as exc:
        # A verification path which cannot run supplies no security decision.
        return {**_LIMITS, "outcome": "BLOCKED", "reason": "verification did not complete",
                "error_type": type(exc).__name__}
