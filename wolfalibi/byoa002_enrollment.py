"""Externally provisioned public identity pins for one synthetic BYOA 002 ceremony."""

import re

from alibi import H, canon
from .byoa_attestation import _checked_inputs, _snapshot
from .finance_records import validate_peer
from .stage3 import FIXTURE_BYTES

SCHEMA = "quorvane.byoa002.enrollment.v1"
PRINCIPALS = ("operator_pub", "owner_pub", "target_pub", "verifier_pub")
TRIAL_ROLES = ("broker_pub", "witness_pub", "supervisor_pub", "owner_pub", "target_pub")
FIXED = {"schema": SCHEMA, "target_id": "synthetic-records-002",
         "operation": "read", "resource": "fictional-record-002"}


def digest(value):
    return H(canon(value)).hex()


def validate_enrollment(enrollment):
    value = _snapshot(enrollment)
    fields = {*FIXED, *PRINCIPALS, "trial_pins", "gateway", "owner_uid", "policy_epoch",
              "revision", "manifest_sha256", "profile_sha256", "trial_witness_sha256"}
    if type(value) is not dict or set(value) != fields or any(value[k] != v for k, v in FIXED.items()):
        raise ValueError("unsupported BYOA 002 enrollment")
    if type(value["trial_pins"]) is not dict or set(value["trial_pins"]) != set(TRIAL_ROLES):
        raise ValueError("missing prior trial role pins")
    keys = [value[k] for k in PRINCIPALS] + list(value["trial_pins"].values())
    for value_hex in [*keys, value["manifest_sha256"], value["profile_sha256"], value["trial_witness_sha256"]]:
        if type(value_hex) is not str or not re.fullmatch("[0-9a-f]{64}", value_hex):
            raise ValueError("invalid key or digest in enrollment")
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate enrollment role key")
    revision = value["revision"]
    if (type(revision) is not dict or set(revision) != {"commit", "tree"}
            or not all(type(v) is str and re.fullmatch("[0-9a-f]{40}", v) for v in revision.values())):
        raise ValueError("invalid source revision in enrollment")
    if any(type(value[k]) is not int or not 0 < value[k] < 2**31 for k in ("policy_epoch", "owner_uid")):
        raise ValueError("invalid owner UID or policy epoch")
    validate_peer(value["gateway"])
    return value


def check_expected(enrollment, expected):
    enrolled = validate_enrollment(enrollment)
    pins, _, _ = _checked_inputs(expected)
    profile = pins["contract"]["profile"]
    if (any(pins[k] != v for k, v in enrolled["trial_pins"].items())
            or profile["byoa"]["manifest_sha256"] != enrolled["manifest_sha256"]
            or digest(profile) != enrolled["profile_sha256"]
            or enrolled["trial_witness_sha256"] != pins["expected_witness_state_digest"]
            or pins["contract"]["fixture_sha256"] != H(FIXTURE_BYTES).hex()
            or pins["contract"]["key"] != "protected.txt"):
        raise ValueError("trial does not match enrolled role pins, source, profile or resource")
    return pins
