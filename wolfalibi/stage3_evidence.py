"""Offline verifier for the one-read Stage 3 synthetic execution transcript."""

import json

from alibi import (
    Broker, DOM_B, DOM_RB, DOM_RW, DOM_W, DOM_WS, DurableWitness, H, OPS,
    canon, cp_hash, enc_entry, leaf_hash, verify_sig, verify_witness_state_anchor,
)


STAGE3_TYPE = "WOLFALIBI_STAGE3_SYNTHETIC_READ_V1"
ASSURANCE = "BROKER_ONLY"
_ZERO = "00" * 32
_CONTRACT_FIELDS = {
    "run_id", "challenge", "expires_at", "profile", "key", "fixture_sha256",
}


class _IncompleteEvidence(ValueError):
    pass


def _hex(value, length, name):
    if type(value) is not str or len(value) != 2 * length:
        raise ValueError(f"invalid {name}")
    decoded = bytes.fromhex(value)
    if decoded.hex() != value:
        raise ValueError(f"noncanonical {name}")
    return decoded


def validate_contract(contract):
    """Check the bounded external references for the single-read profile."""
    if not isinstance(contract, dict) or contract.keys() != _CONTRACT_FIELDS:
        raise ValueError("invalid run contract fields")
    run_id, key, profile = contract["run_id"], contract["key"], contract["profile"]
    if type(run_id) is not str or not 1 <= len(run_id) <= 256 or not run_id.isprintable():
        raise ValueError("invalid run identity")
    if (type(key) is not str or not 1 <= len(key) <= 512 or not key.isprintable()
            or any(part in ("", ".", "..") for part in key.split("/"))):
        raise ValueError("resource key must be canonical and root-relative")
    if type(contract["expires_at"]) is not int or contract["expires_at"] <= 0:
        raise ValueError("invalid challenge expiry")
    if not isinstance(profile, dict) or not profile:
        raise ValueError("missing launcher profile")
    try:
        profile_json = json.dumps(profile, sort_keys=True, allow_nan=False)
    except (TypeError, RecursionError) as exc:
        raise ValueError("launcher profile must be canonical JSON data") from exc
    if len(profile_json) > 32_768:
        raise ValueError("launcher profile exceeds size limit")
    _hex(contract["challenge"], 32, "challenge")
    _hex(contract["fixture_sha256"], 32, "fixture hash")


def run_marker(contract):
    """Commit the external run contract under a non-filesystem WAL key."""
    return b"\x00wolfalibi-stage3:" + H(canon(contract))


def _fields(value, expected, name):
    if not isinstance(value, dict):
        raise ValueError(f"invalid {name}")
    missing = expected - value.keys()
    if missing:
        raise _IncompleteEvidence(f"{name} missing {min(missing)}")
    if value.keys() != expected:
        raise ValueError(f"unexpected fields in {name}")


def _match(actual, expected, name):
    # Canonical comparison distinguishes integer, float and boolean values.
    if canon(actual) != canon(expected):
        raise ValueError(f"{name} mismatch")


def _check_checkpoint(record, key, epoch, predecessor, broker_pub, witness_pub):
    _fields(record, {"cp", "sig", "wsig", "leaves"}, "checkpoint record")
    sequence = epoch + 1
    leaf = enc_entry(key, OPS["r"], 1, sequence)
    cp = {
        "v": 1, "broker": broker_pub.hex(), "epoch": epoch, "prev": predecessor,
        "size": 1, "root": leaf_hash(leaf).hex(), "events": 1,
        "seq_lo": sequence, "seq_hi": sequence,
    }
    _match(record["cp"], cp, "checkpoint")
    _match(record["leaves"], [leaf.hex()], "checkpoint leaf")
    message = canon(cp)
    if not verify_sig(broker_pub, DOM_B, message, _hex(record["sig"], 64, "checkpoint signature")):
        raise ValueError("invalid broker checkpoint signature")
    if not verify_sig(witness_pub, DOM_W, message, _hex(record["wsig"], 64, "checkpoint signature")):
        raise ValueError("invalid witness checkpoint signature")
    return cp_hash(cp).hex()


def _check_anchor(package, witness_pub, generation, predecessor, heads, receipts):
    _fields(package, {"anchor", "signature"}, "witness state anchor package")
    _hex(package["signature"], 64, "state anchor signature")
    witness = witness_pub.hex()
    core = {
        "v": DurableWitness.STATE_VERSION, "witness": witness, "heads": heads,
        "receipt_hashes": receipts, "generation": generation,
        "previous_state_digest": predecessor,
    }
    digest = H(DOM_WS + b"\0" + canon(core)).hex()
    expected = {
        "v": 1, "type": "WITNESS_STATE_ANCHOR_V1", "witness": witness,
        "generation": generation, "previous_state_digest": predecessor,
        "state_digest": digest, "heads_digest": H(canon(heads)).hex(),
        "receipt_history_digest": H(canon(receipts)).hex(),
        "last_receipt_digest": receipts[-1] if receipts else None,
    }
    _fields(package["anchor"], expected.keys(), "witness state anchor")
    _match(package["anchor"], expected, "witness state transition")
    verify_witness_state_anchor(package, witness_pub)
    return digest


def _check_journal(journal_hex, expected_digest, records):
    # The profile commits exactly two events and two checkpoint frames.
    journal = bytearray()
    for epoch, (key, checkpoint) in enumerate(records):
        journal.extend(Broker._frame({"t": "e", "seq": epoch + 1, "m": OPS["r"], "k": key.hex()}))
        journal.extend(Broker._frame({"t": "s", "epoch": epoch, **checkpoint}))
    if _hex(journal_hex, len(journal), "journal bytes") != journal:
        raise ValueError("journal does not match witnessed checkpoints")
    if _hex(expected_digest, 32, "journal digest") != H(journal):
        raise ValueError("journal digest mismatch")


def verify_execution(evidence, *, contract, broker_pub, witness_pub,
                     expected_witness_state_digest, now):
    """Check the broker transcript against verifier-held references.

    Report the signed probe observations alongside the broker-only result.
    Process attestation and confinement assurance remain blocked. Replay
    prevention requires the caller to retire consumed challenges and retain
    the latest accepted witness digest outside witness-controlled storage.
    """
    try:
        validate_contract(contract)
        for reference in (broker_pub, witness_pub, expected_witness_state_digest):
            if not isinstance(reference, bytes) or len(reference) != 32:
                raise ValueError("missing or invalid expected key or witness state digest")
        if broker_pub == witness_pub:
            raise ValueError("the broker and witness require distinct keys")
        if type(now) is not int or now < 0:
            raise ValueError("missing or invalid verifier time")
    except (ValueError, TypeError, RecursionError) as exc:
        return {"outcome": "BLOCKED", "reason": str(exc)}
    if now >= contract["expires_at"]:
        return {"outcome": "REJECTED", "reason": "challenge expired"}
    if evidence is None:
        return {"outcome": "BLOCKED", "reason": "missing execution evidence"}

    try:
        _fields(evidence, {
            "payload", "broker_signature", "witness_signature", "witness_state_chain", "journal_hex",
        }, "execution evidence")
        payload = evidence["payload"]
        _fields(payload, {
            "type", "assurance", "broker", "witness", "contract", "observations", "interval",
            "start", "end", "witness_state_start", "journal_sha256",
        }, "execution payload")
        broker, witness = broker_pub.hex(), witness_pub.hex()
        if (payload["type"], payload["assurance"], payload["broker"], payload["witness"]) != (
                STAGE3_TYPE, ASSURANCE, broker, witness):
            raise ValueError("execution evidence type, assurance or signer identity mismatch")
        _match(payload["contract"], contract, "run contract")
        observations = {
            "direct_denied": True, "canary_closed": True,
            "response_sha256": contract["fixture_sha256"], "child_exit": 0, "channel_eof": True,
        }
        _fields(payload["observations"], observations.keys(), "observations")
        _match(payload["observations"], observations, "observations")
        marker, key = run_marker(contract), contract["key"].encode("utf-8")
        start = _check_checkpoint(payload["start"], marker, 0, _ZERO, broker_pub, witness_pub)
        end = _check_checkpoint(payload["end"], key, 1, start, broker_pub, witness_pub)
        _match(payload["interval"], {
            "end_epoch": 1, "end_checkpoint_hash": end,
        }, "checkpoint interval")
        _check_journal(evidence["journal_hex"], payload["journal_sha256"],
                       ((marker, payload["start"]), (key, payload["end"])))

        transition = evidence["witness_state_chain"]
        if not isinstance(transition, list) or len(transition) > 3:
            raise ValueError("invalid witness state chain")
        if len(transition) != 3:
            raise _IncompleteEvidence("witness state chain is incomplete")
        genesis = _check_anchor(payload["witness_state_start"], witness_pub, 0, _ZERO, {}, [])
        if genesis != expected_witness_state_digest.hex():
            raise ValueError("witness state differs from verifier-held digest")
        message = canon(payload)
        if not verify_sig(broker_pub, DOM_RB, message, _hex(evidence["broker_signature"], 64, "broker signature")):
            raise ValueError("invalid broker evidence signature")
        if not verify_sig(witness_pub, DOM_RW, message, _hex(evidence["witness_signature"], 64, "witness signature")):
            raise ValueError("invalid witness evidence signature")
        started = _check_anchor(transition[0], witness_pub, 1, genesis, {
            broker: {"epoch": 0, "hash": start, "seq_hi": 1},
        }, [])
        end_heads = {broker: {"epoch": 1, "hash": end, "seq_hi": 2}}
        ended = _check_anchor(transition[1], witness_pub, 2, started, end_heads, [])
        retained = _check_anchor(transition[2], witness_pub, 3, ended, end_heads, [H(message).hex()])
    except _IncompleteEvidence as exc:
        return {"outcome": "BLOCKED", "reason": str(exc)}
    except (ValueError, TypeError, RecursionError) as exc:
        return {"outcome": "REJECTED", "reason": str(exc)}

    return {
        "outcome": "VERIFIED", "assurance": ASSURANCE, "confinement": "BLOCKED",
        "witness_state_digest": retained, "witness_state_generation": 3,
        "observations": observations,
    }
