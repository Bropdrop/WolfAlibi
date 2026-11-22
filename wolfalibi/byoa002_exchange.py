"""Authenticated local target-to-verifier witness exchange."""

import json
import os
from pathlib import Path
import secrets
import socket
import stat

from alibi import canon, verify_sig
from .byoa002_enrollment import digest, validate_enrollment
from .solitary_cli import _unique_object

QUERY = b"quorvane/byoa002/target-witness-query/v1"
ANSWER = b"quorvane/byoa002/verifier-witness-answer/v1"
BOUND = 96 * 1024


def _signed(payload, signer, domain):
    return {"payload": payload, "signature": signer.sign(domain, canon(payload)).hex()}


def _verified(record, pub, domain):
    if type(record) is not dict or record.keys() != {"payload", "signature"} or type(record["payload"]) is not dict:
        raise ValueError("malformed witness exchange record")
    signature = record["signature"]
    if (type(signature) is not str or len(signature) != 128 or
            not verify_sig(bytes.fromhex(pub), domain, canon(record["payload"]), bytes.fromhex(signature))):
        raise ValueError("unauthenticated witness exchange")
    return record["payload"]


def _send(connection, document):
    data = canon(document)
    if len(data) > BOUND or connection.send(data) != len(data):
        raise ValueError("incomplete witness packet")


def _receive(connection):
    data = connection.recv(BOUND + 1)
    if not data or len(data) > BOUND:
        raise ValueError("missing or oversized witness packet")
    return json.loads(data, object_pairs_hook=_unique_object)


class WitnessConnection:
    """Accept only a fresh reply under the enrolled verifier's public key."""

    def __init__(self, path, enrollment, target_signer):
        self.enrollment = validate_enrollment(enrollment)
        if target_signer.pub.hex() != self.enrollment["target_pub"]:
            raise ValueError("unexpected target key")
        self.path = os.fspath(path)
        self.signer = target_signer

    def _call(self, action, expected, challenge, receipt=None):
        query = _signed({"action": action, "enrollment_sha256": digest(self.enrollment),
                         "nonce": secrets.token_hex(32), "expected": expected,
                         "challenge": challenge, "receipt": receipt}, self.signer, QUERY)
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as sock:
            sock.settimeout(5)
            sock.connect(self.path)
            _send(sock, query)
            answer = _verified(_receive(sock), self.enrollment["verifier_pub"], ANSWER)
        if answer.keys() != {"query_sha256", "result"} or answer["query_sha256"] != digest(query):
            raise ValueError("wrong witness response binding")
        result = answer["result"]
        if type(result) is not dict or result.get("accepted") is not True or result.keys() != {"accepted", "value"}:
            raise ValueError("external witness refused the request")
        return result["value"]

    def check_pending(self, expected, challenge):
        return self._call("pending", expected, challenge)

    def retain(self, expected, challenge, receipt):
        return self._call("retain", expected, challenge, receipt)

    def reconcile(self, expected, challenge, receipt):
        return self._call("reconcile", expected, challenge, receipt)


def answer_query(query, store, enrollment, signer):
    if signer.pub.hex() != enrollment["verifier_pub"]:
        raise ValueError("wrong witness service key")
    payload = _verified(query, enrollment["target_pub"], QUERY)
    if (payload.keys() != {"action", "enrollment_sha256", "nonce", "expected", "challenge", "receipt"}
            or payload["enrollment_sha256"] != digest(enrollment)
            or type(payload["nonce"]) is not str or len(payload["nonce"]) != 64
            or bytes.fromhex(payload["nonce"]).hex() != payload["nonce"]
            or payload["action"] not in {"pending", "retain", "reconcile"}):
        raise ValueError("invalid target witness query")
    expected, challenge, receipt = (payload[k] for k in ("expected", "challenge", "receipt"))
    try:
        if payload["action"] == "pending":
            if receipt is not None:
                raise ValueError("unexpected receipt")
            value = store.check_pending(expected, challenge)
        elif payload["action"] == "retain":
            value = store.retain(expected, challenge, receipt)
        else:
            value = store.reconcile(expected, challenge, receipt)
        result = {"accepted": True, "value": value}
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        result = {"accepted": False}
    return _signed({"query_sha256": digest(query), "result": result}, signer, ANSWER)


def serve_witness(path, store, enrollment, signer, ready, stop):
    path = Path(path).absolute()
    parent = path.parent.lstat()
    if (path != path.resolve(strict=False) or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid() or parent.st_mode & 0o022):
        raise ValueError("witness socket requires a verifier-controlled directory")
    enrollment = validate_enrollment(enrollment)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        listener.bind(str(path))
        try:
            os.chmod(path, 0o666)
            listener.listen(8)
            listener.settimeout(.25)
            ready()
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(2)
                    try:
                        _send(connection, answer_query(_receive(connection), store, enrollment, signer))
                    except (OSError, TypeError, ValueError):
                        continue
        finally:
            path.unlink(missing_ok=True)
