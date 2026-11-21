"""One synthetic, read-only execution trial, with broker-scoped evidence."""

from __future__ import annotations

import argparse
import json
import math
import os
import select
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from alibi import (Broker, BrokerClosed, DOM_RB, DurableWitness, H, OPS,
                   Signer, WitnessRefused, canon, cp_hash)
from .stage3_evidence import (STAGE3_TYPE, run_marker, validate_contract,
                              verify_execution)
from .stage3_worker import UnsupportedWorker, launch, worker_profile


FIXTURE_KEY = "protected.txt"
FIXTURE_BYTES = b"WolfAlibi Stage 3 synthetic protected bytes\n"
MAX_PACKET = 4096


class TrialBlocked(RuntimeError):
    """A trial ended without a complete, witnessed interval."""


def trial_contract(run_id: str, challenge: bytes, expires_at: int) -> dict:
    """Build the reference contract before running the fixed synthetic worker."""
    contract = {
        "run_id": run_id, "challenge": challenge.hex(), "expires_at": expires_at,
        "profile": worker_profile(), "key": FIXTURE_KEY,
        "fixture_sha256": H(FIXTURE_BYTES).hex(),
    }
    validate_contract(contract)
    return contract


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TrialBlocked("worker deadline expired")
    return remaining


def _receive(channel, deadline):
    channel.settimeout(_remaining(deadline))
    data, _, flags, _ = channel.recvmsg(MAX_PACKET)
    # With no ancillary buffer the kernel discards received descriptors. Treat
    # control-data truncation as a protocol failure, even on an empty packet.
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise TrialBlocked("truncated packet or unexpected control data")
    return data


def _send(channel, packet, deadline):
    channel.settimeout(_remaining(deadline))
    encoded = canon(packet)
    if channel.send(encoded) != len(encoded):
        raise TrialBlocked("incomplete broker response")


def _serve(channel, broker, contract, deadline, *, before_release=None):
    expected_read = {
        "type": "read", "run_id": contract["run_id"],
        "challenge": contract["challenge"], "seq": 1, "key": contract["key"],
        "direct_denied": True, "canary_closed": True,
    }
    request = _receive(channel, deadline)
    if request != canon(expected_read):
        if not request:
            raise TrialBlocked("worker closed before sending probe and request")
        raise TrialBlocked("worker probe or request did not match the run contract")
    if before_release is not None:
        before_release()
    # The fixed fixture is created under a newly allocated, private directory.
    # Broker.read logs the authorized key to its WAL before returning bytes.
    data = broker.read(contract["key"])
    digest = H(data).hex()
    if digest != contract["fixture_sha256"]:
        raise TrialBlocked("fixture did not match the expected digest")
    _send(channel, {"type": "data", "data": data.hex()}, deadline)
    if _receive(channel, deadline) != canon({"type": "done", "data_sha256": digest}):
        raise TrialBlocked("missing or invalid acknowledgement, including duplicate requests")
    return digest


def _checkpoint(broker, cp):
    record = broker.sealed[cp["epoch"]]
    return {
        "cp": cp, "sig": record["sig"].hex(), "wsig": record["wsig"].hex(),
        "leaves": [leaf.hex() for leaf in record["leaves"]],
    }


def _worker_session(broker, root, contract, *, timeout, mode, before_release=None):
    import fcntl

    deadline = time.monotonic() + timeout
    broker_socket, worker_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with broker_socket, worker_socket:
        endpoint_inode = os.fstat(worker_socket.fileno()).st_ino
        with (root / contract["key"]).open("rb") as fixture:
            canary_fd = fcntl.fcntl(fixture.fileno(), fcntl.F_DUPFD, 64)
        try:
            os.set_inheritable(canary_fd, True)
            proc = launch(worker_socket, root, contract["key"], contract["run_id"],
                          bytes.fromhex(contract["challenge"]), canary_fd, mode=mode,
                          expected_profile=contract["profile"])
        finally:
            os.close(canary_fd)
        # Only the launched side may keep the worker endpoint open.
        worker_socket.close()
        try:
            def measure():
                before_release(proc, endpoint_inode, root, canary_fd, deadline)

            digest = _serve(broker_socket, broker, contract, deadline,
                            before_release=measure if before_release else None)
            if proc.wait(timeout=_remaining(deadline)) != 0:
                raise TrialBlocked("worker did not exit successfully")
            # A zero-length packet alone cannot establish peer closure.
            poller = select.poll()
            poller.register(broker_socket, select.POLLHUP)
            if not any(events & select.POLLHUP for _, events in
                       poller.poll(math.ceil(1000 * _remaining(deadline)))):
                raise TrialBlocked("worker socket remained open after exit")
            if _receive(broker_socket, deadline):
                raise TrialBlocked("unexpected data after the worker acknowledgement")
        finally:
            if proc.poll() is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                proc.wait(timeout=2)
    return {
        "direct_denied": True, "canary_closed": True, "response_sha256": digest,
        "child_exit": 0, "channel_eof": True,
    }


def _signed_evidence(broker, witness, journal, contract, prior, observations, start, after_start):
    end = _checkpoint(broker, broker.seal())
    after_end = witness.state_anchor()
    journal_bytes = journal.read_bytes()
    payload = {
        "type": STAGE3_TYPE, "assurance": "BROKER_ONLY",
        "broker": broker.signer.pub.hex(), "witness": witness.signer.pub.hex(),
        "contract": contract, "observations": observations,
        "interval": {"end_epoch": end["cp"]["epoch"],
                     "end_checkpoint_hash": cp_hash(end["cp"]).hex()},
        "start": start, "end": end, "witness_state_start": prior,
        "journal_sha256": H(journal_bytes).hex(),
    }
    signature = broker.signer.sign(DOM_RB, canon(payload))
    witness_signature = witness.cosign_receipt(payload, signature)
    return {
        "payload": payload, "broker_signature": signature.hex(),
        "witness_signature": witness_signature.hex(), "journal_hex": journal_bytes.hex(),
        "witness_state_chain": [after_start, after_end, witness.state_anchor()],
    }


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run_trial(state_dir, *, contract, signer, witness, expected_witness_state_digest,
              timeout=10.0, _worker_mode="normal", _fixture=(FIXTURE_KEY, FIXTURE_BYTES),
              _before_release=None):
    """Run one fixed synthetic worker with a fresh broker and witness history.

    The trusted operator owns state_dir and uses the witness exclusively for
    this run. Failed sessions retain their WAL under run_dir for diagnosis.
    """
    run_dir = None
    try:
        validate_contract(contract)
        contract = json.loads(canon(contract))
        if (type(timeout) not in (int, float) or not 0 < timeout <= 120 or
                not math.isfinite(timeout)):
            raise TrialBlocked("invalid worker timeout")
        fixture_key, fixture_bytes = _fixture
        if (contract["key"] != fixture_key or contract["fixture_sha256"] != H(fixture_bytes).hex()
                or canon(contract["profile"]) != canon(worker_profile())):
            raise TrialBlocked("fixture or worker profile differs from the trial contract")
        if not isinstance(witness, DurableWitness):
            raise TrialBlocked("a durable witness is required")
        if signer.pub == witness.signer.pub:
            raise TrialBlocked("the broker and witness require distinct keys")
        prior = witness.state_anchor()
        if (type(expected_witness_state_digest) is not bytes or
                len(expected_witness_state_digest) != 32 or
                witness.state_digest != expected_witness_state_digest):
            raise TrialBlocked("witness state differs from the externally retained digest")
        if prior["anchor"]["generation"] != 0 or witness.heads or witness.receipt_hashes:
            raise TrialBlocked("this one-run profile requires a fresh witness history")
        if contract["expires_at"] <= time.time():
            raise TrialBlocked("run challenge expired")

        run_dir = Path(tempfile.mkdtemp(prefix="stage3-", dir=Path(state_dir).resolve()))
        _sync_directory(run_dir.parent)
        root = run_dir / "resources"
        root.mkdir(mode=0o700)
        fixture_path = root / fixture_key
        fixture_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fixture_path.write_bytes(fixture_bytes)
        fixture_path.chmod(0o400)
        journal = run_dir / "broker.wal"
        with Broker(root, signer, witness, journal=journal) as broker:
            _sync_directory(run_dir)
            # A reserved non-path leaf commits the contract into the durable
            # genesis checkpoint before a worker can receive any data.
            with broker._operation():
                broker._record(run_marker(contract), OPS["r"])
            start = _checkpoint(broker, broker.seal())
            after_start = witness.state_anchor()
            observations = _worker_session(broker, root, contract, timeout=timeout,
                                           mode=_worker_mode, before_release=_before_release)
            if contract["expires_at"] <= time.time():
                raise TrialBlocked("run challenge expired before closure")
            evidence = _signed_evidence(broker, witness, journal, contract, prior,
                                        observations, start, after_start)
        verification = verify_execution(
            evidence, contract=contract, now=int(time.time()),
            broker_pub=signer.pub, witness_pub=witness.signer.pub,
            expected_witness_state_digest=expected_witness_state_digest,
        )
        if verification["outcome"] != "VERIFIED":
            raise TrialBlocked(verification["reason"])
        return {"outcome": "COMPLETED", "run_dir": str(run_dir), "evidence": evidence,
                "verification": verification}
    except UnsupportedWorker as exc:
        return {"outcome": "UNSUPPORTED", "reason": str(exc),
                "run_dir": str(run_dir) if run_dir else None}
    except (TrialBlocked, BrokerClosed, WitnessRefused, ValueError, OSError,
            subprocess.TimeoutExpired) as exc:
        return {"outcome": "BLOCKED", "reason": str(exc),
                "run_dir": str(run_dir) if run_dir else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True,
                        help="existing private directory for a single synthetic run")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--challenge", required=True, help="externally generated 32-byte hex nonce")
    args = parser.parse_args()
    try:
        contract = trial_contract(args.run_id, bytes.fromhex(args.challenge), int(time.time()) + 120)
        signer = Signer()
        with DurableWitness(args.state_dir / "witness.json", Signer()) as witness:
            retained_digest = witness.state_digest
            result = run_trial(args.state_dir, contract=contract, signer=signer, witness=witness,
                               expected_witness_state_digest=retained_digest)
    except UnsupportedWorker as exc:
        result = {"outcome": "UNSUPPORTED", "reason": str(exc)}
    except (ValueError, OSError) as exc:
        result = {"outcome": "BLOCKED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("verification", {}).get("outcome") == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
