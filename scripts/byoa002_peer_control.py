"""Measure a live gateway or exercise the owner-side wrong-peer control."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from alibi import canon
from wolfalibi.byoa002_transport import measure_gateway, request
from wolfalibi.byoa_qualification_cli import _read


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    measure = sub.add_parser("measure", help="independently sample a live gateway before enrollment")
    measure.add_argument("--gateway-pid", type=int, required=True)
    measure.add_argument("--gateway-uid", type=int, required=True)
    wrong = sub.add_parser("wrong-peer", help="send a signed synthetic packet from the owner's process")
    wrong.add_argument("--packet", type=Path, required=True)
    wrong.add_argument("--target-pid", type=int, required=True)
    wrong.add_argument("--target-uid", type=int, required=True)
    for command in (measure, wrong):
        command.add_argument("--socket", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "measure":
            peer = measure_gateway(args.gateway_pid, args.socket)
            if peer["uid"] != args.gateway_uid:
                raise ValueError("measured gateway differs from expected UID")
            result = {"outcome": "MEASURED", "peer": peer, "observer_uid": os.geteuid()}
        else:
            if os.geteuid() != args.target_uid:
                raise ValueError("run the wrong-peer control as the enrolled target owner")
            packet = _read(args.packet, 65_536)
            result = {"attempt": request(args.socket, "dispatch", packet,
                                         expected_target_pid=args.target_pid, expected_target_uid=args.target_uid),
                      "sender_uid": os.geteuid(), "sender_pid": os.getpid(),
                      "packet_sha256": hashlib.sha256(canon(packet)).hexdigest()}
    except PermissionError:
        result = {"outcome": "UNSUPPORTED", "reason": "mandatory procfs or endpoint measurement unavailable"}
    except (OSError, ValueError, RuntimeError):
        result = {"outcome": "BLOCKED", "reason": "required local process, path or input not validated"}
    print(json.dumps(result, sort_keys=True))
    if args.action == "measure":
        return 0 if result.get("outcome") == "MEASURED" else 2
    return 0 if result.get("attempt", {}).get("outcome") == "DENIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
