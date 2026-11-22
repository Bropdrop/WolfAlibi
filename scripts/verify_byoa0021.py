"""Verify a historical journal against a separately retained public expectations file."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wolfalibi.byoa002_custody import verify_history


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", type=Path, required=True)
    parser.add_argument("--expect", type=Path, required=True)
    args = parser.parse_args()
    try:
        pins = json.loads(args.expect.read_bytes())
        result = verify_history(json.loads(args.history.read_bytes()), enrollment=pins["enrollment"],
                                public_key=bytes.fromhex(pins["public_key"]), expected_head=pins["head"])
    except (ValueError, TypeError, OSError, KeyError) as exc:
        result = {"outcome": "BLOCKED", "reason": str(exc)}
    print(json.dumps(result))
    return int(result["outcome"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
