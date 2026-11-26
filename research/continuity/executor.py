"""One authorized native request in a destination-only process namespace."""

import json, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from research.continuity.destination import DestinationGate
from research.schism.experiment import box


def isolated_commit(state, paths, pins, key, roots, package, request):
    import subprocess
    from research.wt_swarm.run import gate_limits

    config = state.parent / "continuity-public.json"
    config.write_text(
        json.dumps(
            dict(
                paths={k: str(v) for k, v in paths.items()},
                pins=pins,
                roots=roots,
                package=package,
            )
        )
    )
    secret = state.parent / "executor.secret"
    secret.write_bytes(key.private_bytes_raw())
    mounts = [
        ("--ro-bind", config, "/config.json"),
        ("--ro-bind", secret, "/executor.key"),
        ("--bind", state, state),
        ("--ro-bind", paths["control"].parent, paths["control"].parent),
        ("--bind", paths["witness"].parent, paths["witness"].parent),
    ]
    args = box("role", mounts)
    i = args.index("--chdir")
    args[i:i] = [
        "--ro-bind",
        str(Path(__file__).resolve().parent),
        "/src/research/continuity",
    ]
    args[-1] = "research.continuity.executor"
    return json.loads(
        subprocess.check_output(
            args + [str(state)],
            input=json.dumps(request).encode(),
            preexec_fn=gate_limits,
            timeout=10,
        )
    )


if __name__ == "__main__":
    c = json.loads(Path("/config.json").read_bytes())
    key = Ed25519PrivateKey.from_private_bytes(Path("/executor.key").read_bytes())
    gate = DestinationGate(
        Path(sys.argv[1]),
        {k: Path(v) for k, v in c["paths"].items()},
        c["pins"],
        key,
        c["roots"],
        c["package"],
    )
    print(json.dumps(gate.execute(json.loads(input()))))
