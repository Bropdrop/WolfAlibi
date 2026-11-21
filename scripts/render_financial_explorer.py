"""Render the self-contained financial challenge page from verified package inputs."""

import argparse
import base64
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "public_lab"
FINANCIAL = LAB / "financial"
UI = FINANCIAL / "ui"


def reference_path(case):
    if case["input_kind"] == "manifest":
        return "public_lab/manifest.json"
    names = {"evidence": "genuine.json", "pins": "pins.json", "challenge": "challenge.txt"}
    return f"public_lab/vectors/{case['profile']}/{names[case['input_kind']]}"


def embed_file(relative):
    path = ROOT / relative
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(LAB) or resolved != path or path.stat().st_size > 262_144:
        raise ValueError("outside the fixed public fixture inventory")
    raw = path.read_bytes()
    return {"base64": base64.b64encode(raw).decode("ascii"), "sha256": hashlib.sha256(raw).hexdigest()}


def render(report: dict) -> bytes:
    raw = (FINANCIAL / "cases.json").read_bytes()
    cases = json.loads(raw)["cases"]
    if (report["matrix_sha256"] != hashlib.sha256(raw).hexdigest()
            or report["selected_case"] != "all" or report["outcome"] != "PASS"
            or [row["id"] for row in report["cases"]] != [row["id"] for row in cases]):
        raise ValueError("page requires a matching complete recorded matrix")
    artifacts = {}
    for case, result in zip(cases, report["cases"], strict=True):
        case["reference"] = reference_path(case)
        for path in (case["fixture"], case["reference"]):
            if path not in artifacts:
                artifacts[path] = embed_file(path)
        if (artifacts[case["fixture"]]["sha256"] != case["sha256"]
                or result["sha256"] != case["sha256"] or result["expected"] != case["expected"]):
            raise ValueError(f"fixture or report differs from matrix for {case['id']}")
    payload = json.dumps({"cases": cases, "artifacts": artifacts, "report": report},
                         ensure_ascii=True, sort_keys=True, separators=(",", ":")).replace("<", "\\u003c")
    stylesheet = (UI / "style.css").read_text(encoding="utf-8")
    script = (UI / "explorer.js").read_text(encoding="utf-8")
    page = (UI / "template.html").read_text(encoding="utf-8")
    for marker, body in {"STYLE": f"<style>\n{stylesheet}\n</style>",
                         "DATA": f'<script id="payload" type="application/json">{payload}</script>',
                         "SCRIPT": f"<script>\n{script}\n</script>"}.items():
        slot = f"<!-- {marker} -->"
        if page.count(slot) != 1:
            raise ValueError(f"expected one {marker} slot")
        page = page.replace(slot, body)
    return page.encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = render(json.loads((FINANCIAL / "results.json").read_bytes()))
    target = FINANCIAL / "index.html"
    if args.check:
        return 0 if target.read_bytes() == result else 2
    target.write_bytes(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
