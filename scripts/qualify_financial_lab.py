"""Qualify the financial review profile against externally supplied Git object IDs."""

import argparse
import hashlib
from importlib import metadata
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile


ROOT = Path(__file__).resolve().parents[1]
BASE = {"commit": "1d6dddd654489ebdc3ddc028dc23b59d8d407281",
        "tree": "20f161ffa00045d795fc7ee76740002d89c9506f"}
BASE_ARCHIVE_SHA = "0d14aeca661a8c01318ee55258e9198fb27cc1d8772e146b6dd296f7673342c7"
ARCHIVE = "public_lab/quorvane-public-lab-002.zip"
LABELS = {"assurance": "SIMULATED_POLICY_ONLY", "production": "BLOCKED", "confinement": "BLOCKED",
          "cross_uid_custody": "UNSUPPORTED", "certification": "NOT_ISSUED"}
INHERITED = 438
EFFECT_IDS = ("B-T01", "B-T02", "B-T03", "B-T04", "C-T01", "C-T02", "C-T03", "F-T01")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def process(*args, cwd=ROOT):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=900)
    return {"command": list(args), "exit_code": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def git(*args):
    record = process("git", *args)
    require(record["exit_code"] == 0, f"git {args[0]} failed: {record['stderr']}")
    return record["stdout"].splitlines()


def head():
    commit, tree = git("rev-parse", "HEAD^{commit}", "HEAD^{tree}")
    return {"commit": commit, "tree": tree}


def json_command(script, *args, cwd=ROOT):
    record = process(sys.executable, "-I", script, *args, cwd=cwd)
    try:
        result = json.loads(record.pop("stdout"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"{script} emitted no valid JSON report: {record['stderr']}") from exc
    require(isinstance(result, dict), f"{script} emitted a non-object")
    return {**record, "report": result}


def passed(record):
    return record["exit_code"] == 0 and record["report"].get("outcome") == "PASS"


def check_matrix(report, matrix):
    """Check the complete schedule, including controls that cannot establish a guarantee."""
    require(report["schema"] == "QUORVANE_FINANCIAL_REVIEW_V1"
            and report["selected_case"] == "all" and report["outcome"] == "PASS",
            "matrix invocation must complete the entire profile")
    require(all(report.get(k) == v for k, v in LABELS.items()), "matrix changed an assurance label")
    require(report["baseline"] == BASE, "matrix identifies a different baseline")
    expected = {item["id"]: item for item in matrix["cases"]}
    require(len(expected) == len(matrix["cases"]) and {"P01", "P02"} <= expected.keys()
            and set("ABCDEF") <= {case_id[0] for case_id in expected},
            "matrix omits a challenge category or genuine positive control")
    rows = {row["id"]: row for row in report["cases"]}
    require(len(rows) == len(report["cases"]) and rows.keys() == expected.keys(),
            "matrix returned partial, duplicate or unknown results")
    counts = {"MATCH": 0, "UNASSESSED": 0}
    for case_id, spec in expected.items():
        row = rows[case_id]
        observed = row["observed"]
        wanted = spec["expected"]
        require(row["expected"] == wanted and row["fixture"] == spec["fixture"]
                and row["sha256"] == spec["sha256"], f"{case_id} changed its declared inputs")
        require(observed["phase"] == row["expected_phase"] == spec["expected_phase"],
                f"{case_id} verdict came from an unexpected verification phase")
        require(all(observed.get(k) == v for k, v in wanted.items()), f"{case_id} differs from its expected observation")
        score = "UNASSESSED" if wanted["outcome"] in {"UNSUPPORTED", "NOT_ASSESSED"} else "MATCH"
        require(row["result"] == score, f"{case_id} has an invalid score")
        counts[score] += 1
    for case_id, claim in (("P01", "HISTORICAL_SYNTHETIC_PAYMENT_INTENT"),
                           ("P02", "HISTORICAL_INTENT_DISCLOSURE")):
        details = rows[case_id]["observed"]["details"]
        canonical = details["canonical"]
        require(canonical["outcome"] == "VERIFIED" and canonical["verified"] == claim
                and canonical["effect"] == "PENDING_EXTERNAL_SETTLEMENT"
                and details["settlement"] == "UNESTABLISHED"
                and all(canonical.get(k) == v for k, v in LABELS.items()),
                f"{case_id} did not verify the genuine scoped historical claim")
    summary = report["summary"]
    require(summary["scheduled"] == summary["executed"] == len(expected) and summary["matched"] == counts["MATCH"]
            and summary["unassessed"] == counts["UNASSESSED"] and summary["mismatched"] == 0
            and summary["errors"] == 0, "matrix totals disagree with individual observations")


def extract_review(archive, dest):
    with ZipFile(archive) as bundle:
        names = set()
        for item in bundle.infolist():
            path = PurePosixPath(item.filename)
            require(not path.is_absolute() and path.as_posix() == item.filename
                    and ".." not in path.parts and "\\" not in item.filename
                    and item.filename not in names and stat.S_ISREG(item.external_attr >> 16),
                    "archive member is not a unique regular relative file")
            names.add(item.filename)
        bundle.extractall(dest)


def portable_review(matrix, tracked_report):
    with TemporaryDirectory(prefix="qf-review-") as tmp:
        dest = Path(tmp)
        extract_review(ROOT / ARCHIVE, dest)
        current = json_command("scripts/finance_challenge.py", "run", cwd=dest)
        require(passed(current), "standalone matrix did not pass")
        check_matrix(current["report"], matrix)
        require(current["report"]["provenance"]["mode"] == "PORTABLE"
                and current["report"] == tracked_report, "extracted run differs from the packaged observations")
        old = json_command("scripts/public_lab.py", "verify", cwd=dest)
        expected = json.loads((ROOT / "public_lab/reports/verification.json").read_bytes())
        require(passed(old) and old["report"] == expected, "extracted Public Lab 001 results changed")
        return {"extraction": "temporary directory outside Git", "matrix": current, "lab001": old}


def check_effects(record):
    report = record["report"]
    require(passed(record) and report["schema"] == "QUORVANE_FINANCIAL_EFFECT_CONTROLS_V1"
            and all(report.get(k) == v for k, v in LABELS.items()),
            "supplemental local effect controls did not qualify; see their separate profile result")
    controls = report["controls"]
    require(tuple(row["id"] for row in controls) == EFFECT_IDS, "partial or unrecognized effect controls")
    fixture = "public_lab/financial/controls/target.json"
    expected_hash = "fd5ab902e66258cde25a058c70868ffd850a2d895e16e80d25c534d2830cb70d"
    require(digest(ROOT / fixture) == expected_hash, "fixed target scenario specification changed")
    spec = json.loads((ROOT / fixture).read_bytes())
    schedule = {entry["id"]: entry["expected"] for entry in spec["controls"]}
    for row in controls:
        require(row["fixture"] == fixture and row["fixture_sha256"] == expected_hash,
                f"{row['id']} target scenario digest differs")
        expected = json.dumps(schedule[row["id"]], sort_keys=True)
        require(row["outcome"] == "PASS" and json.dumps(row["expected"], sort_keys=True) == expected
                and json.dumps(row["observed"], sort_keys=True) == expected,
                f"{row['id']} target observations differ from expectations")


def qualify(expected, report):
    # Delay repository imports so a missing verification dependency yields JSON.
    from qualify_history_gate import _loader_counts
    from qualify_public_lab import _build, _public_lab
    from qualify_stage35 import unit_suite
    from qualify_voidcell002 import _environment

    require(all(re.fullmatch(r"[0-9a-f]{40}", value) for value in expected.values()),
            "expected commit and tree must be full lowercase Git object IDs")
    require(git("status", "--porcelain=v1", "--untracked-files=all") == [], "qualification needs a clean checkout")
    report["working_tree_clean_start"] = True
    report["environment"] = _environment()
    dependencies = {}
    for package in ("mcp", "langchain", "langchain-core", "openai-agents"):
        try:
            dependencies[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            dependencies[package] = None
    report["environment"]["inherited_test_dependencies"] = dependencies
    require(git("rev-parse", BASE["commit"] + "^{tree}") == [BASE["tree"]], "PR #35 tree mismatch")
    report["tested_revision"] = head()
    require(report["tested_revision"] == expected, "external expected commit/tree differs from checkout")
    parents = git("show", "-s", "--format=%P", "HEAD")
    require(parents == [BASE["commit"]], "candidate requires a single direct PR #35 parent")
    report["parents"] = parents

    preserved = git("diff", "--no-renames", "--name-only", "--diff-filter=DMRTUXB", BASE["commit"], "HEAD")
    require(set(preserved) <= {"README.md"}, f"inherited tracked files changed: {preserved}")
    report["baseline_files"] = {"changed": preserved, "allowed": ["README.md"],
                                "file_count": len(git("ls-tree", "-r", "--name-only", BASE["commit"]))}
    inherited_archive = ROOT / "public_lab/quorvane-public-lab-001.zip"
    require(digest(inherited_archive) == BASE_ARCHIVE_SHA, "original review ZIP hash mismatch")
    report["archives"] = {inherited_archive.name: BASE_ARCHIVE_SHA, Path(ARCHIVE).name: digest(ROOT / ARCHIVE)}
    # Record capability-dependent Linux measurements even when inherited tests later skip.
    report["local_effect_controls"] = json_command("scripts/financial_effect_controls.py")

    def modules(ref):
        return {name for name in git("ls-tree", "--name-only", ref)
                if name.startswith("test_") and name.endswith(".py")}
    inherited = sorted(modules(BASE["commit"]))
    focused = sorted(modules("HEAD") - set(inherited))
    loader = _loader_counts(focused)
    require(loader and all(v["tests"] > 0 and not v["loader_errors"] for v in loader),
            "new test modules must load and enumerate successfully")
    report["new_test_inventory"] = loader
    new_count = sum(v["tests"] for v in loader)
    for label, count, args in (("inherited_suite", INHERITED, ["-v", *inherited]),
                               ("new_suite", new_count, ["-v", *focused]),
                               ("full_suite", INHERITED + new_count, ["discover", "-v"])):
        record = unit_suite(*args)
        report[label] = record
        require(record["outcome"] == "PASS" and record["tests"] == count and record["skipped"] == 0,
                f"{label} failed, skipped a test, or returned an unexpected test count")

    mutations = process(sys.executable, "-u", "mutation_test.py")
    detected = re.findall(r"^CAUGHT\s+M([1-8])\b[^\n]+ -> (test_[^\n]+)$", mutations["stdout"], re.MULTILINE)
    report["mutations"] = {**mutations, "detected": dict(detected)}
    require(mutations["exit_code"] == 0 and sorted(n for n, _ in detected) == list("12345678")
            and "8/8 mutants caught" in mutations["stdout"], "not all eight mutations triggered named test failures")
    report["lab001_verification"] = _public_lab()
    report["lab001_build"] = _build()
    require(report["lab001_verification"]["outcome"] == report["lab001_build"]["outcome"] == "PASS",
            "the inherited Lab 001 package or verifier failed")

    matrix_path = ROOT / "public_lab/financial/cases.json"
    matrix = json.loads(matrix_path.read_bytes())
    current = json_command("scripts/finance_challenge.py", "run", "--expect-commit", expected["commit"],
                           "--expect-tree", expected["tree"])
    report["checkout_matrix"] = current
    require(passed(current), "exact-Git financial challenge runner failed")
    require(current["report"]["matrix_sha256"] == digest(matrix_path), "matrix report digest differs")
    check_matrix(current["report"], matrix)
    provenance = current["report"]["provenance"]
    require(provenance["mode"] == "EXACT_GIT" and all(provenance[k] == v for k, v in expected.items()),
            "matrix failed to bind its run to the requested revision")

    build = json_command("scripts/build_financial_lab.py", "--check")
    report["deterministic_build"] = build
    outputs = {ARCHIVE, "public_lab/financial/index.html", "public_lab/financial/results.json",
               "public_lab/financial/inventory.json"}
    require(passed(build) and build["report"]["schema"] == "QUORVANE_PUBLIC_LAB_002_BUILD_V1"
            and build["report"]["artifacts"] == {name: digest(ROOT / name) for name in outputs},
            "stored financial review artifacts differ from a deterministic rebuild")
    tracked = json.loads((ROOT / "public_lab/financial/results.json").read_bytes())
    report["extracted_archive"] = portable_review(matrix, tracked)
    require(tracked["cases"] == current["report"]["cases"], "checkout and archive challenge observations differ")

    report["working_tree_clean_end"] = git("status", "--porcelain=v1", "--untracked-files=all") == []
    report["revision_unchanged"] = expected == head()
    require(report["working_tree_clean_end"] and report["revision_unchanged"], "checkout changed during qualification")
    check_effects(report["local_effect_controls"])
    report["outcome"] = "PASS"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect-commit", required=True)
    parser.add_argument("--expect-tree", required=True)
    args = parser.parse_args()
    expected = {"commit": args.expect_commit, "tree": args.expect_tree}
    report = {"schema": "quorvane.public-lab-002.qualification.v1", "outcome": "BLOCKED",
              **LABELS, "baseline": BASE, "expected_revision": expected, "inherited_expected": INHERITED}
    try:
        qualify(expected, report)
    except (ImportError, KeyError, OSError, ValueError, TypeError, subprocess.SubprocessError, BadZipFile) as exc:
        report.update(error_type=type(exc).__name__, reason=str(exc))
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["outcome"] == "PASS" else 2


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT / "scripts"))
    raise SystemExit(main())
