#!/usr/bin/env bash
# Run the specified local qualification subset. Keep every result on a failing run.
set -u
python=${PYTHON:-python3}
out=$1
mkdir "$out" || exit 1
exec > >(tee "$out/commands.txt") 2>&1
set -x
git rev-parse HEAD 'HEAD^{tree}'
git status --short --untracked-files=no
uname -srm
id
"$python" -V
"$python" -m pip freeze > "$out/environment.txt"
status=0
timeout 300 "$python" -m unittest -v test_byoa002_custody test_byoa002_closure test_byoa002_package test_byoa002_exchange test_byoa002_qualification test_byoa002_transport test_financial_package test_financial_receipt_check test_history_records test_history_verify test_sector_profiles test_clearance_report test_education_verifier > "$out/tests.txt" 2>&1 || status=1
if grep -Eq 'skipped=|expected failures=|unexpected successes=' "$out/tests.txt"; then status=1; fi
timeout 180 "$python" -c 'import json; from scripts.mutate_byoa002 import exercise; cases=[exercise(i) for i in ("002-M2","002-M3","002-M4")]; print(json.dumps(cases,indent=2)); raise SystemExit(int(not all(c["detected"] for c in cases)))' > "$out/inherited-selected.json" 2>&1 || status=1
for suite in custody closure; do
    timeout 180 "$python" -I scripts/mutate_byoa002.py "--$suite" > "$out/$suite.json" 2>&1 || status=1
done
"$python" -I scripts/verify_byoa0021.py --history docs/evidence/byoa0021/sample/history.json --expect docs/evidence/byoa0021/sample/expect.json > "$out/historical.json" 2>&1 || status=1
tail -5 "$out/tests.txt"
exit "$status"
