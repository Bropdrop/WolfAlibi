#!/usr/bin/env bash
# Run from a clean candidate checkout, with an output path outside the repository.
set -eu
py=${PYTHON:?Set PYTHON to the pinned virtual environment interpreter}
out=$(realpath -m "$1")
mkdir "$out"
commit=$(git rev-parse HEAD)
tree=$(git rev-parse 'HEAD^{tree}')
test -z "$(git status --porcelain)"
printf '%s\n' "$commit" "$tree" > "$out/revision.txt"
run() {
    local name=$1
    shift
    printf '%q ' "$@" >> "$out/commands.txt"
    printf '\n' >> "$out/commands.txt"
    local code=0
    "$@" > "$out/$name.stdout" 2> "$out/$name.stderr" || code=$?
    echo "$code" > "$out/$name.exit"
    if (( code )); then failed=1; fi
}
failed=0
run kernel uname -a
run compiler gcc --version
run permissions id
run capabilities grep -E '^(Cap|NoNewPrivs|Seccomp)' /proc/self/status
run python "$py" -VV
run dependencies "$py" -m pip freeze --all
run requirements "$py" -m pip check
run preflight "$py" -c 'import json; from wolfalibi.solitary_preflight import preflight; r=preflight(); print(json.dumps(r)); raise SystemExit(r["outcome"] != "READY")'
run archives sha256sum public_lab/quorvane-public-lab-001.zip public_lab/quorvane-public-lab-002.zip
run discovery timeout 1200 "$py" scripts/byoa0023_discovery.py "$out/inventory.json"
run legacy-M3 timeout 180 "$py" mutation_test.py --known-vector
for case_id in 002-M2 002-M3 002-M4 002.1-M1 002.1-M2 002.2-M1 002.2-M2; do
    run "$case_id" timeout 180 "$py" -c 'import json,sys; from scripts.mutate_byoa002 import exercise; case=exercise(sys.argv[1]); print(json.dumps(case,indent=2)); raise SystemExit(not case["detected"])' "$case_id"
done
run guarded-observations timeout 180 "$py" -I scripts/observe_byoa0024.py
run ceremony timeout 240 "$py" -I scripts/byoa002_demo.py run --consent --custody --expect-commit "$commit" --expect-tree "$tree" --output "$out/ceremony"
for sample in normal lost; do
    public="$out/ceremony"
    if [[ "$sample" == lost ]]; then public="$public/lost-reply"; fi
    run "verify-$sample" "$py" -I scripts/byoa002_demo.py verify --package "$public/package.json" --expect "$public/expectations.json"
done
test "$(git rev-parse HEAD)" = "$commit"
test -z "$(git status --porcelain)"
exit "$failed"
