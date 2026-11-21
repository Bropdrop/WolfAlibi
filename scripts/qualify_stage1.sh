#!/usr/bin/env bash
# Reproduce the Stage 1 qualification only on the immutable pushed revision.
# All project fixtures are synthetic and local. This script does not fetch,
# push, deploy, enable CI, or change Git history.
set -euo pipefail

wolfalibi_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
wolfalibi_expected_commit="${1:-dd7c5c76cadc49ab464f14abdbf77269ca735291}"
cd "$wolfalibi_root"

test "$(git rev-parse HEAD)" = "$wolfalibi_expected_commit"
test -z "$(git status --short)"

python3 -m unittest discover -v
python3 -m unittest -v test_wolftrap_alibi.py
python3 -u mutation_test.py
python3 alibi.py demo
python3 alibi.py bench 1000000
