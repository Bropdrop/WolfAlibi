#!/usr/bin/env bash
# Run using bash on a Linux host supporting unprivileged bubblewrap and >=1000 threads.
set -euo pipefail
if [[ $# != 4 ]]; then
    echo 'Usage: reproduce.sh LOCAL_REPOSITORY BASELINE_EVIDENCE_ZIP SOVEREIGN_PATCH PINNED_ETCD_BINARY' >&2
    exit 2
fi
repo=$(realpath "$1")
archive=$(realpath "$2")
patch=$(realpath "$3")
binary=$(realpath "$4")
base=24cb95c2223a861f6fc8120d8a9b95d35a8d827a
test "$(git -C "$repo" rev-parse research/wt-swarm-004a)" = "$base"
echo "29fde46015e893f1f6efa4eb2b903e72d2ecabeceebad4e466085091efbd7f14  $archive" | sha256sum -c -
echo "c054131938a55a4a9826c1d566348d5695fe0e4d9ce655dfe936ab18a84e2983  $binary" | sha256sum -c -
work=$(mktemp -d)
echo "Results and detached worktrees at $work"
mkdir "$work/baseline"
unzip -q "$archive" -d "$work/baseline"
manifest=$(find "$work/baseline" -name SHA256SUMS -print -quit)
evidence=$(dirname "$manifest")
(cd "$evidence" && sha256sum --quiet -c SHA256SUMS)
export PYTHONDONTWRITEBYTECODE=1
git -C "$repo" worktree add --detach "$work/original" "$base"
cd "$work/original"
for prior in standalone repeat; do
    python -m research.continuity.audit "$evidence/$prior" "$evidence/$prior/verification-roots.json" | cmp - "$evidence/$prior/verified.json"
    python -m research.continuity.trial "$work/prior-$prior" --stress
done
modules=(research.blackout.test_recovery research.schism.test_fence research.exodus.test_continuity research.continuity.test_lineage research.continuity.test_interrupt)
inherited() {
    python -m unittest discover -s tests -v
    python -m unittest "${modules[@]}" -v
    PYTHONPATH="$PWD" python "$evidence/test_historical_grant.py" -v
}
inherited
for pass in first repeat; do
    git -C "$repo" worktree add --detach "$work/$pass" "$base"
    cd "$work/$pass"
    git apply --index "$patch"
    inherited
    python -m unittest research.sovereign.test_sovereign -v
    out="$work/sovereign-$pass"
    python -m research.sovereign.trial "$out" --stress --etcd "$binary"
    python -m research.sovereign.review "$out" "$out/observer-pins.json"
    python -m research.sovereign.controls "$out"
done
