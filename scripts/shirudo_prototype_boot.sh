#!/bin/sh
# Explicit LAB initrd input. This runs before Shirudo attaches device-mapper guards.
set -eu
umask 077
LC_ALL=C
export LC_ALL
report=/run/wolfalibi/image-boot.json
success=0
stage=load-approved-inputs
set_stage() {
    stage=$1
    printf 'wolfalibi boot stage=%s\n' "$stage" >&2
}
cleanup() {
    exit_status=$?
    trap - EXIT HUP INT TERM
    if [ "$success" != 1 ]; then
        printf 'wolfalibi boot FAILED stage=%s status=%s\n' "$stage" "$exit_status" >&2
        rm -f "$report" "$report.tmp"
        umount /run/wolfalibi/config-witness 2>/dev/null || true
        umount /run/wolfalibi/image 2>/dev/null || true
        veritysetup close wolfalibi-config-witness 2>/dev/null || true
        veritysetup close wolfalibi-gate 2>/dev/null || true
    fi
    veritysetup close wolfalibi-negative 2>/dev/null || true
    exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
# This fixed script handles public image hashes and paths only. Prefix every
# trace line so the bounded CI console diagnostic filter retains the cause.
PS4='+ wolfalibi boot: '
set -x
set_stage load-approved-inputs
. /etc/wolfalibi-boot.conf

set_stage stage-image-files
mkdir -p /run/wolfalibi/image /run/wolfalibi/config-witness /sysroot/var/lib/wolfalibi-image
chmod 0755 /run/wolfalibi /run/wolfalibi/image /run/wolfalibi/config-witness
chmod 0700 /sysroot/var/lib/wolfalibi-image
test ! -e "$report"
cp /wolfalibi-images/gate.img /wolfalibi-images/gate.verity \
    /sysroot/var/lib/wolfalibi-image/
chmod 0444 /sysroot/var/lib/wolfalibi-image/gate.img /sysroot/var/lib/wolfalibi-image/gate.verity
gate_data=/sysroot/var/lib/wolfalibi-image/gate.img
gate_hash=/sysroot/var/lib/wolfalibi-image/gate.verity
config_data=/sysroot/var/lib/shirudo/images/config-boot-keys.img
config_hash=/sysroot/var/lib/shirudo/images/config-boot-keys.verity

# A distinct corrupted backing file and a new mapping give this gate-code
# block no earlier verified mapping cache. Reading through dm-verity must fail.
set_stage corrupt-control-open
veritysetup open /wolfalibi-images/gate-corrupt.img wolfalibi-negative \
    "$gate_hash" "$expected_gate_root"
set_stage corrupt-control-read
set +e
dd if=/dev/mapper/wolfalibi-negative of=/dev/null bs=4096 \
    skip="$corrupt_block" count=1 iflag=direct status=none 2>/run/wolfalibi/corrupt-read.log
corrupt_rc=$?
set -e
test "$corrupt_rc" = 1
grep -q 'Input/output error' /run/wolfalibi/corrupt-read.log
set_stage corrupt-control-close
veritysetup close wolfalibi-negative

# A newly created mapping under the wrong expected root must also reject,
# even though its data and hash files are the unmodified approved files.
set_stage wrong-root-control-open
veritysetup open "$gate_data" wolfalibi-negative "$gate_hash" "$wrong_gate_root"
set_stage wrong-root-control-read
set +e
dd if=/dev/mapper/wolfalibi-negative of=/dev/null bs=4096 count=1 \
    iflag=direct status=none 2>/run/wolfalibi/wrong-root-read.log
wrong_rc=$?
set -e
test "$wrong_rc" = 1
grep -q 'Input/output error' /run/wolfalibi/wrong-root-read.log
set_stage wrong-root-control-close
veritysetup close wolfalibi-negative

set_stage approved-gate-open
veritysetup open "$gate_data" wolfalibi-gate "$gate_hash" "$expected_gate_root"
test "$(blockdev --getro /dev/mapper/wolfalibi-gate)" = 1
data_bytes=$(blockdev --getsize64 /dev/mapper/wolfalibi-gate)
test "$data_bytes" = "$expected_data_bytes"
set_stage approved-gate-full-read
dd if=/dev/mapper/wolfalibi-gate of=/dev/null bs=1048576 iflag=direct status=none
gate_table=$(dmsetup table wolfalibi-gate)
test "$(printf '%s\n' "$gate_table" | awk '{print $12}')" = "$expected_gate_root"
set_stage approved-gate-mount
mount -t ext4 -o ro,nodev,nosuid,noload /dev/mapper/wolfalibi-gate /run/wolfalibi/image
image_device=$(stat -c %d /run/wolfalibi/image)

# A second ordinary mapping witnesses the exact same configuration bytes.
# It can later be bind-mounted read-only into the gate namespace without
# moving Shirudo's own protected configuration mount.
set_stage config-witness-open
veritysetup open "$config_data" wolfalibi-config-witness "$config_hash" "$expected_config_root"
test "$(blockdev --getro /dev/mapper/wolfalibi-config-witness)" = 1
config_bytes=$(blockdev --getsize64 /dev/mapper/wolfalibi-config-witness)
test "$config_bytes" = "$expected_config_bytes"
set_stage config-witness-full-read
dd if=/dev/mapper/wolfalibi-config-witness of=/dev/null bs=4096 iflag=direct status=none
config_table=$(dmsetup table wolfalibi-config-witness)
test "$(printf '%s\n' "$config_table" | awk '{print $12}')" = "$expected_config_root"
set_stage config-witness-mount
mount -t ext4 -o ro,nodev,nosuid,noload /dev/mapper/wolfalibi-config-witness /run/wolfalibi/config-witness
set_stage compare-approved-metadata
cmp /etc/wolfalibi-approved-gate-image.json \
    /run/wolfalibi/config-witness/etc/wolfalibi/gate-image.json
cmp /etc/wolfalibi-approved-anchors.json /run/wolfalibi/image/etc/wolfalibi/anchors.json

# All substitutions are generated bounded integers or lowercase hex, except
# kernel-generated verity tables constrained below to their numeric grammar.
printf '%s\n' "$gate_table" "$config_table" | \
    awk 'NF != 13 || $1 != 0 || $3 != "verity" || $4 != 1 || $7 != 4096 || $8 != 4096 || $10 != 1 || $11 != "sha256" {exit 1}'
case "$gate_table$config_table" in *[!a-z0-9\ :]*) exit 1 ;; esac
set_stage publish-boot-report
printf '{"schema":"wolfalibi.shirudo.image-boot.v1","scope":"LAB_TRUSTED_INITRD","gate_image_root":"%s","config_root":"%s","anchors_sha256":"%s","mount_point":"/run/wolfalibi/image","mapper_name":"wolfalibi-gate","read_only":true,"full_read":true,"data_bytes":%s,"image_device":%s,"dm_table":"%s","config_witness":{"root_hash":"%s","mount_point":"/run/wolfalibi/config-witness","mapper_name":"wolfalibi-config-witness","read_only":true,"full_read":true,"data_bytes":%s,"dm_table":"%s"},"corruption_control":{"mapping_created":true,"read_rejected":true,"read_exit_code":%s,"block":%s},"wrong_root_control":{"mapping_created":true,"read_rejected":true,"read_exit_code":%s,"block":0}}\n' \
    "$expected_gate_root" "$expected_config_root" "$expected_anchors_sha256" \
    "$data_bytes" "$image_device" "$gate_table" "$expected_config_root" "$config_bytes" "$config_table" \
    "$corrupt_rc" "$corrupt_block" "$wrong_rc" >"$report.tmp"
chmod 0644 "$report.tmp"
mv "$report.tmp" "$report"
success=1
set_stage complete
