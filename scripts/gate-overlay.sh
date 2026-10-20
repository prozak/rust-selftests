#!/bin/bash
# gate-overlay.sh <worker-dir> <prog-name> <rust|c>
#
# One QEMU gate run of <prog-name> in a private overlay on top of the shared
# selftests output, which stays untouched: every file swap-and-test.sh
# writes (the object, its skeleton, the consuming .test.o, test_progs) lands
# in <worker-dir>/upper, typically 35-50 MB. Several workers can therefore
# run at once, and "restoring" the C object is emptying upper/.
#
#   1. host: in an unprivileged user+mount namespace, mount
#      overlay(lower=shared, upper=<worker>/upper) OVER the shared tree's own
#      path (so every absolute path in .d files and Makefiles stays valid)
#      and run swap-and-test.sh with a TEST_RUNNER that only records the
#      test filter. The guest cannot boot in there: /dev/kvm refuses opens
#      from a user namespace.
#   2. guest: qemu-test-progs with GATE_UPPER=<worker>/upper mounts
#      overlay(lower=upper:shared, upper=tmpfs) over the same path before
#      running test_progs. Host whiteouts do not survive 9p, so deletions
#      recorded in upper are replayed in the guest.
#
# GATE_PREPARE=1: step 1 only, for a worker whose guest was booted once and
# runs its objects in sequence (scripts/gate-guest-loop): <worker-dir> is
# then one of the worker's two slots (<worker>/s0, <worker>/s1), the -t
# filter and the -d denylist go into its upper/ as the files test_progs
# reads, and the caller (scripts/qemu_gate.py) posts the slot to the guest
# as a job once the guest's previous job is done. Two slots let the host
# build the next object while the guest runs the current one; a classic
# run (no GATE_PREPARE) uses <worker>/upper and never touches a slot.
# Booting one guest per object (the default) costs ~16 s of boot, init and
# setup for a median 0.5 s of tests (docs/gate-runtime.md).
#
# The shared tree must not change while workers run (ci_nightly.py holds
# its lock). Exit status: swap-and-test's on a failed build, else the
# guest's (0 under GATE_PREPARE).
set -euo pipefail

W="$(mkdir -p "$1" && cd "$1" && pwd)"
NAME="$2"
WHICH="$3"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "${HERE}/scripts/paths.sh"
# swap-and-test.sh takes its paths from the environment (the Makefile
# exports them); run by hand, this script has to do the same
export BUILD_DIR KERNEL_SRC SELFTESTS_SRC SELFTESTS_OUTPUT LLVM_PREFIX VMLINUX_BTF QEMU_KERNEL
OUT="$(cd "${SELFTESTS_OUTPUT}" && pwd)"

# overlayfs leaves work/work behind with mode 000
[ ! -d "${W}/work" ] || chmod -R u+rwx "${W}/work"
rm -rf "${W}/upper" "${W}/work" "${W}/filter"
mkdir -p "${W}/upper" "${W}/work"

# 1. build in the namespace; the recorder stands in for the guest runner
GATE_FILTER_OUT="${W}/filter" TEST_RUNNER="${HERE}/scripts/gate-record-filter" \
SELFTESTS_OUTPUT="${OUT}" \
unshare -Urm bash -c '
    set -e
    mount -t overlay overlay \
        -o "lowerdir=$1,upperdir=$2/upper,workdir=$2/work" "$1"
    cd "$3"
    exec scripts/swap-and-test.sh "$4" "$5"
' gate "${OUT}" "${W}" "${HERE}" "${NAME}" "${WHICH}"

# Deleted files become whiteouts in upper/ and are replayed in the guest. A
# directory deleted and recreated would need overlay's opaque-dir xattr
# (trusted.*), which an unprivileged mount cannot set: that fails the build
# above instead of producing a wrong tree.
[ -s "${W}/filter" ] || { echo "gate-overlay: no test filter recorded" >&2; exit 1; }

# 2. run the guest on the same two-layer view
FILTER="$(sed -n 1p "${W}/filter")"
DENY="$(sed -n 2p "${W}/filter")"
if [ -n "${GATE_PREPARE:-}" ]; then
    # Always files (qemu-test-progs says why); in the slot's layer, so the
    # guest's overlay shows them in its cwd.
    tr ',' '\n' <<< "${FILTER}" > "${W}/upper/.test-filter"
    rm -f "${W}/upper/.test-deny"
    [ -z "${DENY}" ] || tr ',' '\n' <<< "${DENY}" > "${W}/upper/.test-deny"
    echo "[gate-overlay] prepared ${W}/upper"
    exit 0
fi
GATE_UPPER="${W}/upper" SELFTESTS_OUTPUT="${OUT}" \
    "${HERE}/scripts/qemu-test-progs" -t "${FILTER}" ${DENY:+-d "${DENY}"}
