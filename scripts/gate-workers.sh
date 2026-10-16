#!/bin/bash
# gate-workers.sh <N> | --clean
#
# Private selftests output trees for running the QEMU gate in parallel.
# swap-and-test.sh swaps a Rust object into the output tree, rebuilds the
# skeletons and test_progs there, and runs the tests from it, so two objects
# can only be tested at once in two trees. Worker K's tree is
#
#   $BUILD_DIR/gate/wK/selftests-output-qemu
#
# a copy of the shared tree WITHOUT the no_alu32/ and cpuv4/ flavors (the
# gate only rebuilds and runs plain test_progs): about 0.7 GB instead of
# 1.5 GB. A hardlink farm would cost nothing but is unsafe: bpftool gen
# skeleton and the compilers rewrite files in place, which would write
# through into the shared tree.
#
# Trees are kept between runs: rsync only refreshes what changed. The .d and
# .cmd files record the shared tree's absolute path; they are rewritten to
# the worker's own path, or make would read the shared tree's dependencies.
# bpftool is shared read-only (swap-and-test.sh finds it beside the output
# directory). --clean removes every worker tree.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "${HERE}/scripts/paths.sh"
GATE="${BUILD_DIR}/gate"
SRC="$(cd "${SELFTESTS_OUTPUT}" && pwd)"
FLAVOR_DIR="$(basename "${SRC}")"                  # selftests-output-qemu
BPFTOOL_DIR="bpftool-output-${FLAVOR_DIR#selftests-output-}"

if [ "${1:-}" = --clean ]; then
    rm -rf "${GATE}"
    exit 0
fi
N="${1:?usage: $0 <workers> | --clean}"

# A swapped-in Rust object in the shared tree would be copied as if it were
# the C object.
for orig in "${SRC}"/*.bpf.o.corig; do
    [ -e "${orig}" ] || break
    cmp -s "${orig}" "${orig%.corig}" || {
        echo "${orig%.corig} is swapped; run make restore-all first" >&2; exit 1; }
done

for k in $(seq 1 "${N}"); do
    w="${GATE}/w${k}"
    dst="${w}/${FLAVOR_DIR}"
    mkdir -p "${dst}"
    ln -sfn "${BUILD_DIR}/${BPFTOOL_DIR}" "${w}/${BPFTOOL_DIR}"
    rsync -a --delete --exclude=/no_alu32/ --exclude=/cpuv4/ \
        --exclude='*.corig' "${SRC}/" "${dst}/"
    find "${dst}" \( -name '*.d' -o -name '*.cmd' \) -type f \
        -exec grep -lZF "${SRC}" {} + 2>/dev/null \
        | xargs -0r sed -i "s#${SRC}#${dst}#g"
    echo "worker ${k}: ${dst} ($(du -sh "${dst}" | cut -f1))"
done
