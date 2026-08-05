#!/bin/bash
# qemu-verify.sh [prog ...]
#
# Re-verify existing Rust translations under the QEMU/x86_64 harness:
# for each program, run `make test-<name>` (swap Rust object in, regen
# skeletons via the kernel Makefile, run affected test_progs tests inside
# the vng/QEMU guest) and then `make restore-<name>`. Results append to
# qemu/results.md. Serial by construction.
#
# The QEMU flavor is selected purely by env overrides — swap-and-test.sh
# and the Makefile are shared with the UML flavor.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"
BUILD="$(cd "${REPO}/.." && pwd)/uml-harness/.build"

export KERNEL_SRC="${BUILD}/bpf-next-x86"
export SELFTESTS_OUTPUT="${BUILD}/selftests-output-qemu"
export VMLINUX_BTF="${KERNEL_SRC}/vmlinux"
export TEST_RUNNER="${REPO}/scripts/qemu-test-progs"

# With no arguments the whole corpus runs and an existing results row means
# "already done" (resume an interrupted run). Explicitly named programs are
# always re-run — their stale row is replaced.
PROGS=("$@")
EXPLICIT=1
if [ "${#PROGS[@]}" -eq 0 ]; then
    EXPLICIT=0
    PROGS=($(ls progs/*.rs | xargs -n1 basename | sed 's/\.rs$//'))
fi

mkdir -p qemu/logs
RESULTS="qemu/results.md"
[ -f "${RESULTS}" ] || {
    echo "| program | verdict | wall | notes |" > "${RESULTS}"
    echo "|---|---|---|---|" >> "${RESULTS}"
}

ADDED=()
for NAME in "${PROGS[@]}"; do
    if grep -q "^| ${NAME} |" "${RESULTS}"; then
        if [ "${EXPLICIT}" -eq 0 ]; then
            echo "skip ${NAME}: already in results" >&2
            continue
        fi
        sed -i "/^| ${NAME} |/d" "${RESULTS}"
    fi
    echo "=== qemu-verify ${NAME} ==="
    START=$(date +%s)
    if timeout 1200 make "test-${NAME}" > "qemu/logs/${NAME}.log" 2>&1 < /dev/null; then
        VERDICT=PASS
    else
        VERDICT=FAIL
    fi
    WALL=$(( $(date +%s) - START ))
    NOTE="$(grep -E "^Summary:" "qemu/logs/${NAME}.log" | tail -1 | tr -d '|')"
    if ! timeout 1200 make "restore-${NAME}" > "qemu/logs/${NAME}.restore.log" 2>&1 < /dev/null; then
        NOTE="${NOTE}; restore-validation-failed"
    fi
    ROW="| ${NAME} | ${VERDICT} | ${WALL}s | ${NOTE} |"
    echo "${ROW}" >> "${RESULTS}"
    ADDED+=("${ROW}")
    echo "${ROW}"
done

# Report only what THIS run produced; the full table lives in ${RESULTS}.
echo "=== qemu-verify done: ${#ADDED[@]} program(s) run ==="
if [ "${#ADDED[@]}" -gt 0 ]; then
    head -2 "${RESULTS}"
    printf '%s\n' "${ADDED[@]}"
fi
