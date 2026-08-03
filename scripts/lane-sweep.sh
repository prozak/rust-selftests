#!/bin/bash
# lane-sweep.sh <lane-id> <candidates.tsv> [max-attempts]
#
# One parallel sweep lane: runs the translation loop over its slice of
# candidates inside its own worktree + selftests output. Writes results
# to the MAIN repo's sweep/lane-results/lane<id>.md (one writer per
# file — no cross-lane races).
#
# GRACEFUL STOP: create <main-repo>/sweep/STOP (any content) and every
# lane finishes its in-flight program and exits. Remove the file and
# relaunch the same command to resume — programs already in any lane's
# results, or already translated in the main repo, are skipped.

set -uo pipefail

LANE="$1"
SAMPLE="$2"
MAX_ATTEMPTS="${3:-2}"

MAIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT="$(dirname "${MAIN}")"
WT="${PARENT}/rust-selftests-lane${LANE}"
BUILD="${PARENT}/uml-harness/.build"

export FLAVOR=qemu
export SELFTESTS_OUTPUT="${BUILD}/selftests-output-qemu-lane${LANE}"
export MODEL="${MODEL:-claude-sonnet-5}"
export TRANSLATE_JSON=1
export QEMU_CPUS="${QEMU_CPUS:-4}"

STOP="${MAIN}/sweep/STOP"
KERNEL_SRC_Q="${BUILD}/bpf-next-x86"
PROG_TESTS="${KERNEL_SRC_Q}/tools/testing/selftests/bpf/prog_tests"

cd "${WT}"
mkdir -p "${MAIN}/sweep/lane-results" "${WT}/sweep/logs"
RESULTS="${MAIN}/sweep/lane-results/lane${LANE}.md"
[ -f "${RESULTS}" ] || {
    echo "| program | loc | verdict | attempts | wall | cost (USD) |" > "${RESULTS}"
    echo "|---|---|---|---|---|---|" >> "${RESULTS}"
}

done_anywhere() {
    local n="$1"
    [ -f "${MAIN}/progs/${n}.rs" ] && return 0
    grep -qh "^| ${n} |" "${MAIN}"/sweep/lane-results/lane*.md 2>/dev/null && return 0
    return 1
}

# read the sample via fd 3: anything inside the loop that touches
# stdin (vng puts the guest console on stdio!) must not eat the list
while IFS=$'\t' read -u 3 -r NAME LOC SECS FEATS; do
    [ -n "${NAME}" ] || continue
    if [ -f "${STOP}" ]; then
        echo "[lane${LANE}] STOP file present — exiting cleanly"
        break
    fi
    done_anywhere "${NAME}" && { echo "[lane${LANE}] skip ${NAME}"; continue; }

    # oracle pre-gate (free): consumers must exist in this build
    if ! grep -l -E "(^| |/)${NAME}\.l?skel\.h" "${SELFTESTS_OUTPUT}"/*.test.d > /dev/null 2>&1 \
        && ! grep -l -E "\"[^\"]*${NAME}\.bpf\.o\"" "${PROG_TESTS}"/*.c > /dev/null 2>&1; then
        echo "| ${NAME} | ${LOC} | ORACLE-UNAVAILABLE | 0 | 0s | 0 |" >> "${RESULTS}"
        continue
    fi

    echo "[lane${LANE}] === ${NAME} (${LOC} loc) ==="
    START=$(date +%s)
    if timeout 2400 ./scripts/translate.sh "${NAME}" "${MAX_ATTEMPTS}" \
            > "${WT}/sweep/logs/${NAME}.log" 2>&1 < /dev/null; then
        VERDICT=PASS
    else
        VERDICT=FAIL
        [ -f "bld/gate-${NAME}.log" ] && \
            tail -80 "bld/gate-${NAME}.log" > "${WT}/sweep/logs/${NAME}.gate.tail"
    fi
    WALL=$(( $(date +%s) - START ))
    ATTEMPTS=$(grep -c "^=== attempt" "${WT}/sweep/logs/${NAME}.log" || true)
    COST=$(grep -h "^AGENT-COST-USD: " "${WT}/sweep/logs/${NAME}.log" \
        | awk '{s += $2} END {printf "%.2f", s}')
    echo "| ${NAME} | ${LOC} | ${VERDICT} | ${ATTEMPTS} | ${WALL}s | ${COST:-0} |" >> "${RESULTS}"

    # keep the lane's output near-pristine: reinstate the C object
    # (validation failure here is recorded but non-fatal)
    timeout 900 make "restore-${NAME}" > /dev/null 2>&1 < /dev/null \
        || cp "${SELFTESTS_OUTPUT}/${NAME}.bpf.o.corig" \
              "${SELFTESTS_OUTPUT}/${NAME}.bpf.o" 2>/dev/null || true
done 3< "${SAMPLE}"

echo "[lane${LANE}] done"
