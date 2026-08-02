#!/bin/bash
# sweep.sh <sample.tsv> [max-attempts]
#
# Stratified sample sweep: run the automated translation loop over a list
# of not-yet-translated programs (sample.tsv: name<TAB>loc<TAB>secs<TAB>feats),
# keep successful translations in progs/, and record one results row per
# program for the failure taxonomy. MUST run serially (shared selftests
# output). Model policy: sonnet-5 first (see bench/README.md).
#
# Before spending any agent budget, a pre-gate replicates swap-and-test's
# consumer discovery: a program whose skeleton is in no *.test.d and whose
# object no prog_tests source loads at runtime has no oracle in THIS build
# (e.g. its tests are UML-incompatible and were skipped) — recorded as
# ORACLE-UNAVAILABLE without invoking the agent.

set -uo pipefail

SAMPLE="$1"
MAX_ATTEMPTS="${2:-2}"
MODEL_ID="${MODEL:-claude-sonnet-5}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"

KERNEL_SRC="$(make -s echo-kernel-src)"
OUT="${SELFTESTS_OUTPUT:-$(cd "${REPO}/.." && pwd)/uml-harness/.build/selftests-output-heimdall}"
PROG_TESTS="${KERNEL_SRC}/tools/testing/selftests/bpf/prog_tests"

SWEEP="sweep"
mkdir -p "${SWEEP}/logs"
RESULTS="${SWEEP}/results.md"
[ -f "${RESULTS}" ] || {
    echo "| program | loc | secs | feats | verdict | attempts | wall | cost (USD) |" > "${RESULTS}"
    echo "|---|---|---|---|---|---|---|---|" >> "${RESULTS}"
}

PASSED=()
while IFS=$'\t' read -r NAME LOC SECS FEATS; do
    [ -n "${NAME}" ] || continue
    if [ -f "progs/${NAME}.rs" ]; then
        echo "skip ${NAME}: translation already exists" >&2
        continue
    fi
    if grep -q "| ${NAME} |" "${RESULTS}"; then
        echo "skip ${NAME}: already in results" >&2
        continue
    fi
    echo "=== sweep ${NAME} (${LOC} loc; ${SECS}; ${FEATS}) ==="

    if ! grep -l -E "(^| |/)${NAME}\.l?skel\.h" "${OUT}"/*.test.d > /dev/null 2>&1 \
        && ! grep -l -E "\"[^\"]*${NAME}\.bpf\.o\"" "${PROG_TESTS}"/*.c > /dev/null 2>&1; then
        echo "| ${NAME} | ${LOC} | ${SECS} | ${FEATS} | ORACLE-UNAVAILABLE | 0 | 0s | 0 |" >> "${RESULTS}"
        tail -1 "${RESULTS}"
        continue
    fi

    START=$(date +%s)
    # </dev/null: anything inside the loop reading stdin would swallow
    # sample lines (this ate one program in the 2026-08-01 run)
    if MODEL="${MODEL_ID}" TRANSLATE_JSON=1 timeout 1800 \
            ./scripts/translate.sh "${NAME}" "${MAX_ATTEMPTS}" \
            > "${SWEEP}/logs/${NAME}.log" 2>&1 < /dev/null; then
        VERDICT=PASS
        PASSED+=("${NAME}")
    else
        VERDICT=FAIL
        [ -f "bld/gate-${NAME}.log" ] && \
            tail -80 "bld/gate-${NAME}.log" > "${SWEEP}/logs/${NAME}.gate.tail"
    fi
    WALL=$(( $(date +%s) - START ))
    ATTEMPTS=$(grep -c "^=== attempt" "${SWEEP}/logs/${NAME}.log" || true)
    COST=$(grep -h "^AGENT-COST-USD: " "${SWEEP}/logs/${NAME}.log" \
        | awk '{s += $2} END {printf "%.2f", s}')

    echo "| ${NAME} | ${LOC} | ${SECS} | ${FEATS} | ${VERDICT} | ${ATTEMPTS} | ${WALL}s | ${COST:-0} |" >> "${RESULTS}"
    tail -1 "${RESULTS}"
done < "${SAMPLE}"

# Reinstate pristine C objects for every success (also re-validates the
# restoration; the Rust translations stay in progs/).
for NAME in "${PASSED[@]}"; do
    make "restore-${NAME}" > "${SWEEP}/logs/${NAME}.restore.log" 2>&1 \
        || echo "WARNING: C-restore for ${NAME} failed" >&2
done

echo "=== sweep done: ${#PASSED[@]} passed ==="
cat "${RESULTS}"
