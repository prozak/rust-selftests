#!/bin/bash
# bench.sh <model-id> [prog ...]
#
# Model benchmark: re-translate already-verified programs from scratch with
# a given model under the identical automated loop, and record pass/fail,
# attempts, wall time, and agent cost. Mirrors the Heimdall paper's
# model-comparison methodology, with our gates as the success criterion.
#
# For each program:
#   - stash the existing verified translation (progs/<name>.rs)
#   - wipe its build artifacts so the loop starts clean
#   - run MODEL=<model-id> TRANSLATE_JSON=1 scripts/translate.sh <name>
#   - archive the model's translation + log under bench/<model-id>/
#   - restore the original translation and its build artifacts
#   - reinstate the pristine C object + skeletons in the selftests output
#     (scripts/swap-and-test.sh <name> c — also re-validates restoration)
#
# Results append to bench/<model-id>/results.md. Programs default to every
# existing translation. MUST run serially (shared selftests output).

set -uo pipefail

MODEL_ID="$1"; shift
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"

PROGS=("$@")
[ "${#PROGS[@]}" -gt 0 ] || PROGS=($(ls progs/*.rs | xargs -n1 basename | sed 's/\.rs$//'))

BENCH="bench/${MODEL_ID}"
mkdir -p "${BENCH}"
RESULTS="${BENCH}/results.md"
[ -f "${RESULTS}" ] || {
    echo "| program | verdict | attempts | wall | agent cost (USD) |" > "${RESULTS}"
    echo "|---|---|---|---|---|" >> "${RESULTS}"
}

for NAME in "${PROGS[@]}"; do
    [ -f "progs/${NAME}.rs" ] || { echo "skip ${NAME}: no verified translation" >&2; continue; }
    echo "=== bench ${MODEL_ID} / ${NAME} ==="

    mv "progs/${NAME}.rs" "bench/.stash-${NAME}.rs"
    rm -f bld/${NAME}.* bld/${NAME}-*.bc "bld/translate-${NAME}.log" "bld/gate-${NAME}.log"

    START=$(date +%s)
    if MODEL="${MODEL_ID}" TRANSLATE_JSON=1 ./scripts/translate.sh "${NAME}" 3 \
            > "${BENCH}/${NAME}.log" 2>&1; then
        VERDICT=PASS
    else
        VERDICT=FAIL
    fi
    WALL=$(( $(date +%s) - START ))

    ATTEMPTS=$(grep -c "^=== attempt" "${BENCH}/${NAME}.log" || true)
    COST=$(grep -h "^AGENT-COST-USD: " "${BENCH}/${NAME}.log" \
        | awk '{s += $2} END {printf "%.2f", s}')

    [ -f "progs/${NAME}.rs" ] && cp "progs/${NAME}.rs" "${BENCH}/${NAME}.rs"
    rm -f "progs/${NAME}.rs"
    mv "bench/.stash-${NAME}.rs" "progs/${NAME}.rs"
    rm -f bld/${NAME}.* bld/${NAME}-*.bc

    # restore pristine C object + skeletons; re-runs affected tests as a
    # restoration check (failure here is a harness problem, not the model's)
    if ! scripts/swap-and-test.sh "${NAME}" c > "${BENCH}/${NAME}.restore.log" 2>&1; then
        echo "WARNING: C-restore for ${NAME} failed, see ${BENCH}/${NAME}.restore.log" >&2
    fi

    echo "| ${NAME} | ${VERDICT} | ${ATTEMPTS} | ${WALL}s | ${COST:-?} |" >> "${RESULTS}"
    tail -1 "${RESULTS}"
done

# rebuild the original translations' objects so `make` state is clean
make > /dev/null 2>&1 || true
echo "=== bench ${MODEL_ID} done ==="
cat "${RESULTS}"
