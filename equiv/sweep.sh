#!/usr/bin/env bash
# Run the Z3 equivalence checker over a list of program names, in parallel.
# Usage: equiv/sweep.sh <names-file> <out-dir> [jobs]
# Emits <out-dir>/<name>.log per program and <out-dir>/summary.tsv
set -u
NAMES=$1; OUT=$2; JOBS=${3:-8}
PY=/home/prozak/sources/heimdall_experiment/z3-venv/bin/python
REPO=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$OUT"

run_one() {
    name=$1
    log="$OUT/$name.log"
    timeout 120 "$PY" "$REPO/equiv/check.py" "$name" --timeout 30000 \
        </dev/null >"$log" 2>&1
    rc=$?
    n_equiv=$(grep -c '^  EQUIV' "$log")   # counts EQUIV and EQUIV32
    n_ineq=$(grep -c '^  INEQUIV' "$log")
    n_bail=$(grep -c '^  BAIL' "$log")
    n_core=$(grep -c '^  CORESKIP' "$log")
    n_unk=$(grep -c '^  UNKNOWN\|^  UNPAIRED' "$log")
    if [ $rc -eq 124 ]; then verdict=TIMEOUT
    elif grep -q '^missing object' "$log"; then verdict=NO_OBJ
    elif [ "$n_ineq" -gt 0 ]; then verdict=INEQUIV
    elif [ "$n_bail" -gt 0 ]; then verdict=BAIL
    elif [ "$n_unk" -gt 0 ]; then verdict=UNKNOWN
    elif [ "$n_core" -gt 0 ]; then verdict=CORESKIP
    elif [ "$n_equiv" -gt 0 ] && [ $rc -eq 0 ]; then verdict=EQUIV
    elif grep -q ': 0/0 program' "$log"; then verdict=NOPROGS
    else verdict=ERROR
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$verdict" "$n_equiv" "$n_ineq" "$n_bail" "$n_core" "$n_unk"
}
export -f run_one 2>/dev/null || true
export OUT PY REPO

xargs -a "$NAMES" -P "$JOBS" -I{} bash -c 'run_one "$@"' _ {} > "$OUT/summary.tsv"
sort -o "$OUT/summary.tsv" "$OUT/summary.tsv"
cut -f2 "$OUT/summary.tsv" | sort | uniq -c | sort -rn
