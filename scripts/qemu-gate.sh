#!/bin/bash
# qemu-gate.sh [-l N] [prog ...]
#
# The QEMU gate over the whole corpus, N lanes in parallel (default 4):
# for every translation, swap the Rust object into a lane's private copy
# of the selftests output, regenerate skeletons, relink test_progs, run
# the consuming prog_tests in the guest, then put the C object back.
# Same per-object semantics as `make test-<name>` / qemu-verify.sh, but
# it drives scripts/swap-and-test.sh directly with the QEMU-flavor
# environment: going through make would let each lane's freshly created
# .corig retrigger the object build in the shared bld/, and four lanes
# rebuilding the same bld/ files at once is a race.
#
# Objects come from THIS repo's bld/ (build them first); the lane outputs
# come from scripts/setup-lanes.sh. Results land in qemu/gate/lane<i>.md
# (one writer per file) and are merged into qemu/gate/results.md at the
# end. A FAIL is re-run with the pristine C object so the row records
# whether the C object passes in the same environment (C-FAIL = the test
# is broken here, not the translation).

set -uo pipefail

LANES=4
while getopts "l:" opt; do
    case "$opt" in
        l) LANES="$OPTARG" ;;
        *) echo "usage: $0 [-l N] [prog ...]" >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO}"
BUILD="$(cd "${REPO}/.." && pwd)/uml-harness/.build"

export KERNEL_SRC="${BUILD}/bpf-next-x86"
export SELFTESTS_SRC="${KERNEL_SRC}/tools/testing/selftests/bpf"
export LLVM_PREFIX="${LLVM_PREFIX:-${BUILD}/llvm-install}"
export FLAVOR=qemu
export VMLINUX_BTF="${KERNEL_SRC}/vmlinux"
export TEST_RUNNER="${REPO}/scripts/qemu-test-progs"
export QEMU_CPUS="${QEMU_CPUS:-4}"

PROGS=("$@")
if [ "${#PROGS[@]}" -eq 0 ]; then
    PROGS=($(ls progs/*.rs | xargs -n1 basename | sed 's/\.rs$//'))
fi
for n in "${PROGS[@]}"; do
    [ -f "bld/${n}.bpf.o" ] || { echo "bld/${n}.bpf.o missing — build first" >&2; exit 1; }
done
for i in $(seq 1 "${LANES}"); do
    [ -x "${BUILD}/selftests-output-qemu-lane${i}/test_progs" ] \
        || { echo "lane ${i} output missing (scripts/setup-lanes.sh ${LANES})" >&2; exit 1; }
done

GATE="qemu/gate"
mkdir -p "${GATE}/logs"

run_lane() {
    local lane="$1"; shift
    local out="${BUILD}/selftests-output-qemu-lane${lane}"
    local results="${GATE}/lane${lane}.md"
    echo "| program | verdict | wall | notes |" > "${results}"
    echo "|---|---|---|---|" >> "${results}"
    local name start wall verdict note log
    for name in "$@"; do
        log="${GATE}/logs/${name}.log"
        start=$(date +%s)
        if SELFTESTS_OUTPUT="${out}" timeout 1200 \
                scripts/swap-and-test.sh "${name}" rust > "${log}" 2>&1 < /dev/null; then
            verdict=PASS
        elif grep -q "no prog_tests consume ${name}" "${log}"; then
            verdict=NO-ORACLE
        else
            verdict=FAIL
        fi
        wall=$(( $(date +%s) - start ))
        note="$(grep -E "^Summary:" "${log}" | tail -1 | tr -d '|')"
        # put the C object back; only a FAIL pays for a second guest boot
        # to learn whether the C object passes here at all
        if [ "${verdict}" = FAIL ]; then
            if SELFTESTS_OUTPUT="${out}" timeout 1200 \
                    scripts/swap-and-test.sh "${name}" c > "${log%.log}.c.log" 2>&1 < /dev/null; then
                note="${note}; C-PASS"
            elif grep -q "no prog_tests consume ${name}" "${log%.log}.c.log"; then
                # the Rust swap broke a test object's compile, which also
                # dropped its .test.d, so consumer discovery finds nothing
                # now: the C object was not actually exercised
                note="${note}; C-NOCONSUMER"
            else
                note="${note}; C-FAIL"
            fi
        else
            SELFTESTS_OUTPUT="${out}" SWAP_ONLY=1 timeout 1200 \
                scripts/swap-and-test.sh "${name}" c > "${log%.log}.c.log" 2>&1 < /dev/null \
                || cp "${out}/${name}.bpf.o.corig" "${out}/${name}.bpf.o" 2>/dev/null
        fi
        echo "| ${name} | ${verdict} | ${wall}s | ${note} |" >> "${results}"
        echo "[lane${lane}] ${name}: ${verdict} (${wall}s)"
    done
}

# round-robin slices keep every lane busy regardless of object size order
declare -a SLICE
for idx in "${!PROGS[@]}"; do
    lane=$(( idx % LANES + 1 ))
    SLICE[$lane]="${SLICE[$lane]:-} ${PROGS[$idx]}"
done
PIDS=()
for i in $(seq 1 "${LANES}"); do
    run_lane "${i}" ${SLICE[$i]:-} &
    PIDS+=($!)
done
wait "${PIDS[@]}"

MERGED="${GATE}/results.md"
{
    echo "| program | verdict | wall | notes |"
    echo "|---|---|---|---|"
    tail -q -n +3 "${GATE}"/lane*.md | sort
} > "${MERGED}"
echo "=== qemu-gate done: $(tail -n +3 "${MERGED}" | wc -l) program(s) ==="
tail -n +3 "${MERGED}" | awk -F'|' '{print $3}' | sort | uniq -c
