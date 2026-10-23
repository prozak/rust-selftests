#!/bin/bash
# swap-and-test.sh <prog-name> <rust|c>
#
# Install either the Rust translation (bld/<name>.bpf.o) or the pristine C
# object (<name>.bpf.o.corig) as <name>.bpf.o in the selftests output, then
# drive the KERNEL'S OWN selftests Makefile to regenerate every skeleton and
# test object derived from it, relink test_progs, and run the affected tests
# inside the guest (TEST_RUNNER: QEMU by default). The prog_tests harness
# is reused verbatim.
#
# The set of affected tests is discovered from the generated *.test.d
# dependency files (which record skeleton-header inclusion), so prog-name /
# test-name mismatches are handled without any hardcoded mapping; within a
# consuming file, scripts/affected_tests.py keeps the test functions that
# reference the object or its skeleton (see there). An object that is one
# half of a multi-object skeleton (Makefile.skel's `<skel>.skel.h-deps`)
# has that skeleton regenerated, with the other halves as installed, and
# its consumers.
#
# Expects env (exported by the Makefile): KERNEL_SRC SELFTESTS_SRC
# SELFTESTS_OUTPUT LLVM_PREFIX TEST_RUNNER; FLAVOR=uml adds UML_HARNESS and
# UML_INSTALL_DIR.

set -euo pipefail

NAME="$1"
WHICH="${2:-rust}"

: "${KERNEL_SRC:?}" "${SELFTESTS_SRC:?}" "${SELFTESTS_OUTPUT:?}"
: "${LLVM_PREFIX:?}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLAVOR="${FLAVOR:-qemu}"
if [ "${FLAVOR}" = uml ]; then
    : "${UML_HARNESS:?}" "${UML_INSTALL_DIR:?}"
    TEST_RUNNER="${TEST_RUNNER:-${UML_HARNESS}/uml-test-progs}"
    # the UML kernel's pt_regs layout, for any BPF C the harness rebuilds
    FLAVOR_BPF_CFLAGS="EXTRA_BPF_CFLAGS=-D__UML_PT_REGS__"
else
    TEST_RUNNER="${TEST_RUNNER:-${HERE}/scripts/qemu-test-progs}"
    FLAVOR_BPF_CFLAGS=
fi

OUT="${SELFTESTS_OUTPUT}"
ORIG="${OUT}/${NAME}.bpf.o.corig"

# Back up the pristine C object once, before the first swap.
[ -f "${ORIG}" ] || cp "${OUT}/${NAME}.bpf.o" "${ORIG}"

case "${WHICH}" in
    rust) SRC="${HERE}/bld/${NAME}.bpf.o" ;;
    c)    SRC="${ORIG}" ;;
    *)    echo "usage: $0 <prog-name> <rust|c>" >&2; exit 1 ;;
esac
[ -f "${SRC}" ] || { echo "missing ${SRC}" >&2; exit 1; }

cp "${SRC}" "${OUT}/${NAME}.bpf.o"
echo "[swap] installed $(basename "${SRC}") as ${NAME}.bpf.o (${WHICH})"
# A stale bench job file would make the guest run benches instead of
# test_progs (scripts/gate-bench-run); under the gate's overlay the
# deletion is a whiteout the guest replays.
rm -f "${OUT}/.bench-runs"

# The selftests make invocation, mirroring build-qemu-selftests.sh (and
# bpf-uml-selftests build.sh under FLAVOR=uml).
# NOTE: TRUNNER target names contain a double slash (OUTPUT has a trailing
# slash and the Makefile concatenates another) — goals must match exactly,
# otherwise make falls back to builtin rules or reports "No rule".
sfmake() {
    make -C "${SELFTESTS_SRC}" \
        OUTPUT="${OUT}/" \
        CLANG="${LLVM_PREFIX}/bin/clang" \
        LLC="${LLVM_PREFIX}/bin/llc" \
        LD="${LLVM_PREFIX}/bin/ld.lld" \
        BPFTOOL="$(dirname "${OUT}")/bpftool-output-$(basename "${OUT}" | sed 's/^selftests-output-//')/bpftool" \
        VMLINUX_BTF="${VMLINUX_BTF:-${KERNEL_SRC}/linux}" \
        ARCH=x86_64 TEST_KMODS= SKIP_LLVM=1 \
        ${FLAVOR_BPF_CFLAGS} BPF_STRICT_BUILD=0 \
        NON_CHECK_FEAT_TARGETS="clean docs-clean emit_tests $*" \
        -j"$(nproc)" -k "$@"
}
# NON_CHECK_FEAT_TARGETS: the selftests Makefile includes
# tools/build/Makefile.feature for every goal outside that list, and the
# include probes the toolchain on every make (a test-all.c compile that
# fails, then test-llvm): 0.3 s per invocation here, for a result
# (feature-llvm) the Makefile reads only under SKIP_LLVM != 1. Naming our
# goals in the list skips the include. Should a bpf-next bump rename the
# variable, the probe merely runs again.

# Regenerate the skeleton headers derived from this object, if any. Tests
# without skeletons load the .bpf.o from disk at runtime, so the swap alone
# is enough for them.
#
# A multi-object skeleton (Makefile.skel: `<skel>.skel.h-deps := a.bpf.o
# b.bpf.o ...`) is derived from every object it links, whatever its name:
# bpftool's static linker merges the halves as installed, so a swap of any
# half regenerates it, and the skeleton's consumers are that half's.
LINKED=()
if [ -f "${SELFTESTS_SRC}/Makefile.skel" ]; then
    while read -r skel deps; do
        case " ${deps} " in *" ${NAME}.bpf.o "*) LINKED+=("${skel}") ;; esac
    done < <(sed -n 's/^\([A-Za-z0-9_]*\)\.skel\.h-deps *:= *\(.*\)$/\1.skel.h \2/p' \
             "${SELFTESTS_SRC}/Makefile.skel")
fi
SKELS=()
for b in "${NAME}.skel.h" "${NAME}.lskel.h" ${LINKED[@]+"${LINKED[@]}"}; do
    case " ${SKELS[*]-} " in *"/${b} "*) continue ;; esac
    h="${OUT}/${b}"
    # A failed skeleton build can remove the header. Its C consumer still
    # requires it on the next swap/restore, so recover from source includes;
    # a linked skeleton is always one the Makefile builds.
    if [ ! -f "${h}" ]; then
        case " ${LINKED[*]-} " in *" ${b} "*) ;; *)
            grep -qF "\"${b}\"" "${SELFTESTS_SRC}"/prog_tests/*.c || continue ;;
        esac
    fi
    rm -f "${h}"
    SKELS+=("${OUT}//${b}")
done

TESTS=()
if [ "${#SKELS[@]}" -gt 0 ]; then
    # Find every test object whose dep file pulls in one of those skeletons.
    # The dep files are the previous build's, which is enough: a test's
    # include set does not depend on the skeleton's content. A linked
    # skeleton's generation also writes <skel>.subskel.h, which is what a
    # subskeleton's consumer includes (test_subskeleton_lib).
    for h in "${SKELS[@]}"; do
        stem="$(basename "${h}")"; stem="${stem%.lskel.h}"; stem="${stem%.skel.h}"
        for d in $(grep -l -E "(^| |/)${stem}\.(l?skel|subskel)\.h" "${OUT}"/*.test.d); do
            base="$(basename "${d}" .test.d)"
            # A map_tests/ source is compiled into test_maps, which the
            # gate never runs (#68): not a consumer. Keeping it would make
            # the test_progs relink below demand a test object the main
            # Makefile does not build (map_percpu_stats: C-FAIL for the
            # pristine object too).
            if [ -f "${SELFTESTS_SRC}/map_tests/${base}.c" ] && \
               [ ! -f "${SELFTESTS_SRC}/prog_tests/${base}.c" ]; then
                continue
            fi
            case " ${TESTS[*]-} " in *" ${base} "*) ;; *) TESTS+=("${base}") ;; esac
        done
    done
    # The selftests build auto-generates skeletons for every prog; some tests
    # ignore them and load the .bpf.o from disk instead, so an unconsumed
    # skeleton is normal — fall through to runtime discovery.
    #
    # One make for the skeletons and, with consumers, test_progs: its rule
    # depends on every skeleton, so the regeneration precedes the runner
    # sub-make (Makefile.runner, since bpf-next 645f5fcf) whose .test.d
    # includes make it recompile the objects that include a regenerated
    # skeleton; the relink follows. A *.test.o is no longer a goal the main
    # Makefile knows. A second make for the skeletons alone would parse the
    # Makefile (and its toolchain probes) twice: 0.25 s per swap.
    GOALS=("${SKELS[@]}")
    if [ "${#TESTS[@]}" -gt 0 ]; then
        rm -f "${OUT}/test_progs"
        GOALS+=("${OUT}//test_progs")
    fi
    sfmake "${GOALS[@]}" > /dev/null
    if [ "${#TESTS[@]}" -gt 0 ]; then
        # PERMISSIVE mode drops an object whose compile failed from the link
        # without failing make, so demand one newer than the skeleton for
        # each test.
        for base in "${TESTS[@]}"; do
            for h in "${SKELS[@]}"; do
                [ "${OUT}/${base}.test.o" -nt "${OUT}/$(basename "${h}")" ] || \
                    { echo "failed to rebuild ${base}.test.o" >&2; exit 1; }
            done
        done
        [ -x "${OUT}/test_progs" ] || { echo "test_progs relink failed" >&2; exit 1; }
        echo "[swap] test_progs relinked"
    fi
fi

# Tests may also reference the object file by name and load it at runtime
# (no skeleton involved); those need no rebuild, just the swapped file.
for f in $(grep -l -E "\"[^\"]*${NAME}\.bpf\.o\"" "${SELFTESTS_SRC}"/prog_tests/*.c); do
    base="$(basename "${f}" .c)"
    case " ${TESTS[*]-} " in *" ${base} "*) ;; *) TESTS+=("${base}") ;; esac
done
# A consumer neither grep can see: a prog_tests file that runs a user
# program which builds the object's file name at run time
# (prog_tests/xdp_synproxy.c runs ./xdp_synproxy, which opens
# "<argv0>_kern.bpf.o"). scripts/extra-consumers lists those by hand.
while read -r obj base; do
    case "${obj}" in ''|'#'*) continue ;; esac
    [ "${obj}" = "${NAME}" ] || continue
    case " ${TESTS[*]-} " in *" ${base} "*) ;; *) TESTS+=("${base}") ;; esac
done < "${HERE}/scripts/extra-consumers"

# A benchs/ object: its only consumer is the `bench` driver, and
# scripts/bench-consumers says which bench names (and arguments) exercise
# it. Relink bench the way test_progs is relinked above (the Makefile's
# bench_<x>.o rules name the skeletons they include, so the regenerated
# skeleton recompiles the driver's object), write the rows to .bench-runs
# for the guest (scripts/gate-bench-run; under the gate's overlay the
# file lands in the worker's layer) and run the guest with a filter that
# names the object. A driver that no longer compiles against the
# skeleton (a type the Rust BTF spells differently; -Werror) is a FAIL
# here, which the C re-run then classifies.
if [ "${#TESTS[@]}" -eq 0 ]; then
    BENCH_ROWS=()
    while read -r obj rest; do
        case "${obj}" in ''|'#'*) continue ;; esac
        [ "${obj}" = "${NAME}" ] || continue
        BENCH_ROWS+=("${rest}")
    done < "${HERE}/scripts/bench-consumers"
    if [ "${#BENCH_ROWS[@]}" -gt 0 ]; then
        rm -f "${OUT}/bench"
        sfmake "${OUT}//bench" > /dev/null
        # bench_<x>.o rules: one line each, '\'-continued (bench_ringbufs)
        for o in $(sed -e ':a' -e '/\\$/N; s/\\\n//; ta' "${SELFTESTS_SRC}/Makefile" \
                   | sed -n "s|^\$(OUTPUT)/\(bench_[a-z_0-9]*\.o\):.*/${NAME}\.skel\.h.*|\1|p"); do
            [ "${OUT}/${o}" -nt "${OUT}/${NAME}.skel.h" ] || \
                { echo "failed to rebuild ${o}" >&2; exit 1; }
        done
        [ -x "${OUT}/bench" ] || { echo "bench relink failed" >&2; exit 1; }
        echo "[swap] bench relinked"
        printf '%s\n' "${BENCH_ROWS[@]}" > "${OUT}/.bench-runs"
        echo "[swap] bench runs: $(printf '%s; ' "${BENCH_ROWS[@]}")"
        TESTS=("bench:${NAME}")
    fi
fi
[ "${#TESTS[@]}" -gt 0 ] || { echo "no prog_tests consume ${NAME}" >&2; exit 1; }

# The names collected above are prog_tests FILE basenames, but the -t
# filter matches REGISTERED test names (the test_<name>() functions).
# They coincide for most files but not all (bpf_verif_scale.c registers
# verif_scale_*, test_xdp_veth.c registers xdp_veth_*, ...), and a file
# can hold tests of many objects (verifier.c: one per verifier_* object).
# scripts/affected_tests.py expands each file to the test functions that
# reference this object (or a skeleton it is linked into, under the
# skeleton's name) when that set is certainly complete, else to every
# test the file defines, and to the basename when it defines none. -t is
# a substring match in test_progs, so a name may select tests whose name
# extends it: a superset, never a miss.
DENY=""
if [ "${TESTS[0]}" = "bench:${NAME}" ]; then
    # a bench run has no registered test to expand or deny
    echo "[swap] affected tests: ${TESTS[*]}"
else
    SRCS=()
    for t in "${TESTS[@]}"; do SRCS+=("${SELFTESTS_SRC}/prog_tests/${t}.c"); done
    NAMES="${NAME}"
    for h in ${SKELS[@]+"${SKELS[@]}"}; do
        stem="$(basename "${h}")"; stem="${stem%.lskel.h}"; stem="${stem%.skel.h}"
        [ "${stem}" = "${NAME}" ] || NAMES="${NAMES},${stem}"
    done
    EXPANDED=()
    for n in $(python3 "${HERE}/scripts/affected_tests.py" "${NAMES}" "${SRCS[@]}"); do
        case " ${EXPANDED[*]-} " in *" ${n} "*) ;; *) EXPANDED+=("${n}") ;; esac
    done
    # Subtract tests known to fail with pristine C objects (kernel limits /
    # environment) so bundled always-broken tests can't fail a translation.
    # known-bad-tests: exact test names leave the -t list (an object whose every
    # consumer is denied has no oracle), and every entry - a test name or
    # test/subtest - also goes to test_progs as its -d glob denylist, which
    # matches whole names: a -t name is a substring match and can pull a denied
    # test back in (stack_arg selects verifier_stack_arg).
    DENY_FILE="$(dirname "${BASH_SOURCE[0]}")/known-bad-tests"
    if [ -f "${DENY_FILE}" ]; then
        DENY="$(grep -v '^#' "${DENY_FILE}" | grep -v '^[[:space:]]*$' | paste -sd, -)"
        KEPT=()
        for n in "${EXPANDED[@]}"; do
            grep -qxF "${n}" <(grep -v '^#' "${DENY_FILE}") || KEPT+=("${n}")
        done
        [ "${#KEPT[@]}" -lt "${#EXPANDED[@]}" ] && \
            echo "[swap] denylisted: $(( ${#EXPANDED[@]} - ${#KEPT[@]} )) test(s)"
        EXPANDED=("${KEPT[@]}")
    fi

    TESTS=("${EXPANDED[@]}")
    echo "[swap] affected tests: ${TESTS[*]}"
fi

# SWAP_ONLY=1: install the object and rebuild what derives from it, but do
# not boot the guest (a batch driver restoring the C object between runs).
[ -z "${SWAP_ONLY:-}" ] || { echo "[swap] SWAP_ONLY set — not running"; exit 0; }

FILTER="$(IFS=,; echo "${TESTS[*]}")"
# TEST_RUNNER selects the guest runner. Any runner must accept
# -t <comma-list> and honor TEST_PROGS/SELFTESTS_OUTPUT.
TEST_PROGS="${OUT}/test_progs" \
SELFTESTS_OUTPUT="${OUT}" \
UML_INSTALL_DIR="${UML_INSTALL_DIR:-}" \
    "${TEST_RUNNER}" -t "${FILTER}" ${DENY:+-d "${DENY}"}
