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
# reference the object (see there).
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
        -j"$(nproc)" -k "$@"
}

# Regenerate the skeleton headers derived from this object, if any. Tests
# without skeletons load the .bpf.o from disk at runtime, so the swap alone
# is enough for them.
SKELS=()
for h in "${OUT}/${NAME}.skel.h" "${OUT}/${NAME}.lskel.h"; do
    # A failed skeleton build can remove the header. Its C consumer still
    # requires it on the next swap/restore, so recover from source includes.
    if [ ! -f "${h}" ]; then
        grep -qF "\"$(basename "${h}")\"" "${SELFTESTS_SRC}"/prog_tests/*.c || continue
    fi
    rm -f "${h}"
    SKELS+=("${OUT}//$(basename "${h}")")
done

TESTS=()
if [ "${#SKELS[@]}" -gt 0 ]; then
    sfmake "${SKELS[@]}" > /dev/null

    # Find every test object whose dep file pulls in one of those skeletons.
    for d in $(grep -l -E "(^| |/)${NAME}\.l?skel\.h" "${OUT}"/*.test.d); do
        TESTS+=("$(basename "${d}" .test.d)")
    done
    # The selftests build auto-generates skeletons for every prog; some tests
    # ignore them and load the .bpf.o from disk instead, so an unconsumed
    # skeleton is normal — fall through to runtime discovery.
    if [ "${#TESTS[@]}" -gt 0 ]; then
        # Since bpf-next 645f5fcf the test objects are compiled by a
        # sub-make (Makefile.runner) that the main Makefile's test_progs rule
        # always runs; the .test.d files it includes make it recompile the
        # objects that include a regenerated skeleton, and the relink follows.
        # A *.test.o is no longer a goal the main Makefile knows. PERMISSIVE
        # mode drops an object whose compile failed from the link without
        # failing make, so demand one newer than the skeleton for each test.
        rm -f "${OUT}/test_progs"
        sfmake "${OUT}//test_progs" > /dev/null
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
[ "${#TESTS[@]}" -gt 0 ] || { echo "no prog_tests consume ${NAME}" >&2; exit 1; }

# The names collected above are prog_tests FILE basenames, but the -t
# filter matches REGISTERED test names (the test_<name>() functions).
# They coincide for most files but not all (bpf_verif_scale.c registers
# verif_scale_*, test_xdp_veth.c registers xdp_veth_*, ...), and a file
# can hold tests of many objects (verifier.c: one per verifier_* object).
# scripts/affected_tests.py expands each file to the test functions that
# reference this object when that set is certainly complete, else to every
# test the file defines, and to the basename when it defines none. -t is
# a substring match in test_progs, so a name may select tests whose name
# extends it: a superset, never a miss.
SRCS=()
for t in "${TESTS[@]}"; do SRCS+=("${SELFTESTS_SRC}/prog_tests/${t}.c"); done
EXPANDED=()
for n in $(python3 "${HERE}/scripts/affected_tests.py" "${NAME}" "${SRCS[@]}"); do
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
DENY=""
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
