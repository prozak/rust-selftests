#!/bin/bash
# swap-and-test.sh <prog-name> <rust|c>
#
# Install either the Rust translation (bld/<name>.bpf.o) or the pristine C
# object (<name>.bpf.o.corig) as <name>.bpf.o in the selftests output, then
# drive the KERNEL'S OWN selftests Makefile to regenerate every skeleton and
# test object derived from it, relink test_progs, and run the affected tests
# inside the UML guest. The prog_tests harness is reused verbatim.
#
# The set of affected tests is discovered from the generated *.test.d
# dependency files (which record skeleton-header inclusion), so prog-name /
# test-name mismatches are handled without any hardcoded mapping.
#
# Expects env (exported by the Makefile): KERNEL_SRC SELFTESTS_SRC
# SELFTESTS_OUTPUT LLVM_PREFIX UML_HARNESS UML_INSTALL_DIR

set -euo pipefail

NAME="$1"
WHICH="${2:-rust}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${KERNEL_SRC:?}" "${SELFTESTS_SRC:?}" "${SELFTESTS_OUTPUT:?}"
: "${LLVM_PREFIX:?}" "${UML_HARNESS:?}" "${UML_INSTALL_DIR:?}"

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

# The selftests make invocation, mirroring bpf-uml-selftests build.sh.
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
        VMLINUX_BTF="${KERNEL_SRC}/linux" \
        ARCH=x86_64 TEST_KMODS= SKIP_LLVM=1 \
        EXTRA_BPF_CFLAGS=-D__UML_PT_REGS__ BPF_STRICT_BUILD=0 \
        -j"$(nproc)" -k "$@"
}

# Regenerate the skeleton headers derived from this object, if any. Tests
# without skeletons load the .bpf.o from disk at runtime, so the swap alone
# is enough for them.
SKELS=()
for h in "${OUT}/${NAME}.skel.h" "${OUT}/${NAME}.lskel.h"; do
    [ -f "${h}" ] || continue
    rm -f "${h}"
    SKELS+=("${OUT}//$(basename "${h}")")
done

TESTS=()
if [ "${#SKELS[@]}" -gt 0 ]; then
    sfmake "${SKELS[@]}" > /dev/null

    # Find every test object whose dep file pulls in one of those skeletons,
    # rebuild each explicitly (PERMISSIVE mode silently drops deleted test
    # objects from the link, so each must be named as a goal), then relink.
    for d in $(grep -l -E "(^| |/)${NAME}\.l?skel\.h" "${OUT}"/*.test.d); do
        base="$(basename "${d}" .test.d)"
        TESTS+=("${base}")
        rm -f "${OUT}/${base}.test.o"
        sfmake "${OUT}//${base}.test.o" > /dev/null
        [ -f "${OUT}/${base}.test.o" ] || { echo "failed to rebuild ${base}.test.o" >&2; exit 1; }
    done
    [ "${#TESTS[@]}" -gt 0 ] || { echo "skeletons exist but no prog_tests consume them?" >&2; exit 1; }

    rm -f "${OUT}/test_progs"
    sfmake "${OUT}//test_progs" > /dev/null
    [ -x "${OUT}/test_progs" ] || { echo "test_progs relink failed" >&2; exit 1; }
    echo "[swap] test_progs relinked"
fi

# Tests may also reference the object file by name and load it at runtime
# (no skeleton involved); those need no rebuild, just the swapped file.
for f in $(grep -l -E "\"[^\"]*${NAME}\.bpf\.o\"" "${SELFTESTS_SRC}"/prog_tests/*.c); do
    base="$(basename "${f}" .c)"
    case " ${TESTS[*]-} " in *" ${base} "*) ;; *) TESTS+=("${base}") ;; esac
done
[ "${#TESTS[@]}" -gt 0 ] || { echo "no prog_tests consume ${NAME}" >&2; exit 1; }
echo "[swap] affected tests: ${TESTS[*]}"

FILTER="$(IFS=,; echo "${TESTS[*]}")"
TEST_PROGS="${OUT}/test_progs" \
SELFTESTS_OUTPUT="${OUT}" \
UML_INSTALL_DIR="${UML_INSTALL_DIR}" \
    "${UML_HARNESS}/uml-test-progs" -t "${FILTER}"
