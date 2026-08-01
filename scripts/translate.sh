#!/bin/bash
# translate.sh <prog-name> [max-attempts]
#
# Heimdall-style automated translation loop. Hands the C selftest program
# to a headless Claude Code agent (claude -p) armed with TRANSLATING.md and
# the existing verified translations, then independently re-runs the
# deterministic gates:
#
#   1. compile         make bld/<name>.bpf.o
#   2. kernel verifier / oracle   make test-<name>  (swap into selftests
#      output, kernel-Makefile skeleton regen, affected test_progs tests
#      run verbatim in UML — failures at load time are verifier failures,
#      failures at run time are behavioral divergence)
#
# The agent is allowed and expected to run the same gates itself and
# iterate; the outer loop is the trust-but-verify controller: if the gates
# do not pass after the agent finishes, it is re-invoked with the failing
# gate output, up to max-attempts times.
#
# Env: MODEL (optional claude model override), CLAUDE_BIN (default claude)

set -uo pipefail

NAME="$1"
MAX_ATTEMPTS="${2:-3}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLAUDE_BIN="${CLAUDE_BIN:-claude}"

cd "${REPO}"

KERNEL_SRC="${KERNEL_SRC:-$(make -s -f /dev/stdin <<'EOF'
include Makefile
print-kernel:
	@echo $(KERNEL_SRC)
EOF
print-kernel 2>/dev/null || true)}"
[ -n "${KERNEL_SRC}" ] || { echo "cannot resolve KERNEL_SRC" >&2; exit 1; }
CSRC="${KERNEL_SRC}/tools/testing/selftests/bpf/progs/${NAME}.c"
[ -f "${CSRC}" ] || { echo "no such selftest program: ${CSRC}" >&2; exit 1; }

LOG="bld/translate-${NAME}.log"
mkdir -p bld
: > "${LOG}"

gate() {
    # Returns 0 iff the full pipeline passes; gate output goes to $GATE_OUT
    GATE_OUT="bld/gate-${NAME}.log"
    {
        make "$(pwd)/bld/${NAME}.bpf.o" && make "test-${NAME}"
    } > "${GATE_OUT}" 2>&1
    local rc=$?
    if [ ${rc} -eq 0 ] && grep -qE "0 FAILED" "${GATE_OUT}" \
        && grep -qE "Summary: [1-9][0-9]* PASSED" "${GATE_OUT}"; then
        return 0
    fi
    return 1
}

PROMPT_BASE="You are working in the rust-selftests repo at ${REPO}.

Task: translate the kernel BPF selftest program ${CSRC}
into Rust at progs/${NAME}.rs.

Read, in this order, before writing any code:
1. TRANSLATING.md — the translation rules; follow them exactly.
2. The C source above, and every userspace test that consumes it
   (grep for '${NAME}' under
   ${KERNEL_SRC}/tools/testing/selftests/bpf/prog_tests/)
   — the userspace tests define the contract your translation must satisfy.
3. The existing verified translations in progs/*.rs as reference idiom.

Then iterate until done:
- 'make' must compile your translation to bld/${NAME}.bpf.o
- 'make test-${NAME}' swaps your object into the selftests build and runs
  every affected test_progs test in a UML kernel. It must end with
  '0 FAILED' and a nonzero PASSED count. Load failures in its output are
  kernel-verifier rejections; test FAILs are behavioral divergence from
  the C original — read the log, fix progs/${NAME}.rs, re-run.

Hard rules:
- Only create/modify progs/${NAME}.rs. Never modify the C sources, the
  Makefile, scripts/, TRANSLATING.md, other translations, or anything in
  the kernel tree.
- Do not run 'make restore-*' or git commands.
- When 'make test-${NAME}' passes, print TRANSLATION-OK as your last line.
  If you conclude you cannot make it pass, print TRANSLATION-FAIL and a
  one-paragraph reason."

ATTEMPT=1
EXTRA=""
while [ ${ATTEMPT} -le ${MAX_ATTEMPTS} ]; do
    echo "=== attempt ${ATTEMPT}/${MAX_ATTEMPTS} for ${NAME} ===" | tee -a "${LOG}"
    ${CLAUDE_BIN} -p "${PROMPT_BASE}${EXTRA}" \
        --allowedTools "Bash,Read,Write,Edit,Glob,Grep" \
        ${MODEL:+--model "${MODEL}"} \
        2>&1 | tee -a "${LOG}"

    if gate; then
        echo "=== ${NAME}: ALL GATES PASS (attempt ${ATTEMPT}) ===" | tee -a "${LOG}"
        tail -n 20 "${GATE_OUT}" | grep -E "affected tests|#[0-9]+ |Summary" || true
        exit 0
    fi

    echo "=== ${NAME}: gates failed after attempt ${ATTEMPT} ===" | tee -a "${LOG}"
    EXTRA="

Your previous attempt exists at progs/${NAME}.rs but the independent gate
run failed. Failing gate output (tail):
$(tail -n 60 "${GATE_OUT}")
Fix the translation and try again."
    ATTEMPT=$((ATTEMPT + 1))
done

echo "=== ${NAME}: FAILED after ${MAX_ATTEMPTS} attempts ===" | tee -a "${LOG}"
exit 1
