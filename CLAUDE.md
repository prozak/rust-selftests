# rust-selftests: what every session needs to know

Rust translations of the kernel's BPF selftest programs (`progs/<name>.rs` for
`tools/testing/selftests/bpf/progs/<name>.c`), each checked two ways: the QEMU
gate runs the upstream prog_tests consumer against the Rust object in place of
the C one, and the Z3 prover compares the two objects program by program.
README.md "Start here" / "Status", TRANSLATING.md (idioms, markers, lints) and
docs/ (gate-runtime, ci-nightly, maintainer) are the long form; this file is
the part that was being re-derived at the start of every session.

## Session protocol (user's standing rules)

1. Read the memory index and the ONE resume prompt file in
   `~/sources/heimdall_experiment/next-session-prompt-*.md`; `git status -sb`,
   push first if "ahead".
2. Before any other tool call print the task in simple words (what, why, what
   done looks like; no paths, no jargon), then `EnterPlanMode`. The plan file
   opens with an "## In simple words" section; implement only after approval.
3. Commit locally as work lands; ONE `git push` of all commits at session end
   (the permission prompt is the approval). Then update memory
   (`~/.claude/projects/-home-prozak-sources-heimdall-experiment/memory/`),
   write the next resume prompt and delete the previous one.
4. Report progress every ~5 minutes during long runs. Add follow-up tasks to
   the GitHub issues yourself; never say interactive work cost "$0".

## Where things are

| thing | path |
|---|---|
| C sources, prog_tests consumers | `.build/bpf-next/tools/testing/selftests/bpf/{progs,prog_tests}` |
| C objects + built selftests (the oracle's tree) | `.build/selftests-output-qemu/` (`SELFTESTS_OUTPUT`); kernel pin in `kernel-commit` |
| LLVM 23 (llc/opt), bpftool | `.build/llvm/bin/`, `.build/bpftool-output-qemu/bpftool` |
| rust-bpf (add_ksyms.py, btf crate) | `../rust-bpf` (`RUSTBPF`) |
| built Rust objects | `bld/<name>.bpf.o` |
| gate baseline / logs | `qemu/gate/baseline.tsv` (name, rust_md5, c_md5, env_md5, verdict PASS/FAIL/NO-ORACLE, seconds, test_progs summary), `qemu/gate/logs/<name>.log` (Rust) and `<name>.c.log` (C re-check) |
| prover baseline / waivers | `equiv/results/baseline.tsv`, `equiv/waivers.tsv` (in the toolchain hash: adding a waiver = full re-sweep) |
| gate denylist / extra consumers | `scripts/known-bad-tests`, `scripts/extra-consumers` |
| roadmap and pools | issue #31 (latest dated comment), #32 negatives, #45 CO-RE kinds, #73 bench oracle, #71/#28/#13 prover bails, #62 tool, #63 real-world |

## Per-object rhythm

```sh
make $PWD/bld/<name>.bpf.o                          # absolute target; prints each BTF post-pass
python3 scripts/translint.py <name>                 # mechanical lints; test-tags class = C object's BTF is ground truth
.venv/bin/python scripts/gate.py --workers 8 <names>   # QEMU gate, per name, ~12 s a batch; writes baseline rows
.venv/bin/python equiv/guard.py --jobs 8 <names>     # prover (positives only; negatives never load)
.venv/bin/python equiv/check.py <name>               # one object's bail reason / proof detail
make ci-fast                                         # hermetic: pytest equiv/tests, compileall, SEMANTICS.md freshness
```

Survey of what is untranslated: `progs/*.c` in the C tree minus `progs/*.rs`,
minus `scripts/non-targets.tsv`; `__failure` count marks a negative object.
`make test-<name>` swaps one object into the shared tree (always `make
restore-all`, then `make restore-<name>` to relink); `gate.py` uses private
per-worker overlays instead and needs no restore.

## Markers the build reads from the .rs (details in TRANSLATING.md)

`// BTF_KSYM: name` (mirror the C's kfunc/ksym proto), `// BTF_KCONFIG: NAME`,
`// BTF_EXTERN: name` (cross-object extern), `// BTF_C_MEMBERS: struct`,
`// BTF_ANON: Type`, `// BTF_C_VOID: c_void`, `// BTF_C_CHAR: u8`,
`// BTF_FWD: S` (incomplete type from an `extern type`), `// BTF_FN_PTR:
struct.member = fn`, `// BTF_TYPE_ID:`, `// BPF_NAKED: fn`, `// BPF_PROGRAM_ORDER:`,
`// C_LAYOUT: .data .bss`, `// BTF_WEAK_KFUNC: name`, `// translint: allow(class)`
plus reason. Test-loader expectations: `test_tags! { prog: __failure, __msg("...") }`
copied from the C, relaxing only register/`fp-`/`off=`/insn tokens with `{{regex}}`.

## Standing constraints

- QEMU is the only oracle (`FLAVOR=uml` only when asked). `.venv/bin/python`
  for gate and prover. Never touch `~/sources/bpf-uml-selftests`.
- Gate environment files (editing any = full re-gate, ~10 min, 8 guests):
  `scripts/swap-and-test.sh`, `affected_tests.py`, `qemu-test-progs`,
  `gate-overlay.sh`, `gate-record-filter`, `gate-guest-loop`, `known-bad-tests`,
  `gate-serial`, `extra-consumers`. Never edit them, `equiv/*.py` or
  `waivers.tsv` while a gate or guard runs; `equiv/bpfcore.py` is in the prover
  hash (never edit it for a non-prover reason).
- Never `guard.py --all` while a gate runs; the prover reads the C objects from
  `SELFTESTS_OUTPUT`, so never run it while a swap is installed (bench scripts
  install one). No CPU-heavy work during a timed (full) gate. Sweeps at `-P 8`;
  more fabricates TIMEOUTs.
- No bare `git stash`. Commit locally, one batch push at session end.
- `grep` in this shell is ugrep with `--ignore-files`/`-I`: it skips `.build/`,
  `qemu/gate/logs` and "binary" files silently; use `command grep`.
- `pkill -f <pattern>` kills the calling shell when the pattern is in its own
  command line. A vng guest run from a background shell needs `< /dev/null`,
  stdout piped (`| cat > log`, vng's relay writes from offset 0 over the console
  log), and a guest-side script file beyond ~1.5 KB of command (2048-byte
  kernel command line).

## Machine

WSL2, 32 CPUs, 23 GB RAM, ~600 GB free on `/`. `gate.py --workers` caps at 8
(one KVM guest each); `guard.py --jobs 8`. Full gate ~10 min, full prover sweep
hours (run only when the toolchain hash changes). Check-ins while runs go:
`tail` the run's own log, never the whole console.
