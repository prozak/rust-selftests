# Tracing environment repair (2026-09-07)

Subsequent [whole-stack validation](ci-nightly-results-2026-09-07.md)
exposed regressions in this regenerated module and stopped at 290/596
runtime rows. The targeted tracing results below remain valid, but the
module generation is not compatible with the whole existing kernel BTF
stack. See the later report before using the recorded zero-failure gate.

The three remaining runtime failures share the `tracing_struct` consumer.
Its struct, many-argument, and union subtests already passed; only
`int128_args` failed, making all three object-swap rows fail.

## Root cause and correction

`bpf_testmod_test_int128_arg(__int128 a, int b, long c)` exists in the
GCC-built module's symbol table and machine code, but pahole v1.31 omits
its FUNC from BTF. Its positional parameter/register analysis treats the
128-bit scalar as one argument slot, so the following arguments appear
to use unexpected registers. The kernel enables `consistent_func`, which
excludes that function from BTF. This is not a Rust translation failure.

The pinned upstream pahole revision
[`416753b4ba90fe3b72952ace9954edb321657936`](https://github.com/acmel/dwarves/commit/416753b4ba90fe3b72952ace9954edb321657936)
accounts for wide arguments with `parameter__abi_slots()` and related
location analysis. This revision had also been independently validated
in the sibling `bpf-uml-selftests` project. We rebuilt it locally from
clean upstream source, including its pinned libbpf submodule, with no
pahole patches.

`pahole-commit` and `scripts/build-qemu-pahole.sh` make that dependency
reproducible in a separate `bld/pahole-<commit>/` prefix. The builder
rejects tracked source edits and reuses an installation only when its
source/recipe identity matches.

`scripts/refresh-qemu-testmod-btf.py` replays the kernel's recorded module
link into a staging directory, then runs the kernel's own `gen-btf.sh`.
It obtains pahole and resolver flags from `scripts/Makefile.btf`, keeping
`consistent_func`, layout, `--fatal_warnings`, and `--distill_base` enabled.
Fresh linking also resets resolved BTF IDs before regeneration. Before
installation, the script requires the int128 FUNC to be present and every
executable section to match the original byte-for-byte. It records source,
tool, kernel BTF, module, and executable-section identities in a manifest.

The QEMU selftests build now selects this tool and explicitly refreshes
the module even when Kbuild considers its compiler/linker inputs current.
For an already prepared output:

```sh
bash scripts/build-qemu-pahole.sh
python3 scripts/refresh-qemu-testmod-btf.py --install
```

Run serially with other builds, proofs, object swaps, and QEMU tests.
No kernel source/configuration, Rust translations, C assertions, or
waivers are changed. The kernel pin remains
`3ccdb07813829ba9487273e75d1cb238cfa774c1`.

## Validation and proof-cache correctness

An isolated module-BTF replacement first made all four C subtests pass.
The final integrated path is validated by serial Rust/C pairs for all
three translations. Executable `.text` and `.static_call.text` hashes
remain identical to the original module. The regenerated module exposes
215 functions versus 212 previously: the int128 target and the two
`bpf_dummy_reg`/`bpf_dummy_unreg` functions are added; none are removed.
The 212 existing function argument/return type shapes are unchanged.

The checker reads module BTF for CO-RE and kfunc signatures, but the guard
previously omitted modules from its toolchain hash. The guard now hashes
each module's name, `.BTF`, and optional `.BTF.base`, including additions
and removals. Unrelated debug-section changes do not invalidate proofs.
This intentionally invalidates the old cached corpus; a fresh proof sweep
is required before accepting the new baseline.

Local evidence is under ignored `nightly/a4-tracing-20260907/`:
`final-module/manifest.json`, `final-runtime/`, `text-sha256.json`,
`module-function-diff.json`, the pinned-tool build/reuse logs, and the
fresh proof and closing CI logs. Initial runs using a full vmlinux base
are retained separately; final runs use the normal distilled module base.

All final Rust/C pairs pass: each consumer reports **1/4 PASSED,
0 SKIPPED, 0/0 FAILED**. The recorded runtime gate is now
**588 PASS / 0 FAIL / 8 NO-ORACLE**. Only the three repaired rows were
refreshed in this step; the other 593 are retained. This is not a repeat
full runtime nightly, and existing skipped assertions in other passing
consumers remain a separate coverage concern.

The fresh eight-worker proof sweep completed all 596 objects with every
verdict unchanged: **417 EQUIV / 120 BAIL / 33 TIMEOUT / 13 UNKNOWN /
13 NOPROGS**, zero INEQUIV. All three tracing translations remain EQUIV.
Every C/Rust object hash is unchanged and matches the refreshed baseline;
all 596 rows now include the module BTF dependency in their tool hash.
All C objects are restored.

Closing `make ci-local` passes **168 tests**, zero lint errors, 127 existing
warnings, and all 596 proof rows cached with no missing objects. A final
staged regeneration, including the kernel-pin check, reproduces the tested
module byte-for-byte. The tool builder and module refresh were exercised
directly; the general selftests build was not repeated. Kernel, harness,
and Rust toolchain source checkouts remain unchanged. Machine-readable
closeout evidence is in `nightly/a4-tracing-20260907/results.json`.

The next validation step is a fresh whole-stack nightly. The eight
NO-ORACLE objects, existing skipped assertions, and incomplete proof
verdicts remain separate coverage work.
