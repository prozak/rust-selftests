# Kernel gap reporting (Phase 4)

Run from `rust-selftests` with Python 3.12+ and Git:

```sh
scripts/kernel-gap.sh /path/to/bpf-next-tip > /tmp/kernel-gap.md
scripts/kernel-gap.sh /path/to/bpf-next-tip --format json > /tmp/kernel-gap.json
```

The base is the exact commit in `kernel-commit`, read from the local x86
kernel repository. The candidate is the supplied checkout's committed
`HEAD`. Uncommitted source edits, untracked files, and build outputs are
ignored. Prefer an unpatched upstream candidate: using a harness branch
will correctly report harness changes too.

The command does not fetch, build, alter refs, change either kernel
checkout, or swap test objects. It archives the relevant committed trees
into a temporary directory, computes the report, and checks the seven
x86 patches there in their original order. Each successful patch is
applied only to that temporary tree before checking the next one. A
failed patch blocks later checks; a successful reverse check is reported
as `already_applied`. Missing inputs are errors, not successful checks.

## Report contents

- Added, removed, and modified top-level `progs/*.c` objects, with local
  `progs/*.rs` overlap and the reasons in `scripts/non-targets.tsv`.
- Base/candidate coverage and translations absent from the candidate.
- Added/removed tag-bearing lines, recognizing macros and wrappers
  defined through `__test_tag` in either version of `bpf_misc.h`.
- Diffs for changed translations, all selftest headers, `test_loader`,
  and C test consumers. JSON also retains every changed object's diff.
- Ordered x86 patch results and SHA-256 hashes of the checked patches.

Tag counts are textual review hints, not a substitute for preprocessing,
compiled BTF checks, or translint. They count changed lines containing a
recognized macro, not individual tags. Multiline argument-only edits and
annotations defined outside `bpf_misc.h` require reviewing the full diff.
Renames appear as removals and additions; no similarity threshold hides
the old translation name. Coverage includes explicitly listed non-targets
in the raw upstream denominator, consistently with the bump analysis.

Exit status: **0** for a complete report with applicable/already-applied
patches, **1** for patch conflicts (the report is still written), **2**
for missing/invalid inputs or operational errors. Source drift itself is
informational and does not fail the command.

Override input locations or reproduce a historical comparison with:

```sh
scripts/kernel-gap.sh /path/to/candidate \
  --base-repo /path/to/repo-containing-the-pin \
  --base-ref 520d7d7942025a58a0c79a61b905a556cf3cb524 \
  --patch-dir /path/to/harness/patches/bpf-selftests-uml
```

The default patch directory is the sibling `uml-harness` repository.
Both resolved commit IDs appear in the report. JSON uses `schema_version: 1`.

## Weekly CI

`.github/workflows/kernel-gap.yml` runs Mondays at 07:23 UTC and supports
manual dispatch. It fetches a depth-1 upstream tip and the recorded pin,
then uploads JSON and Markdown reports, including reports with patch
conflicts. Patch files come from the reviewed harness commit
`7983e26bb213526c768b24170d5a6fb5bb1964a4`; update that workflow pin when
deliberately changing the x86 patch stack.

This is the weekly gap-reporting portion of the CI plan in issue #23.
It does not implement the remaining whole-stack `ci-nightly` build,
equivalence, runtime, and codegen pipeline. It never advances the kernel
pin or opens/posts issues automatically. A bump remains a reviewed
decision based on changed translations, shared contracts, and patch status.

Tests run with `make ci-fast` and cover rename accounting, translation
overlap, newly defined tags, header/loader/consumer changes, ordered patch
dependencies, conflicts and blocked checks, already-applied patches,
missing inputs, CLI exit codes, and preservation of dirty source/index/HEAD.

## Validation on 2026-09-06

The historical comparison from pristine `520d7d794202` to pristine
`3ccdb0781382` reproduces 35 added objects, one removed, 52 modified,
10 modified objects with current translations, and 63 changed C consumers.
All seven x86 patches apply in order. The old pristine tree contains 974
objects; the original plan's 975 counts the extra harness fixture. The
new pristine tree contains 1008 objects.

Comparing `3ccdb0781382` with itself reports no source drift and all seven
patches applicable. Comparing it with the local patched `0f783f853d0e`
tree reports one added fixture, five modified objects, and all seven
patches already applied. These runs left the harness and kernel checkout
clean.

`make ci-local` passes: 108 tests, zero lint errors (127 existing warnings),
and 596 current cached proof rows with zero missing objects. Workflow YAML
and its embedded shell blocks pass local syntax checks. The GitHub-hosted
scheduled job has not been run as part of this local validation.
