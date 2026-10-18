# rust-selftests

The Linux kernel's BPF selftest programs, translated from C to Rust and run
through the kernel's own test harness.

Each `progs/<name>.rs` here is a translation of
[`tools/testing/selftests/bpf/progs/<name>.c`](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/progs?id=645f5fcf7a5582f5d6ed2322f41cb34076c63b2c)
in bpf-next. The Rust is compiled straight to a BPF object by rustc and
LLVM, using the [4ast/rust-bpf](https://github.com/4ast/rust-bpf) pipeline:
no aya, no bpf-linker, no libbpf-rs. The object is then dropped in place of
the one clang built from the C file, and the kernel's unmodified tests decide
whether it is good.

610 of the 1,008 programs in the kernel tree are translated. In the last
full run (2026-10-16), 602 of them pass the kernel's tests with the Rust
object in place; [Status](#status) has the rest.

## What "passes" means

The kernel tests each BPF program with a userspace test in
`prog_tests/*.c`, linked into one binary, `test_progs`. That test opens the
object through a generated skeleton, loads it (so the in-kernel verifier
must accept it), attaches it, triggers it and checks what it did.

For a translation, this repo:

1. builds `bld/<name>.bpf.o` from `progs/<name>.rs`;
2. installs it as `<name>.bpf.o` in a build of the kernel selftests, and
   lets the kernel's own Makefile regenerate the skeletons and relink
   `test_progs`;
3. boots a QEMU guest running bpf-next at the commit in
   [`kernel-commit`](kernel-commit) and runs every `prog_tests` test that
   uses the object.

**PASS** means those tests report zero failures with the Rust object in
place. The tests, the skeleton generator, libbpf and the kernel are
unmodified bpf-next: no patches are
applied ([`patches/kernel/`](patches/kernel) is empty). A passing test can still skip
subtests, and a test that exercises several objects runs the others from C.
**NO-ORACLE** means no `prog_tests` test uses the object, so nothing ran.

The kernel is pinned, not tracking: `645f5fcf7a55` is bpf-next as of
2026-10-16.

## Start here

Read one translation next to its original. A short one with maps,
read-only globals and a `bpf_loop` callback:

- C: [`progs/test_map_lookup_percpu_elem.c`](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/progs/test_map_lookup_percpu_elem.c?id=645f5fcf7a5582f5d6ed2322f41cb34076c63b2c)
- Rust: [`progs/test_map_lookup_percpu_elem.rs`](progs/test_map_lookup_percpu_elem.rs)
- the test that judges both: [`prog_tests/map_lookup_percpu_elem.c`](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/prog_tests/map_lookup_percpu_elem.c?id=645f5fcf7a5582f5d6ed2322f41cb34076c63b2c)

A map definition in C,

```c
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} percpu_array_map SEC(".maps");
```

becomes

```rust
#[link_section = ".maps"]
#[no_mangle]
static percpu_array_map: BpfMap<u32, u64, { maps::PERCPU_ARRAY }, 1> = BpfMap::new();
```

and a program is an `extern "C" fn` placed in the section libbpf expects:

```rust
#[link_section = "tp/syscalls/sys_enter_getuid"]
#[no_mangle]
extern "C" fn sysenter_getuid(_ctx: *const c_void) -> i32 { ... }
```

[TRANSLATING.md](TRANSLATING.md) is the full set of rules: how each C
construct is written in Rust, and the mistakes that the tools below caught.

## How an object is built

`make` runs, for each `progs/<name>.rs`:

```
rustc --emit=llvm-bc  ->  llvm-link (+ libcore/liballoc)  ->  bpf-postproc
  ->  opt (internalize + O2)  ->  add_ksyms.py  ->  llc -mcpu=v4
```

The pipeline, the target description, the `#[btf]` macro and `bpf-postproc`
come from rust-bpf. This repo adds:

| | |
|---|---|
| [`bpf-rs-core/`](bpf-rs-core) | support crate the translations use: map types, helper and kfunc wrappers, context types, section macros |
| [`scripts/btf_*.py`](scripts) and friends | post-link fixes that make the object's BTF and symbols match what the C object exposes to the harness |
| [`equiv/`](equiv) | a checker that symbolically executes the C-built and Rust-built objects and asks Z3 whether anything observable can differ |
| [`codegen/`](codegen) | a comparison of what rustc and clang emit for the proved-equivalent pairs |
| [`collections/`](collections) | Rust `alloc` collections running in BPF on an arena allocator |
| [`scripts/translint.py`](scripts/translint.py) | a linter for known translation mistakes |
| [`scripts/naked_gen.py`](scripts/naked_gen.py) | generates the translation of a `verifier_*` selftest written as `__naked` BPF asm, verbatim |

The prover and the runtime gate catch different bugs, and neither replaces
the other. The prover compares program behaviour and has found integer
narrowing mistakes that every test passed over; it cannot see an object's
BTF, symbols or section order, which is where the runtime gate has found
its own.

## Status

From `make ci-nightly` on 2026-10-17 (`nightly/20261017-verifier-sweep`,
the sources of commit 88992f1, the end of the verifier sweep) on bpf-next
`645f5fcf7a55` with no patches, pahole v1.32, LLVM 23.1.4 (release/23.x
plus `patches/llvm/`) and rustc 1.99.1. The per-object tables are
[`qemu/gate/baseline.tsv`](qemu/gate/baseline.tsv) and
[`equiv/results/baseline.tsv`](equiv/results/baseline.tsv).

**Runtime gate** (776 objects, eight 4-CPU KVM guests at a time, 44 minutes):

| | objects |
|---|---:|
| PASS | 766 |
| FAIL | 0 |
| NO-ORACLE | 10 |

The ten NO-ORACLE objects have no `prog_tests` consumer, or only one listed
in [`scripts/known-bad-tests`](scripts/known-bad-tests) (`fs_kfuncs`, whose
xattr subtests fail with the C objects on this virtiofs root). Three more
entries there name tests that fail with the pristine C objects of a clang 23
build at this pin (`verifier_stack_arg`, a `stack_arg_precision` subtest, an
`exceptions` subtest); the list also reaches test_progs as its `-d`
denylist.

**Proof sweep** (same 776 objects, 180 s each, 26 minutes at eight jobs):

| | objects |
|---|---:|
| EQUIV — every program proved equivalent to its C original | 505 |
| BAIL — some program met something the checker does not model | 191 |
| TIMEOUT | 49 |
| UNKNOWN | 16 |
| NOPROGS — the object has no programs | 13 |
| INEQUIV | 1 |
| ERROR | 1 |

Counted by program rather than by object, 3197 of the 4087 programs in the
EQUIV and BAIL rows are proved.

**The verifier sweep** (#25, #27; 2026-10-17) is what this run adds: 140 of
the 143 `verifier_*.c` files, 138 objects more than the LLVM 23 run. The
naked asm programs, some 2200 functions, are generated verbatim from the C
source and the C object by `scripts/naked_gen.py`, and translint's
`naked-verbatim` class compares them with the C object instruction by
instruction; the 211 C bodies are translated by hand in `progs/hand/`.
All 140 objects PASS the gate. The checker proves 60 of them whole and
1675 of their 2101 programs; the 69 BAIL objects are partial proofs (the
rest of their programs use helpers, kfuncs, stack arguments or expected
rejections it does not model), 10 time out, and `verifier_arena_scalar` is
the ERROR: a Z3 type error in the checker's atomic model, a checker defect
still to fix. No verdict of the 638 earlier objects changed. Left out:
`verifier_aggregate_arg` and `verifier_aggregate_ret` (rustc's BPF C ABI
passes aggregates indirectly where clang flattens them into registers) and
`verifier_bitfield_write` (a CO-RE bitfield relocation needs bitfield
members in the object's own BTF, which Rust cannot define).
[docs/history/verifier-sweep-2026-10-17.md](docs/history/verifier-sweep-2026-10-17.md)
describes the generator and what the hand translations taught.

The run before it, `nightly/20261017-llvm23`, was the first on LLVM 23;
[docs/history/llvm23-move-2026-10-17.md](docs/history/llvm23-move-2026-10-17.md)
has what the move broke and how each piece was fixed.

The INEQUIV is `cpumask_success`. Its kfuncs return `bool`, and on x86-64
only the low byte of that return is defined. clang masks the result to one
bit; rustc marks the return as already zero-extended, so the Rust object
tests the whole register. That is a defect in how the object is built, not
in the checker. Its runtime test passes: most of the kfuncs involved
return clean values on the test machine, and the two that were seen not to
are not called directly (the source says where). The kernel's
`bpf_list_empty()` does not return a clean value, so `refcounted_kptr.rs`
masks its three list predicates by hand (its header explains). Until the
build masks these returns, `make ci-local` fails on this object.

## Reproducing it

You need an x86_64 Linux host with KVM (`/dev/kvm` readable and writable
by you; the test runner refuses to start otherwise), about
30 GB of disk and 16 GB of memory (the kernel link peaks at 7.4 GB). Everything below was measured on
a 32-thread machine running Ubuntu 24.04 with gcc 13.3.

Host tools: the usual kernel build dependencies (gcc, make, flex, bison,
bc, libelf, libssl, cmake for pahole), `qemu-system-x86_64`,
[virtme-ng](https://github.com/arighi/virtme-ng) 1.41, Rust 1.99.1 with the
`rust-src` component (`rust-toolchain.toml` pins it; rustup installs it on
first use), cmake and ninja for LLVM, Python 3.12.

```sh
git clone --recurse-submodules https://github.com/prozak/rust-selftests
git clone https://github.com/4ast/rust-bpf            # next to it
git -C rust-bpf fetch origin pull/6/head              # #[btf_tag], not merged yet
git -C rust-bpf checkout FETCH_HEAD
cd rust-selftests

scripts/build-llvm.sh             # LLVM release/23.x + patches/llvm/ -> .build/llvm  (40 min on 32 CPUs, 2 GB)
scripts/build-qemu-kernel.sh      # bpf-next at kernel-commit -> .build/bpf-next   (300 MB fetch, 4 min, 9 GB)
scripts/build-qemu-selftests.sh   # kernel selftests -> .build/selftests-output-qemu  (1 min, 1.3 GB)
```

The LLVM is built from source because the translations need a BPF backend
fix the release tarballs do not carry yet (`patches/llvm/`, issue #49);
`scripts/fetch-llvm.sh` installs a release tarball instead once they do.

Build rust-bpf's support libraries with the same LLVM and the same rustc
(its Makefile defaults to nightly; run this from `rust-selftests/` so the
toolchain file resolves `rustc`):

```sh
make -C ../rust-bpf \
  LLVM_PREFIX=$PWD/.build/llvm \
  RUSTC=$(rustup which rustc) \
  RUST_SRC=$(rustc --print sysroot)/lib/rustlib/src/rust/library
```

Tested with rust-bpf at `1dc4bb7` plus pull request #6 (`3e35246`), which
adds the `#[btf_tag]` decl tags the translations use (that exact tree is
[prozak/rust-bpf `pr6-on-master`](https://github.com/prozak/rust-bpf/tree/pr6-on-master));
`make` stops with a
message if the checkout lacks the PR's `btf_tags.py`. A checkout elsewhere
than `../rust-bpf` is passed as `make RUSTBPF=/path/to/rust-bpf`.

Then:

```sh
make -j8                                  # all objects -> bld/      (about 1 min)
make test-test_map_lookup_percpu_elem     # one translation, in QEMU (about 20 s)
make restore-all                          # put the C objects back
make gate                                 # every translation whose inputs changed, in QEMU
```

`make test-<name>` leaves the Rust object installed; `make restore-all`
undoes every swap. `make gate` re-runs the translations whose Rust object,
C object or gate environment differ from the committed
[`qemu/gate/baseline.tsv`](qemu/gate/baseline.tsv), eight guests at a time
over private overlays of the selftests output, and restores the C objects
itself; with nothing changed it finishes in seconds. `make ci-local` runs
it after the proof guard. The whole corpus afresh, with the proof sweep,
is `make ci-nightly` (see [docs/ci-nightly.md](docs/ci-nightly.md)); its
gate took 31 minutes in the 2026-10-16 run with eight guests (58 minutes
with four, 3 hours 27 minutes with one).
It needs `pip install -r requirements.txt`, into `.venv/` if you want
`make` to find it by itself.

All paths default to `.build/` inside the checkout and can be moved with
`BUILD_DIR`, or one by one (`KERNEL_SRC`, `SELFTESTS_OUTPUT`, `LLVM_PREFIX`,
`RUSTBPF`, `VNG`). [docs/maintainer.md](docs/maintainer.md) covers running
subsets, the parallel gate, reading results and recovering a drifted output
directory.

## Layout

| | |
|---|---|
| `progs/` | the translations, one per kernel `progs/*.c` |
| `kernel-commit`, `pahole-commit` | the pinned bpf-next and pahole revisions |
| `kernel/config-x86_64` | the guest kernel's configuration |
| `patches/kernel/` | patches applied to the pinned kernel before building: none are needed |
| `qemu/gate/baseline.tsv` | the recorded runtime verdict of every translation |
| `equiv/results/baseline.tsv` | the recorded proof verdict of every translation |
| `docs/` | the nightly and kernel-gap guides, the maintainer guide; dated reports under `docs/history/` |

## License

GPL-2.0-only, as the kernel selftests these programs are translated from;
see [LICENSE](LICENSE). Each `progs/*.rs` carries the SPDX identifier of its
C original, so the few dual-licensed originals stay dual-licensed.
`collections/vendor/libarena-rs` is a submodule under its own license.
