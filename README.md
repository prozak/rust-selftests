# rust-selftests

The Linux kernel's BPF selftest programs, translated from C to Rust and run
through the kernel's own test harness.

Each `progs/<name>.rs` here is a translation of
[`tools/testing/selftests/bpf/progs/<name>.c`](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/progs?id=3ccdb07813829ba9487273e75d1cb238cfa774c1)
in bpf-next. The Rust is compiled straight to a BPF object by rustc and
LLVM, using the [4ast/rust-bpf](https://github.com/4ast/rust-bpf) pipeline:
no aya, no bpf-linker, no libbpf-rs. The object is then dropped in place of
the one clang built from the C file, and the kernel's unmodified tests decide
whether it is good.

596 of the 1,008 programs in the kernel tree are translated. In the last
full run (2026-10-10), 584 of them pass the kernel's tests with the Rust
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

The kernel is pinned, not tracking: `3ccdb0781382` is bpf-next as of
2026-09-04.

## Start here

Read one translation next to its original. A short one with maps,
read-only globals and a `bpf_loop` callback:

- C: [`progs/test_map_lookup_percpu_elem.c`](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/progs/test_map_lookup_percpu_elem.c?id=3ccdb07813829ba9487273e75d1cb238cfa774c1)
- Rust: [`progs/test_map_lookup_percpu_elem.rs`](progs/test_map_lookup_percpu_elem.rs)
- the test that judges both: [`prog_tests/map_lookup_percpu_elem.c`](https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/prog_tests/map_lookup_percpu_elem.c?id=3ccdb07813829ba9487273e75d1cb238cfa774c1)

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

The prover and the runtime gate catch different bugs, and neither replaces
the other. The prover compares program behaviour and has found integer
narrowing mistakes that every test passed over; it cannot see an object's
BTF, symbols or section order, which is where the runtime gate has found
its own.

## Status

From `make ci-nightly` on 2026-10-10 (the sources of commit `1985958`), on bpf-next
`3ccdb0781382` with no patches, plus the re-runs listed below. The
per-object tables are [`qemu/gate/results.md`](qemu/gate/results.md) and
[`equiv/results/baseline.tsv`](equiv/results/baseline.tsv).

**Runtime gate** (596 objects, serial, 4-CPU guest):

| | objects |
|---|---:|
| PASS | 584 |
| FAIL, and the C object fails the same way | 4 |
| NO-ORACLE | 8 |

The run itself ended at 581 PASS / 7 FAIL. Three of the seven were re-run
the next day and pass:

- `get_branch_snapshot`, `get_smp_processor_id`: the guest kernel
  panicked 1.8 s into boot, before the test started. Both pass on a second
  boot.
- `test_tc_tunnel`: the translation carried a kernel BTF id that the
  rebuilt kernel no longer used. It now emits the relocation the C object
  has (`3296ed8`) and passes.

The other four fail with the unmodified C objects too, on this host, on
that day: `test_tc_edt` misses a rate-accuracy threshold, and the three
`tracing_multi_*` objects share a test whose attach of 64,321 functions
takes about 146 s against a 120 s watchdog. All four passed in September
on the same host. They are timing, not translation.

60 of the passing rows include skipped subtests.

**Proof sweep** (same 596 objects, 180 s each):

| | objects |
|---|---:|
| EQUIV — every program proved equivalent to its C original | 417 |
| BAIL — the checker met something it does not model | 120 |
| TIMEOUT | 32 |
| UNKNOWN | 13 |
| NOPROGS — the object has no programs | 13 |
| INEQUIV | 1 |

The INEQUIV is `cpumask_success`: C masks the return of
`bpf_cpumask_empty()` to one bit and the Rust tests all 32. Whether that
is a translation bug or a gap in how the checker models kfunc returns is
open; its runtime test passes. Until it is settled `make ci-local` fails
on it.

## Reproducing it

You need an x86_64 Linux host with KVM (`/dev/kvm` readable by you), about
30 GB of disk and 16 GB of memory (the kernel link peaks at 7.4 GB). Everything below was measured on
a 32-thread machine running Ubuntu 24.04 with gcc 13.3.

Host tools: the usual kernel build dependencies (gcc, make, flex, bison,
bc, libelf, libssl, cmake for pahole), `qemu-system-x86_64`,
[virtme-ng](https://github.com/arighi/virtme-ng) 1.41, Rust stable with the
`rust-src` component (1.96.1 here), Python 3.12.

```sh
git clone --recurse-submodules https://github.com/prozak/rust-selftests
git clone https://github.com/4ast/rust-bpf            # next to it
cd rust-selftests

scripts/fetch-llvm.sh             # LLVM 22.1.8 release -> .build/llvm       (1.9 GB download, 12 GB unpacked)
scripts/build-qemu-kernel.sh      # bpf-next at kernel-commit -> .build/bpf-next   (300 MB fetch, 4 min, 9 GB)
scripts/build-qemu-selftests.sh   # kernel selftests -> .build/selftests-output-qemu  (1 min, 1.3 GB)
```

Build rust-bpf's support libraries with the same LLVM and a stable rustc
(its Makefile defaults to nightly):

```sh
make -C ../rust-bpf \
  LLVM_PREFIX=$PWD/.build/llvm \
  RUSTC=$(rustup which --toolchain stable rustc) \
  RUST_SRC=$(rustc +stable --print sysroot)/lib/rustlib/src/rust/library
```

Tested with rust-bpf at `c130551`.

Then:

```sh
make -j8                                  # all objects -> bld/      (about 1 min)
make test-test_map_lookup_percpu_elem     # one translation, in QEMU (about 20 s)
make restore-all                          # put the C objects back
```

`make test-<name>` leaves the Rust object installed; `make restore-all`
undoes every swap. The whole corpus, with the proof sweep, is
`make ci-nightly` (8 hours here on 2026-10-10, nearly all of it the serial runtime gate; see [docs/ci-nightly.md](docs/ci-nightly.md)).
It needs `pip install -r requirements.txt`, into `.venv/` if you want
`make` to find it by itself.

All paths default to `.build/` inside the checkout and can be moved with
`BUILD_DIR`, or one by one (`KERNEL_SRC`, `SELFTESTS_OUTPUT`, `LLVM_PREFIX`,
`RUSTBPF`, `VNG`). [docs/maintainer.md](docs/maintainer.md) covers running
subsets, parallel lanes, reading results and recovering a drifted output
directory.

## Layout

| | |
|---|---|
| `progs/` | the translations, one per kernel `progs/*.c` |
| `kernel-commit`, `pahole-commit` | the pinned bpf-next and pahole revisions |
| `kernel/config-x86_64` | the guest kernel's configuration |
| `patches/kernel/` | patches applied to the pinned kernel before building: none are needed |
| `qemu/gate/results.md` | the recorded runtime verdict of every translation |
| `equiv/results/baseline.tsv` | the recorded proof verdict of every translation |
| `docs/` | the nightly and kernel-gap guides, the maintainer guide; dated reports under `docs/history/` |

## License

GPL-2.0-only, as the kernel selftests these programs are translated from;
see [LICENSE](LICENSE). Each `progs/*.rs` carries the SPDX identifier of its
C original, so the few dual-licensed originals stay dual-licensed.
`collections/vendor/libarena-rs` is a submodule under its own license.
