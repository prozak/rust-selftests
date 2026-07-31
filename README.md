# rust-selftests — Rust translations of the kernel BPF selftests

Rust translations of `tools/testing/selftests/bpf/progs/*.c`, compiled
**directly to BPF by upstream rustc/LLVM** (the
[4ast/rust-bpf](https://github.com/4ast/rust-bpf) pipeline — no aya, no
bpf-linker), and validated against the kernel's **unmodified** selftests
harness: the real `prog_tests/*.c`, the real skeleton generation, the real
`test_progs`, running in a UML bpf-next kernel.

## Structure

This repo mirrors the kernel selftests directory: for each translated
program `progs/<name>.c` in the kernel tree there is a `progs/<name>.rs`
here. Nothing from the kernel tree is copied — the repo contains only the
Rust sources, the build pipeline, and the swap/test driver. Everything else
is referenced from the checkouts it is pointed at, so the working state is
fully recreatable from any bpf-next selftests build.

## Prerequisites

- a bpf-next checkout with selftests built (see `kernel-pin` for the commit
  this was developed against); the isolated
  [bpf-uml-selftests](../uml-harness) build provides this plus the UML
  kernel and `uml-veristat` / `uml-test-progs`
- a built [4ast/rust-bpf](../rust-bpf) checkout (`bld_deps/` with
  libcore/liballoc rlibs, `bld/bpf-postproc`, `bld/libbtf_macros.so`)
- LLVM >= 22 (llc/opt/llvm-link/llvm-readelf/llvm-objcopy)
- rustc (stable is fine; `rust-src` component, `RUSTC_BOOTSTRAP=1` is set by
  the Makefile)

Default paths assume the `heimdall_experiment` layout; override
`KERNEL_SRC` / `SELFTESTS_OUTPUT` / `RUSTBPF` / `LLVM_PREFIX` /
`UML_HARNESS` / `UML_INSTALL_DIR` to point elsewhere.

## Usage

```sh
make                  # build bld/<name>.bpf.o for every progs/*.rs
make verify           # kernel-verifier gate: uml-veristat over all objects
make test-fentry_test # swap Rust object into the selftests output,
                      # regenerate skeletons + test_progs via the kernel
                      # Makefile, run the affected tests in UML
make restore-fentry_test  # reinstall the pristine C object and rebuild
make status           # translation coverage
```

`make test-<name>` reuses the harness verbatim by construction: the Rust
object is installed as `<name>.bpf.o` in the selftests output directory and
the kernel's own Makefile regenerates the (possibly signed) skeletons and
relinks `test_progs` from it. The pristine C object is backed up once as
`<name>.bpf.o.corig` and can be reinstalled at any time (`restore-<name>`),
which also enables C-vs-Rust A/B runs of the same test.

The set of affected tests is discovered from the generated `*.test.d`
dependency files, so program/test name mismatches need no manual mapping.
The internalize keep-list for each program is derived from the global
FUNC/OBJECT symbols of the C-built object — the C object's ELF ABI is the
contract the translation must satisfy.

## Translation conventions

See `progs/fentry_test.rs` for the reference shape:

- `#![no_std] #![no_main]`, edition 2021
- one `extern "C" fn` per BPF program, `#[no_mangle]`, placed with
  `#[link_section = "<sec>/<attach-target>"]`; ctx is `*const u64`
- globals the harness reads/writes are `#[no_mangle] static mut` matching
  the C names/types (zero-initialized ⇒ `.bss`)
- license via `#[link_section = "license"]` static
- helper/kfunc bindings as local `extern "C"` declarations wrapped in safe
  fns; CO-RE field access via the `#[btf]` proc-macro (from rust-bpf)
