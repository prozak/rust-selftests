# Real Rust collections in BPF (arena-backed)

`alloc::{Box, Vec, String, VecDeque}` — the real ones, from the Rust
standard library — running inside SEC("syscall") BPF programs, backed by a
BPF arena through [libbpf/libarena]'s buddy allocator.

The implementation now lives in its own repository,
[prozak/libarena-rs](https://github.com/prozak/libarena-rs) (also on
crates.io as `libarena-rs`), vendored here as the `vendor/libarena-rs`
submodule. That repository holds the `GlobalAlloc`, the C glue, the
bitcode-merge pipeline (`mk/libarena.mk`), the runner and the test programs,
plus the write-up of what it took to make `alloc` verify in BPF and the known
limits. This directory is only the harness shim that points the crate's
pipeline at this tree's LLVM, `vmlinux.h`, libbpf and qemu kernel:

```
$ git submodule update --init --recursive collections/vendor/libarena-rs
$ make test          # boots the pinned qemu kernel via vng
OK   test_rs_box
OK   test_rs_grow_shrink
OK   test_rs_sort
OK   test_rs_string
OK   test_rs_vec
OK   test_rs_vecdeque
bld/collections_smoke.bpf.o: 6/6 passed
```

Changes to the allocator, the pipeline or the test programs go to the crate
repository; this directory only tracks which crate commit the tree builds.

[libbpf/libarena]: https://github.com/libbpf/libarena
