# LLVM patches

Patches that `scripts/build-llvm.sh` applies, in name order, to llvm-project
release/23.x at the `LLVM_COMMIT` in that script before building the LLVM
every translation is compiled with (`LLVM_PREFIX`). While this directory is
not empty the release tarballs are not usable (`scripts/fetch-llvm.sh`
refuses); when upstream carries a patch, delete it here.

- `0001-BPF-Remove-unused-preserve_field_info-calls-instead-of-crashing.patch`:
  BPFAbstractMemberAccess crashes in `replaceWithGEP` on an unused
  `llvm.bpf.preserve.field.info` call (segfault in release builds, "Must
  specify element type" assertion otherwise). rustc leaves one behind
  whenever it makes a `#[btf]` field access dead, so without the fix
  `getsockname`, `getpeername`, `recvmsg_unix_prog` and `stream` cannot use
  CO-RE field offsets (issues #49, #60). Upstream: branch
  [prozak/llvm-project `bpf-unused-field-info`](https://github.com/prozak/llvm-project/tree/bpf-unused-field-info)
  (399ba9d79852), pull request to llvm/llvm-project pending.
