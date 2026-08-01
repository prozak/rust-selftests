// Program-side accessors.

/// Read argument `i` of a tracing program (fentry/fexit/tp_btf): ctx is an
/// array of u64 slots, one per target-function argument; the verifier types
/// each slot load from the target's BTF proto. Truncate the returned u64
/// with `as` to the target argument's C type — this is what C's BPF_PROG
/// macro does.
#[inline(always)]
pub fn fentry_arg(ctx: *const u64, i: usize) -> u64 {
    unsafe { *ctx.add(i) }
}
