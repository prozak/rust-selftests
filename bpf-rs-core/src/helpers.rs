// BPF helper calls, the canonical thunk: a call through a fn pointer whose
// value is the constant helper ID; LLVM folds it into the direct BPF
// helper-call instruction. This is the same mechanism as C's bpf_helpers.h
// (`(void *)BPF_FUNC_x`) — the transmute lives HERE and nowhere else.
//
// Map arguments are generic over the map-def struct (`*const M`), matching
// how libbpf/the verifier see them (the pointer's pointee type is never
// inspected at the call site). Key/value pointers are c_void, null-checked
// lookups return raw pointers the caller must check.

use core::ffi::c_void;

macro_rules! thunk {
    ($id:literal, fn($($aty:ty),*) $(-> $rty:ty)?) => {{
        let f: extern "C" fn($($aty),*) $(-> $rty)? =
            unsafe { core::mem::transmute($id as usize) };
        f
    }};
}

#[inline(always)]
pub fn bpf_map_lookup_elem<M, K>(map: *const M, key: &K) -> *mut c_void {
    thunk!(1, fn(*const M, *const c_void) -> *mut c_void)(
        map,
        key as *const K as *const c_void,
    )
}

#[inline(always)]
pub fn bpf_map_update_elem<M, K, V>(map: *const M, key: &K, value: &V, flags: u64) -> i64 {
    thunk!(2, fn(*const M, *const c_void, *const c_void, u64) -> i64)(
        map,
        key as *const K as *const c_void,
        value as *const V as *const c_void,
        flags,
    )
}

#[inline(always)]
pub fn bpf_map_delete_elem<M, K>(map: *const M, key: &K) -> i64 {
    thunk!(3, fn(*const M, *const c_void) -> i64)(map, key as *const K as *const c_void)
}

#[inline(always)]
pub fn bpf_ktime_get_ns() -> u64 {
    thunk!(5, fn() -> u64)()
}

#[inline(always)]
pub fn bpf_get_prandom_u32() -> u32 {
    thunk!(7, fn() -> u32)()
}

#[inline(always)]
pub fn bpf_get_smp_processor_id() -> u32 {
    thunk!(8, fn() -> u32)()
}

#[inline(always)]
pub fn bpf_tail_call<M>(ctx: *const c_void, prog_array: *const M, index: u32) -> i64 {
    thunk!(12, fn(*const c_void, *const M, u32) -> i64)(ctx, prog_array, index)
}

#[inline(always)]
pub fn bpf_get_current_pid_tgid() -> u64 {
    thunk!(14, fn() -> u64)()
}

#[inline(always)]
pub fn bpf_get_current_uid_gid() -> u64 {
    thunk!(15, fn() -> u64)()
}

#[inline(always)]
pub fn bpf_get_current_comm(buf: *mut c_void, size: u32) -> i64 {
    thunk!(16, fn(*mut c_void, u32) -> i64)(buf, size)
}

#[inline(always)]
pub fn bpf_perf_event_output<M, T>(
    ctx: *const c_void,
    map: *const M,
    flags: u64,
    data: &T,
    size: u64,
) -> i64 {
    thunk!(25, fn(*const c_void, *const M, u64, *const c_void, u64) -> i64)(
        ctx,
        map,
        flags,
        data as *const T as *const c_void,
        size,
    )
}

#[inline(always)]
pub fn bpf_get_stackid<M>(ctx: *const c_void, map: *const M, flags: u64) -> i64 {
    thunk!(27, fn(*const c_void, *const M, u64) -> i64)(ctx, map, flags)
}

#[inline(always)]
pub fn bpf_get_current_task() -> u64 {
    thunk!(35, fn() -> u64)()
}

#[inline(always)]
pub fn bpf_get_stack(ctx: *const c_void, buf: *mut c_void, size: u32, flags: u64) -> i64 {
    thunk!(67, fn(*const c_void, *mut c_void, u32, u64) -> i64)(ctx, buf, size, flags)
}

#[inline(always)]
pub fn bpf_probe_read_user(dst: *mut c_void, size: u32, src: *const c_void) -> i64 {
    thunk!(112, fn(*mut c_void, u32, *const c_void) -> i64)(dst, size, src)
}

#[inline(always)]
pub fn bpf_probe_read_kernel<T>(dst: &mut T, size: u32, src: *const c_void) -> i64 {
    thunk!(113, fn(*mut c_void, u32, *const c_void) -> i64)(
        dst as *mut T as *mut c_void,
        size,
        src,
    )
}

#[inline(always)]
pub fn bpf_ringbuf_output<M>(map: *const M, data: *const c_void, size: u64, flags: u64) -> i64 {
    thunk!(130, fn(*const M, *const c_void, u64, u64) -> i64)(map, data, size, flags)
}

#[inline(always)]
pub fn bpf_ringbuf_reserve<M>(map: *const M, size: u64, flags: u64) -> *mut c_void {
    thunk!(131, fn(*const M, u64, u64) -> *mut c_void)(map, size, flags)
}

#[inline(always)]
pub fn bpf_ringbuf_submit(data: *mut c_void, flags: u64) {
    thunk!(132, fn(*mut c_void, u64))(data, flags)
}

#[inline(always)]
pub fn bpf_ringbuf_discard(data: *mut c_void, flags: u64) {
    thunk!(133, fn(*mut c_void, u64))(data, flags)
}

#[inline(always)]
pub fn bpf_ringbuf_query<M>(map: *const M, flags: u64) -> u64 {
    thunk!(134, fn(*const M, u64) -> u64)(map, flags)
}

/// __sync_fetch_and_add on a plain integer global: the C selftests use GCC
/// atomics on ordinary `long` globals; the BTF/skeleton type must stay a
/// plain int, so the atomic view is punned on at the access site only.
#[inline(always)]
pub fn sync_fetch_and_add(p: *mut isize, v: isize) {
    use core::sync::atomic::{AtomicIsize, Ordering};
    unsafe { (*(p as *mut AtomicIsize)).fetch_add(v, Ordering::SeqCst) };
}

/// C's __sink()/volatile-buffer barrier: forces `p` (and what it points at)
/// to be materialized. The self-move form emits exactly one real insn — a
/// zero-insn asm's line record collapses onto the next insn's offset and
/// the kernel rejects the duplicate .BTF.ext line_info entry.
#[inline(always)]
pub fn sink<T>(p: &mut *mut T) {
    unsafe {
        core::arch::asm!("{0} = {0}", inout(reg) *p, options(nostack, preserves_flags));
    }
}

/// Consume a value in a register without emitting an instruction (C:
/// `asm volatile("" :: "r"(v))`). Keeps dead-arg-elim from dropping a
/// function argument, preserving the C signature in BTF.
#[inline(always)]
pub fn sink_val(v: i32) {
    unsafe {
        core::arch::asm!("/* {0} */", in(reg) v, options(nomem, nostack, preserves_flags));
    }
}
