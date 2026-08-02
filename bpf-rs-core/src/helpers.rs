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
pub fn bpf_probe_read_user_str(dst: *mut c_void, size: u32, src: *const c_void) -> i64 {
    thunk!(114, fn(*mut c_void, u32, *const c_void) -> i64)(dst, size, src)
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
pub fn bpf_probe_read_kernel_str(dst: *mut c_void, size: u32, src: *const c_void) -> i64 {
    thunk!(115, fn(*mut c_void, u32, *const c_void) -> i64)(dst, size, src)
}

#[inline(always)]
pub fn bpf_copy_from_user(dst: *mut c_void, size: u32, user_ptr: *const c_void) -> i64 {
    thunk!(148, fn(*mut c_void, u32, *const c_void) -> i64)(dst, size, user_ptr)
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

#[inline(always)]
pub fn bpf_skb_store_bytes(
    skb: *const c_void,
    offset: u32,
    from: *const c_void,
    len: u32,
    flags: u64,
) -> i64 {
    thunk!(9, fn(*const c_void, u32, *const c_void, u32, u64) -> i64)(skb, offset, from, len, flags)
}

#[inline(always)]
pub fn bpf_l3_csum_replace(skb: *const c_void, offset: u32, from: u64, to: u64, size: u64) -> i64 {
    thunk!(10, fn(*const c_void, u32, u64, u64, u64) -> i64)(skb, offset, from, to, size)
}

#[inline(always)]
pub fn bpf_redirect(ifindex: u32, flags: u64) -> i64 {
    thunk!(23, fn(u32, u64) -> i64)(ifindex, flags)
}

#[inline(always)]
pub fn bpf_skb_load_bytes(skb: *const c_void, offset: u32, to: *mut c_void, len: u32) -> i64 {
    thunk!(26, fn(*const c_void, u32, *mut c_void, u32) -> i64)(skb, offset, to, len)
}

#[inline(always)]
pub fn bpf_skb_pull_data(skb: *const c_void, len: u32) -> i64 {
    thunk!(39, fn(*const c_void, u32) -> i64)(skb, len)
}

#[inline(always)]
pub fn bpf_skb_adjust_room(skb: *const c_void, len_diff: i32, mode: u32, flags: u64) -> i64 {
    thunk!(50, fn(*const c_void, i32, u32, u64) -> i64)(skb, len_diff, mode, flags)
}

#[inline(always)]
pub fn bpf_sk_lookup_udp<T>(
    ctx: *const c_void,
    tuple: *const T,
    tuple_size: u32,
    netns: u64,
    flags: u64,
) -> *mut c_void {
    thunk!(85, fn(*const c_void, *const T, u32, u64, u64) -> *mut c_void)(
        ctx, tuple, tuple_size, netns, flags,
    )
}

#[inline(always)]
pub fn bpf_sk_release(sock: *mut c_void) -> i64 {
    thunk!(86, fn(*mut c_void) -> i64)(sock)
}

#[inline(always)]
pub fn bpf_skc_lookup_tcp<T>(
    ctx: *const c_void,
    tuple: *const T,
    tuple_size: u32,
    netns: u64,
    flags: u64,
) -> *mut c_void {
    thunk!(99, fn(*const c_void, *const T, u32, u64, u64) -> *mut c_void)(
        ctx, tuple, tuple_size, netns, flags,
    )
}

#[inline(always)]
pub fn bpf_tcp_check_syncookie<S, I, T>(
    sk: *mut S,
    iph: *const I,
    iph_len: u32,
    th: *const T,
    th_len: u32,
) -> i64 {
    thunk!(100, fn(*mut S, *const I, u32, *const T, u32) -> i64)(sk, iph, iph_len, th, th_len)
}

#[inline(always)]
pub fn bpf_csum_level(skb: *const c_void, level: u64) -> i64 {
    thunk!(135, fn(*const c_void, u64) -> i64)(skb, level)
}

#[inline(always)]
pub fn bpf_check_mtu(ctx: *const c_void, ifindex: u32, mtu_len: *mut u32, len_diff: i32, flags: u64) -> i64 {
    thunk!(163, fn(*const c_void, u32, *mut u32, i32, u64) -> i64)(ctx, ifindex, mtu_len, len_diff, flags)
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

/// `bpf_loop(nr_loops, callback_fn, callback_ctx, flags)`. The callback
/// function's address is taken as an ordinary Rust fn-pointer value, which
/// LLVM's BPF backend lowers to the same BPF_PSEUDO_FUNC load the kernel
/// verifier expects for a callback argument — no special relocation needed
/// on our end.
#[inline(always)]
pub fn bpf_loop<C>(
    nr_loops: u32,
    callback_fn: extern "C" fn(u64, *mut C) -> i64,
    callback_ctx: *mut C,
    flags: u64,
) -> i64 {
    thunk!(181, fn(u32, extern "C" fn(u64, *mut C) -> i64, *mut C, u64) -> i64)(
        nr_loops,
        callback_fn,
        callback_ctx,
        flags,
    )
}

/// `bpf_for_each_map_elem(map, callback_fn, callback_ctx, flags)`. Same
/// fn-pointer-as-BPF_PSEUDO_FUNC mechanism as `bpf_loop`; the callback
/// signature mirrors the kernel's `long (*callback_fn)(struct bpf_map *map,
/// void *key, void *value, void *aux)`.
#[inline(always)]
pub fn bpf_for_each_map_elem<M, K, V, C>(
    map: *const M,
    callback_fn: extern "C" fn(*mut M, *mut K, *mut V, *mut C) -> i64,
    callback_ctx: *mut C,
    flags: u64,
) -> i64 {
    thunk!(164, fn(*const M, extern "C" fn(*mut M, *mut K, *mut V, *mut C) -> i64, *mut C, u64) -> i64)(
        map,
        callback_fn,
        callback_ctx,
        flags,
    )
}

#[inline(always)]
pub fn bpf_get_func_ip(ctx: *const c_void) -> u64 {
    thunk!(173, fn(*const c_void) -> u64)(ctx)
}

/// C's `barrier_var()`: round-trips a scalar place through a register so the
/// optimizer can't prove pre/post equality. Used to make an otherwise
/// invertible op (e.g. `x ^= i; x ^= i;`) opaque to the verifier's value
/// tracking, so it doesn't try to carry a precise value across every
/// bpf_loop callback invocation and blow up its state count.
#[inline(always)]
pub fn barrier_var(v: &mut usize) {
    unsafe {
        core::arch::asm!("{0} = {0}", inout(reg) *v, options(nostack, preserves_flags));
    }
}

/// `bpf_get_local_storage(map, flags)`: pointer to the per-cpu-cgroup local
/// storage area for a `BPF_MAP_TYPE_CGROUP_STORAGE`/`BPF_MAP_TYPE_CGRP_STORAGE`
/// map, keyed implicitly by the attached cgroup — never null for a correctly
/// attached program, same genericity as `bpf_map_lookup_elem`.
#[inline(always)]
pub fn bpf_get_local_storage<M>(map: *const M, flags: u64) -> *mut c_void {
    thunk!(81, fn(*const M, u64) -> *mut c_void)(map, flags)
}

/// `bpf_spin_lock(lock)` / `bpf_spin_unlock(lock)`. Generic over the caller's
/// `bpf_spin_lock`-named struct, same as the map-def genericity above: the
/// pointee type is never inspected at the call site.
#[inline(always)]
pub fn bpf_spin_lock<L>(lock: *mut L) -> i64 {
    thunk!(93, fn(*mut L) -> i64)(lock)
}

#[inline(always)]
pub fn bpf_spin_unlock<L>(lock: *mut L) -> i64 {
    thunk!(94, fn(*mut L) -> i64)(lock)
}

/// `bpf_seq_printf(seq, fmt, fmt_size, data, data_len)`: the raw helper C's
/// BPF_SEQ_PRINTF macro wraps. `data`/`data_len` describe a packed array of
/// 8-byte slots, one per format-string argument (`data_len == 0` and a null
/// `data` are valid for a format string with no arguments).
/// `bpf_kptr_xchg(dst, ptr)`: atomically exchange a referenced kptr stored at
/// `dst` (a `__kptr`-tagged field/global) with `ptr`, returning the old
/// value (caller must `bpf_obj_drop` a non-null result).
#[inline(always)]
pub fn bpf_kptr_xchg(dst: *mut c_void, val: *mut c_void) -> *mut c_void {
    thunk!(194, fn(*mut c_void, *mut c_void) -> *mut c_void)(dst, val)
}

#[inline(always)]
pub fn bpf_seq_printf(
    seq: *mut c_void,
    fmt: *const c_void,
    fmt_size: u32,
    data: *const c_void,
    data_len: u32,
) -> i64 {
    thunk!(126, fn(*mut c_void, *const c_void, u32, *const c_void, u32) -> i64)(
        seq, fmt, fmt_size, data, data_len,
    )
}

/// `bpf_get_current_task_btf()`: like `bpf_get_current_task`, but returns a
/// BTF-typed (PTR_TO_BTF_ID) `struct task_struct *`, so callers may pass the
/// result to CO-RE field reads directly instead of going through
/// `bpf_probe_read_kernel`.
#[inline(always)]
pub fn bpf_get_current_task_btf<T>() -> *mut T {
    thunk!(158, fn() -> *mut T)()
}

#[inline(always)]
pub fn bpf_probe_write_user(dst: *mut c_void, src: *const c_void, len: u32) -> i64 {
    thunk!(36, fn(*mut c_void, *const c_void, u32) -> i64)(dst, src, len)
}

/// `bpf_timer_init(timer, map, flags)`. Generic over the caller's
/// `bpf_timer`-named field struct and the owning map-def type, same
/// pointee-erased-at-the-call-site genericity as `bpf_spin_lock`.
#[inline(always)]
pub fn bpf_timer_init<T, M>(timer: *mut T, map: *const M, flags: u64) -> i64 {
    thunk!(169, fn(*mut T, *const M, u64) -> i64)(timer, map, flags)
}

/// `bpf_timer_set_callback(timer, callback_fn)`. Same fn-pointer-as-
/// BPF_PSEUDO_FUNC mechanism as `bpf_loop`/`bpf_for_each_map_elem`; the
/// callback signature mirrors the kernel's
/// `long (*callback_fn)(void *map, int *key, void *value)`.
#[inline(always)]
pub fn bpf_timer_set_callback<T, M, K, V>(
    timer: *mut T,
    callback_fn: extern "C" fn(*mut M, *mut K, *mut V) -> i64,
) -> i64 {
    thunk!(170, fn(*mut T, extern "C" fn(*mut M, *mut K, *mut V) -> i64) -> i64)(
        timer,
        callback_fn,
    )
}

#[inline(always)]
pub fn bpf_timer_start<T>(timer: *mut T, nsecs: u64, flags: u64) -> i64 {
    thunk!(171, fn(*mut T, u64, u64) -> i64)(timer, nsecs, flags)
}

#[inline(always)]
pub fn bpf_get_retval() -> i32 {
    thunk!(186, fn() -> i32)()
}

#[inline(always)]
pub fn bpf_set_retval(retval: i32) -> i32 {
    thunk!(187, fn(i32) -> i32)(retval)
}

/// __sync_fetch_and_add on a plain `unsigned int`/__u32 global: same
/// atomic-view-punned-at-the-call-site idea as `sync_fetch_and_add`, but for
/// globals whose C/BTF type is 32-bit (changing them to isize would double
/// their size and shift every later .bss member).
#[inline(always)]
pub fn sync_fetch_and_add_u32(p: *mut u32, v: u32) {
    use core::sync::atomic::{AtomicU32, Ordering};
    unsafe { (*(p as *mut AtomicU32)).fetch_add(v, Ordering::SeqCst) };
}

#[inline(always)]
pub fn bpf_sk_lookup_tcp<T>(
    ctx: *const c_void,
    tuple: *const T,
    tuple_size: u32,
    netns: u64,
    flags: u64,
) -> *mut c_void {
    thunk!(84, fn(*const c_void, *const T, u32, u64, u64) -> *mut c_void)(
        ctx, tuple, tuple_size, netns, flags,
    )
}

#[inline(always)]
pub fn bpf_redirect_map<M>(map: *const M, key: u64, flags: u64) -> i64 {
    thunk!(51, fn(*const M, u64, u64) -> i64)(map, key, flags)
}

#[inline(always)]
pub fn bpf_skb_cgroup_id(skb: *const c_void) -> u64 {
    thunk!(79, fn(*const c_void) -> u64)(skb)
}

#[inline(always)]
pub fn bpf_skb_ancestor_cgroup_id(skb: *const c_void, ancestor_level: i32) -> u64 {
    thunk!(83, fn(*const c_void, i32) -> u64)(skb, ancestor_level)
}

#[inline(always)]
pub fn bpf_sk_cgroup_id(sk: *mut c_void) -> u64 {
    thunk!(128, fn(*mut c_void) -> u64)(sk)
}

#[inline(always)]
pub fn bpf_sk_ancestor_cgroup_id(sk: *mut c_void, ancestor_level: i32) -> u64 {
    thunk!(129, fn(*mut c_void, i32) -> u64)(sk, ancestor_level)
}

#[inline(always)]
pub fn bpf_skb_change_type(skb: *const c_void, ty: u32) -> i64 {
    thunk!(32, fn(*const c_void, u32) -> i64)(skb, ty)
}

/// `bpf_fib_lookup(ctx, params, plen, flags)`. Generic over the caller's
/// `bpf_fib_lookup`-shaped params struct, same pointee-erased-at-the-call-site
/// genericity as `bpf_spin_lock`.
#[inline(always)]
pub fn bpf_fib_lookup<T>(ctx: *const c_void, params: *mut T, plen: i32, flags: u32) -> i64 {
    thunk!(69, fn(*const c_void, *mut T, i32, u32) -> i64)(ctx, params, plen, flags)
}

/// `bpf_redirect_neigh(ifindex, params, plen, flags)`. Generic over the
/// caller's `bpf_redir_neigh`-shaped params struct.
#[inline(always)]
pub fn bpf_redirect_neigh<T>(ifindex: u32, params: *mut T, plen: i32, flags: u64) -> i64 {
    thunk!(152, fn(u32, *mut T, i32, u64) -> i64)(ifindex, params, plen, flags)
}

/// `long bpf_strncmp(const char *s1, u32 s1_sz, const char *s2)`.
#[inline(always)]
pub fn bpf_strncmp(s1: *const c_void, s1_sz: u32, s2: *const c_void) -> i64 {
    thunk!(182, fn(*const c_void, u32, *const c_void) -> i64)(s1, s1_sz, s2)
}

/// `long bpf_lwt_push_encap(struct sk_buff *skb, u32 type, void *hdr, u32 len)`.
#[inline(always)]
pub fn bpf_lwt_push_encap(skb: *const c_void, typ: u32, hdr: *const c_void, len: u32) -> i64 {
    thunk!(73, fn(*const c_void, u32, *const c_void, u32) -> i64)(skb, typ, hdr, len)
}

/// `long bpf_lwt_seg6_store_bytes(struct sk_buff *skb, u32 offset, const void *from, u32 len)`.
#[inline(always)]
pub fn bpf_lwt_seg6_store_bytes(skb: *const c_void, offset: u32, from: *const c_void, len: u32) -> i64 {
    thunk!(74, fn(*const c_void, u32, *const c_void, u32) -> i64)(skb, offset, from, len)
}

/// `long bpf_lwt_seg6_adjust_srh(struct sk_buff *skb, u32 offset, s32 delta)`.
#[inline(always)]
pub fn bpf_lwt_seg6_adjust_srh(skb: *const c_void, offset: u32, delta: i32) -> i64 {
    thunk!(75, fn(*const c_void, u32, i32) -> i64)(skb, offset, delta)
}

/// `long bpf_lwt_seg6_action(struct sk_buff *skb, u32 action, void *param, u32 param_len)`.
#[inline(always)]
pub fn bpf_lwt_seg6_action(skb: *const c_void, action: u32, param: *mut c_void, param_len: u32) -> i64 {
    thunk!(76, fn(*const c_void, u32, *mut c_void, u32) -> i64)(skb, action, param, param_len)
}

/// `long bpf_override_return(struct pt_regs *regs, u64 rc)`.
#[inline(always)]
pub fn bpf_override_return(regs: *const c_void, rc: u64) -> i64 {
    thunk!(58, fn(*const c_void, u64) -> i64)(regs, rc)
}
