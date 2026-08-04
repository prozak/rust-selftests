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

/// `long bpf_bind(struct bpf_sock_addr *ctx, struct sockaddr *addr, int addr_len)`.
/// Generic over the caller's `bpf_sock_addr`-named ctx struct and the
/// sockaddr-shaped addr struct, same pointee-erased-at-the-call-site
/// genericity as `bpf_spin_lock`.
#[inline(always)]
pub fn bpf_bind<C, A>(ctx: *mut C, addr: *mut A, addr_len: i32) -> i64 {
    thunk!(64, fn(*mut C, *mut A, i32) -> i64)(ctx, addr, addr_len)
}

/// `void *bpf_cgrp_storage_get(struct bpf_map *map, struct cgroup *cgroup,
/// void *value, u64 flags)`. Generic over both the map-def type and the
/// cgroup-pointer type: the verifier's arg-type check for `ARG_PTR_TO_BTF_ID`
/// looks at the actual BTF id carried by the register at the call site, not
/// any source-level pointer cast, so passing a pointer whose real BTF type
/// isn't `struct cgroup` (e.g. a `struct task_struct *`) reproduces C's
/// `(struct cgroup *)task` type-confusion exactly.
#[inline(always)]
pub fn bpf_cgrp_storage_get<M, T>(
    map: *const M,
    cgroup: *mut T,
    value: *mut c_void,
    flags: u64,
) -> *mut c_void {
    thunk!(210, fn(*const M, *mut T, *mut c_void, u64) -> *mut c_void)(map, cgroup, value, flags)
}

/// `long bpf_csum_diff(__be32 *from, u32 from_size, __be32 *to, u32 to_size, __wsum seed)`.
#[inline(always)]
pub fn bpf_csum_diff(
    from: *const c_void,
    from_size: u32,
    to: *const c_void,
    to_size: u32,
    seed: u32,
) -> i64 {
    thunk!(28, fn(*const c_void, u32, *const c_void, u32, u32) -> i64)(
        from, from_size, to, to_size, seed,
    )
}

/// `long bpf_d_path(const struct path *path, char *buf, u32 sz)`.
#[inline(always)]
pub fn bpf_d_path<T>(path: *const T, buf: *mut c_void, sz: u32) -> i64 {
    thunk!(147, fn(*const T, *mut c_void, u32) -> i64)(path, buf, sz)
}

/// `bpf_find_vma(task, addr, callback_fn, callback_ctx, flags)`. Same
/// fn-pointer-as-BPF_PSEUDO_FUNC mechanism as `bpf_loop`; the callback
/// signature mirrors the kernel's `long (*callback_fn)(struct task_struct
/// *task, struct vm_area_struct *vma, void *callback_ctx)`.
#[inline(always)]
pub fn bpf_find_vma<T, V, C>(
    task: *mut T,
    addr: u64,
    callback_fn: extern "C" fn(*mut T, *mut V, *mut C) -> i64,
    callback_ctx: *mut C,
    flags: u64,
) -> i64 {
    thunk!(180, fn(*mut T, u64, extern "C" fn(*mut T, *mut V, *mut C) -> i64, *mut C, u64) -> i64)(
        task,
        addr,
        callback_fn,
        callback_ctx,
        flags,
    )
}

#[inline(always)]
pub fn bpf_get_current_cgroup_id() -> u64 {
    thunk!(80, fn() -> u64)()
}

/// `long bpf_getsockopt(void *bpf_socket, int level, int optname, void *optval, int optlen)`.
#[inline(always)]
pub fn bpf_getsockopt<C>(
    bpf_socket: *mut C,
    level: i32,
    optname: i32,
    optval: *mut c_void,
    optlen: i32,
) -> i64 {
    thunk!(57, fn(*mut C, i32, i32, *mut c_void, i32) -> i64)(
        bpf_socket, level, optname, optval, optlen,
    )
}

/// `u64 bpf_ktime_get_tai_ns(void)`.
#[inline(always)]
pub fn bpf_ktime_get_tai_ns() -> u64 {
    thunk!(208, fn() -> u64)()
}

/// `long bpf_map_pop_elem(struct bpf_map *map, void *value)`:
/// BPF_MAP_TYPE_QUEUE/STACK pop (removes and returns the front/top element).
#[inline(always)]
pub fn bpf_map_pop_elem<M, V>(map: *const M, value: &mut V) -> i64 {
    thunk!(88, fn(*const M, *mut c_void) -> i64)(map, value as *mut V as *mut c_void)
}

/// `long bpf_map_push_elem(struct bpf_map *map, const void *value, u64 flags)`:
/// BPF_MAP_TYPE_QUEUE/STACK push.
#[inline(always)]
pub fn bpf_map_push_elem<M, V>(map: *const M, value: &V, flags: u64) -> i64 {
    thunk!(87, fn(*const M, *const c_void, u64) -> i64)(
        map,
        value as *const V as *const c_void,
        flags,
    )
}

/// `long bpf_map_update_elem(...)` variant taking the value as a raw
/// pointer instead of `&V` — for call sites that already hold a pointer
/// (e.g. passing a `PTR_TO_SOCKET` straight through, as C does when it
/// deliberately misuses the helper on a sockmap).
#[inline(always)]
pub fn bpf_map_update_elem_ptr<M, K>(map: *const M, key: &K, value: *const c_void, flags: u64) -> i64 {
    thunk!(2, fn(*const M, *const c_void, *const c_void, u64) -> i64)(
        map,
        key as *const K as *const c_void,
        value,
        flags,
    )
}

/// `long bpf_msg_pop_data(struct sk_msg_buff *msg, u32 start, u32 len, u64 flags)`.
#[inline(always)]
pub fn bpf_msg_pop_data<T>(msg: *mut T, start: u32, len: u32, flags: u64) -> i64 {
    thunk!(91, fn(*mut T, u32, u32, u64) -> i64)(msg, start, len, flags)
}

/// `void *bpf_per_cpu_ptr(const void *percpu_ptr, u32 cpu)`: may return NULL,
/// caller must check.
#[inline(always)]
pub fn bpf_per_cpu_ptr(percpu_ptr: *const c_void, cpu: u32) -> *mut c_void {
    thunk!(153, fn(*const c_void, u32) -> *mut c_void)(percpu_ptr, cpu)
}

/// Raw-pointer variant of `bpf_probe_read_kernel` for callers that build up a
/// payload at a runtime-computed destination address (e.g. a `void *payload`
/// cursor advanced across several CO-RE field chases), where the generic
/// `&mut T` form of `bpf_probe_read_kernel` can't express the destination.
#[inline(always)]
pub fn bpf_probe_read_kernel_raw(dst: *mut c_void, size: u32, src: *const c_void) -> i64 {
    thunk!(113, fn(*mut c_void, u32, *const c_void) -> i64)(dst, size, src)
}

/// `bpf_get_current_task_btf()`: like `bpf_get_current_task`, but returns a
/// BTF-typed (PTR_TO_BTF_ID) `struct task_struct *`, so callers may pass the
/// result to CO-RE field reads directly instead of going through
/// `bpf_probe_read_kernel`.
/// `bpf_seq_write(seq, data, len)`: write raw bytes to the seq_file, the
/// helper `BPF_SEQ_PRINTF`'s sibling `bpf_seq_write()` libbpf macro wraps.
#[inline(always)]
pub fn bpf_seq_write(seq: *mut c_void, data: *const c_void, len: u32) -> i64 {
    thunk!(127, fn(*mut c_void, *const c_void, u32) -> i64)(seq, data, len)
}

/// `long bpf_sk_assign(struct sk_buff *skb, struct bpf_sock *sk, u64 flags)`.
#[inline(always)]
pub fn bpf_sk_assign(skb: *const c_void, sk: *mut c_void, flags: u64) -> i64 {
    thunk!(124, fn(*const c_void, *mut c_void, u64) -> i64)(skb, sk, flags)
}

#[inline(always)]
pub fn bpf_skb_change_proto(skb: *const c_void, proto: u16, flags: u64) -> i64 {
    thunk!(31, fn(*const c_void, u16, u64) -> i64)(skb, proto, flags)
}

/// `long bpf_snprintf(char *str, u32 str_size, const char *fmt, u64 *data, u32 data_len)`.
#[inline(always)]
pub fn bpf_snprintf(
    str_: *mut c_void,
    str_size: u32,
    fmt: *const c_void,
    data: *const c_void,
    data_len: u32,
) -> i64 {
    thunk!(165, fn(*mut c_void, u32, *const c_void, *const c_void, u32) -> i64)(
        str_, str_size, fmt, data, data_len,
    )
}

/// `long bpf_task_pt_regs(struct task_struct *task)`: returns the
/// kernel-internal `struct pt_regs *` for a `task_struct *` (typically from
/// `bpf_get_current_task_btf()`), as a raw pointer value.
#[inline(always)]
pub fn bpf_task_pt_regs<T>(task: *mut T) -> *mut c_void {
    thunk!(175, fn(*mut T) -> *mut c_void)(task)
}

/// `void *bpf_this_cpu_ptr(const void *percpu_ptr)`.
#[inline(always)]
pub fn bpf_this_cpu_ptr(percpu_ptr: *const c_void) -> *mut c_void {
    thunk!(154, fn(*const c_void) -> *mut c_void)(percpu_ptr)
}

#[inline(always)]
pub fn bpf_trace_printk(fmt: *const c_void, fmt_size: u32, arg1: u64, arg2: u64, arg3: u64) -> i64 {
    thunk!(6, fn(*const c_void, u32, u64, u64, u64) -> i64)(fmt, fmt_size, arg1, arg2, arg3)
}

/// `long bpf_xdp_adjust_meta(struct xdp_md *xdp_md, int delta)`.
#[inline(always)]
pub fn bpf_xdp_adjust_meta<T>(xdp: *mut T, delta: i32) -> i64 {
    thunk!(54, fn(*mut T, i32) -> i64)(xdp, delta)
}

/// __sync_fetch_and_add on a plain `__u64`/`unsigned long long` global: same
/// atomic-view-punned-at-the-call-site idea as `sync_fetch_and_add_u32`, but
/// for globals whose C/BTF type is 64-bit unsigned.
#[inline(always)]
pub fn sync_fetch_and_add_u64(p: *mut u64, v: u64) {
    use core::sync::atomic::{AtomicU64, Ordering};
    unsafe { (*(p as *mut AtomicU64)).fetch_add(v, Ordering::SeqCst) };
}

/// `long bpf_setsockopt(void *bpf_socket, int level, int optname,
/// void *optval, int optlen)`. Generic over the ctx-shaped socket pointer;
/// optval is *const so both mut and const call sites coerce.
#[inline(always)]
pub fn bpf_setsockopt<C>(
    bpf_socket: *mut C,
    level: i32,
    optname: i32,
    optval: *const c_void,
    optlen: i32,
) -> i64 {
    thunk!(49, fn(*mut C, i32, i32, *const c_void, i32) -> i64)(
        bpf_socket, level, optname, optval, optlen,
    )
}

/// `void *bpf_task_storage_get(struct bpf_map *map, struct task_struct *task,
/// void *value, u64 flags)`. Generic over map-def and task pointer types;
/// may return NULL, caller must check.
#[inline(always)]
pub fn bpf_task_storage_get<M, T>(
    map: *const M,
    task: *mut T,
    value: *const c_void,
    flags: u64,
) -> *mut c_void {
    thunk!(156, fn(*const M, *mut T, *const c_void, u64) -> *mut c_void)(
        map, task, value, flags,
    )
}

/// `void *bpf_sk_storage_get(struct bpf_map *map, struct sock *sk,
/// void *value, u64 flags)`. Generic over map-def and sk pointer types
/// (both mut and const sk call sites coerce); may return NULL.
#[inline(always)]
pub fn bpf_sk_storage_get<M, T>(
    map: *const M,
    sk: *const T,
    value: *const c_void,
    flags: u64,
) -> *mut c_void {
    thunk!(107, fn(*const M, *const T, *const c_void, u64) -> *mut c_void)(
        map, sk, value, flags,
    )
}

/// `long bpf_bprm_opts_set(struct linux_binprm *bprm, u64 flags)`.
#[inline(always)]
pub fn bpf_bprm_opts_set<T>(bprm: *mut T, flags: u64) -> i64 {
    thunk!(159, fn(*mut T, u64) -> i64)(bprm, flags)
}

/// `long bpf_cgrp_storage_delete(struct bpf_map *map, struct cgroup *cgroup)`.
#[inline(always)]
pub fn bpf_cgrp_storage_delete<M, C>(map: *const M, cgroup: *mut C) -> i64 {
    thunk!(211, fn(*const M, *mut C) -> i64)(map, cgroup)
}

#[inline(always)]
pub fn bpf_clone_redirect(skb: *const c_void, ifindex: u32, flags: u64) -> i64 {
    thunk!(13, fn(*const c_void, u32, u64) -> i64)(skb, ifindex, flags)
}

/// `long bpf_copy_from_user_task(void *dst, u32 size, const void *user_ptr,
/// struct task_struct *tsk, u64 flags)`. Generic over the caller's
/// `task_struct`-typed pointer, same pointee-erased-at-the-call-site
/// genericity as `bpf_task_pt_regs`.
#[inline(always)]
pub fn bpf_copy_from_user_task<T>(
    dst: *mut c_void,
    size: u32,
    user_ptr: *const c_void,
    tsk: *mut T,
    flags: u64,
) -> i64 {
    thunk!(191, fn(*mut c_void, u32, *const c_void, *mut T, u64) -> i64)(
        dst, size, user_ptr, tsk, flags,
    )
}

/// `void *bpf_dynptr_data(const struct bpf_dynptr *ptr, u64 offset, u64
/// len)`: get a pointer to the underlying dynptr data; NULL on error.
#[inline(always)]
pub fn bpf_dynptr_data(ptr: *const c_void, offset: u64, len: u64) -> *mut c_void {
    thunk!(203, fn(*const c_void, u64, u64) -> *mut c_void)(ptr, offset, len)
}

/// `long bpf_dynptr_from_mem(void *data, u64 size, u64 flags, struct bpf_dynptr *ptr)`.
/// `data` must point into a map value (e.g. a `.bss`/`.data` global).
#[inline(always)]
pub fn bpf_dynptr_from_mem(data: *mut c_void, size: u64, flags: u64, ptr: *mut c_void) -> i64 {
    thunk!(197, fn(*mut c_void, u64, u64, *mut c_void) -> i64)(data, size, flags, ptr)
}

/// `u64 bpf_get_attach_cookie(void *ctx)`: the cookie value supplied at
/// attach time (`bpf_*_opts.*_cookie`), same helper libbpf's USDT support
/// (`__bpf_usdt_spec_id`) uses to look up which `struct __bpf_usdt_spec`
/// applies at the current probe site.
#[inline(always)]
pub fn bpf_get_attach_cookie(ctx: *const c_void) -> u64 {
    thunk!(174, fn(*const c_void) -> u64)(ctx)
}

/// `long bpf_get_branch_snapshot(void *entries, u32 size, u64 flags)`.
#[inline(always)]
pub fn bpf_get_branch_snapshot(entries: *mut c_void, size: u32, flags: u64) -> i64 {
    thunk!(176, fn(*mut c_void, u32, u64) -> i64)(entries, size, flags)
}

/// `long bpf_get_func_arg(void *ctx, u32 n, u64 *value)`: reads the `n`-th
/// argument register (zero based) of the traced function into `*value`.
/// 0 on success, -EINVAL if `n` >= the traced function's argument count.
#[inline(always)]
pub fn bpf_get_func_arg(ctx: *const c_void, n: u32, value: *mut u64) -> i64 {
    thunk!(183, fn(*const c_void, u32, *mut u64) -> i64)(ctx, n, value)
}

/// `long bpf_get_func_arg_cnt(void *ctx)`: number of argument registers of
/// the traced function, for fentry/fexit programs.
#[inline(always)]
pub fn bpf_get_func_arg_cnt(ctx: *const c_void) -> i64 {
    thunk!(185, fn(*const c_void) -> i64)(ctx)
}

/// `long bpf_get_func_ret(void *ctx, u64 *value)`: reads the traced
/// function's return value into `*value`. 0 on success, -EOPNOTSUPP for
/// tracing programs other than fexit/fmod_ret.
#[inline(always)]
pub fn bpf_get_func_ret(ctx: *const c_void, value: *mut u64) -> i64 {
    thunk!(184, fn(*const c_void, *mut u64) -> i64)(ctx, value)
}

#[inline(always)]
pub fn bpf_get_ns_current_pid_tgid(dev: u64, ino: u64, nsdata: *mut c_void, size: u32) -> i64 {
    thunk!(120, fn(u64, u64, *mut c_void, u32) -> i64)(dev, ino, nsdata, size)
}

/// `long bpf_get_task_stack(struct task_struct *task, void *buf, u32 size, u64 flags)`.
/// Generic over the caller's BTF-typed `task_struct` pointer, same
/// pointee-erased-at-the-call-site genericity as `bpf_timer_init`.
#[inline(always)]
pub fn bpf_get_task_stack<T>(task: *mut T, buf: *mut c_void, size: u32, flags: u64) -> i64 {
    thunk!(141, fn(*mut T, *mut c_void, u32, u64) -> i64)(task, buf, size, flags)
}

/// `long bpf_ima_file_hash(struct file *file, void *dst, u32 size)`.
#[inline(always)]
pub fn bpf_ima_file_hash<T>(file: *mut T, dst: *mut c_void, size: u32) -> i64 {
    thunk!(193, fn(*mut T, *mut c_void, u32) -> i64)(file, dst, size)
}

/// `long bpf_ima_inode_hash(struct inode *inode, void *dst, u32 size)`.
/// Pointee-erased like the other BTF-typed-arg helpers.
#[inline(always)]
pub fn bpf_ima_inode_hash<T>(inode: *mut T, dst: *mut c_void, size: u32) -> i64 {
    thunk!(161, fn(*mut T, *mut c_void, u32) -> i64)(inode, dst, size)
}

/// `long bpf_inode_storage_delete(struct bpf_map *map, void *inode)`.
#[inline(always)]
pub fn bpf_inode_storage_delete<M, T>(map: *const M, inode: *mut T) -> i64 {
    thunk!(146, fn(*const M, *mut T) -> i64)(map, inode)
}

/// `u64 bpf_jiffies64(void)`: the kernel's `jiffies` counter (used by
/// `tcp_jiffies32` == `(u32)bpf_jiffies64()`).
#[inline(always)]
pub fn bpf_jiffies64() -> u64 {
    thunk!(118, fn() -> u64)()
}

/// `u64 bpf_ktime_get_boot_ns(void)`.
#[inline(always)]
pub fn bpf_ktime_get_boot_ns() -> u64 {
    thunk!(125, fn() -> u64)()
}

/// `void *bpf_map_lookup_percpu_elem(struct bpf_map *map, const void *key, u32 cpu)`.
/// Same pointee-erased map genericity as `bpf_map_lookup_elem`; returns the
/// per-cpu value for `cpu`, null if `cpu` is out of range.
#[inline(always)]
pub fn bpf_map_lookup_percpu_elem<M, K>(map: *const M, key: &K, cpu: u32) -> *mut c_void {
    thunk!(195, fn(*const M, *const c_void, u32) -> *mut c_void)(
        map,
        key as *const K as *const c_void,
        cpu,
    )
}

/// `bpf_map_peek_elem(map, value)`: reads the front element (queue/stack)
/// or checks membership (bloom filter) without removing it.
#[inline(always)]
pub fn bpf_map_peek_elem<M, V>(map: *const M, value: &mut V) -> i64 {
    thunk!(89, fn(*const M, *mut c_void) -> i64)(map, value as *mut V as *mut c_void)
}

/// `long bpf_msg_redirect_hash(struct sk_msg_md *msg, struct bpf_map *map, void *key, u64 flags)`.
#[inline(always)]
pub fn bpf_msg_redirect_hash<S, M, K>(msg: *const S, map: *const M, key: *const K, flags: u64) -> i64 {
    thunk!(71, fn(*const S, *const M, *const c_void, u64) -> i64)(
        msg,
        map,
        key as *const c_void,
        flags,
    )
}

/// `long bpf_msg_redirect_map(struct sk_msg_md *msg, struct bpf_map *map, u32 key, u64 flags)`.
#[inline(always)]
pub fn bpf_msg_redirect_map<S, M>(msg: *const S, map: *const M, key: u32, flags: u64) -> i64 {
    thunk!(60, fn(*const S, *const M, u32, u64) -> i64)(msg, map, key, flags)
}

/// `long bpf_perf_event_read_value(struct bpf_map *map, u64 flags, struct bpf_perf_event_value *buf, u32 buf_size)`.
#[inline(always)]
pub fn bpf_perf_event_read_value<M, T>(map: *const M, flags: u64, buf: &mut T, buf_size: u32) -> i64 {
    thunk!(55, fn(*const M, u64, *mut c_void, u32) -> i64)(
        map,
        flags,
        buf as *mut T as *mut c_void,
        buf_size,
    )
}

/// `long bpf_probe_read(void *dst, u32 size, const void *unsafe_ptr)`. The
/// original (pre kernel/user split) variant, still callable directly; kept
/// distinct from `bpf_probe_read_kernel` (both alive as separate helper IDs
/// in the UAPI).
#[inline(always)]
pub fn bpf_probe_read(dst: *mut c_void, size: u32, src: *const c_void) -> i64 {
    thunk!(4, fn(*mut c_void, u32, *const c_void) -> i64)(dst, size, src)
}

/// `long bpf_probe_read_str(void *dst, u32 size, const void *unsafe_ptr)`.
/// The original (pre kernel/user split) variant of `bpf_probe_read_kernel_str`.
#[inline(always)]
pub fn bpf_probe_read_str(dst: *mut c_void, size: u32, src: *const c_void) -> i64 {
    thunk!(45, fn(*mut c_void, u32, *const c_void) -> i64)(dst, size, src)
}

#[inline(always)]
pub fn bpf_read_branch_records(ctx: *const c_void, buf: *mut c_void, size: u32, flags: u64) -> i64 {
    thunk!(119, fn(*const c_void, *mut c_void, u32, u64) -> i64)(ctx, buf, size, flags)
}

/// `long bpf_redirect_peer(u32 ifindex, u64 flags)`.
#[inline(always)]
pub fn bpf_redirect_peer(ifindex: u32, flags: u64) -> i64 {
    thunk!(155, fn(u32, u64) -> i64)(ifindex, flags)
}

/// `void bpf_ringbuf_discard_dynptr(struct bpf_dynptr *ptr, u64 flags)`.
#[inline(always)]
pub fn bpf_ringbuf_discard_dynptr(ptr: *mut c_void, flags: u64) {
    thunk!(200, fn(*mut c_void, u64))(ptr, flags)
}

/// `long bpf_ringbuf_reserve_dynptr(void *ringbuf, u32 size, u64 flags,
/// struct bpf_dynptr *ptr)`: reserve `size` bytes in the ring buffer,
/// accessible through the dynptr interface. `flags` must be 0. Always
/// pairs with `bpf_ringbuf_submit_dynptr`/`bpf_ringbuf_discard_dynptr`.
#[inline(always)]
pub fn bpf_ringbuf_reserve_dynptr<M>(
    map: *const M,
    size: u32,
    flags: u64,
    ptr: *mut c_void,
) -> i64 {
    thunk!(198, fn(*const M, u32, u64, *mut c_void) -> i64)(map, size, flags, ptr)
}

/// `void bpf_ringbuf_submit_dynptr(struct bpf_dynptr *ptr, u64 flags)`.
#[inline(always)]
pub fn bpf_ringbuf_submit_dynptr(ptr: *mut c_void, flags: u64) {
    thunk!(199, fn(*mut c_void, u64))(ptr, flags)
}

/// `long bpf_send_signal(u32 sig)`.
#[inline(always)]
pub fn bpf_send_signal(sig: u32) -> i64 {
    thunk!(109, fn(u32) -> i64)(sig)
}

/// `long bpf_send_signal_thread(u32 sig)`.
#[inline(always)]
pub fn bpf_send_signal_thread(sig: u32) -> i64 {
    thunk!(117, fn(u32) -> i64)(sig)
}

/// `long bpf_sk_redirect_hash(struct __sk_buff *skb, struct bpf_map *map, void *key, u64 flags)`.
#[inline(always)]
pub fn bpf_sk_redirect_hash<S, M, K>(skb: *const S, map: *const M, key: *const K, flags: u64) -> i64 {
    thunk!(72, fn(*const S, *const M, *const c_void, u64) -> i64)(
        skb,
        map,
        key as *const c_void,
        flags,
    )
}

/// `long bpf_skb_change_head(struct sk_buff *skb, u32 len, u64 flags)`.
#[inline(always)]
pub fn bpf_skb_change_head(skb: *const c_void, len: u32, flags: u64) -> i64 {
    thunk!(43, fn(*const c_void, u32, u64) -> i64)(skb, len, flags)
}

/// `long bpf_skb_change_tail(struct sk_buff *skb, u32 len, u64 flags)`:
/// resize (trim or grow) the packet backing `skb` to `len`.
#[inline(always)]
pub fn bpf_skb_change_tail(skb: *const c_void, len: u32, flags: u64) -> i64 {
    thunk!(38, fn(*const c_void, u32, u64) -> i64)(skb, len, flags)
}

/// `long bpf_skb_ecn_set_ce(struct sk_buff *skb)`.
#[inline(always)]
pub fn bpf_skb_ecn_set_ce(skb: *mut c_void) -> i64 {
    thunk!(97, fn(*mut c_void) -> i64)(skb)
}

/// `long bpf_skb_get_tunnel_key(struct sk_buff *skb, struct bpf_tunnel_key *key, u32 size, u64 flags)`.
/// Generic over the caller's tunnel-key scratch struct, same
/// pointee-erased-at-the-call-site genericity as `bpf_skb_set_tunnel_key`.
#[inline(always)]
pub fn bpf_skb_get_tunnel_key<T>(skb: *const c_void, key: *mut T, size: u32, flags: u64) -> i64 {
    thunk!(20, fn(*const c_void, *mut T, u32, u64) -> i64)(skb, key, size, flags)
}

/// `long bpf_skb_get_tunnel_opt(struct sk_buff *skb, void *opt, u32 size)`.
/// Generic over the caller's tunnel-opt scratch struct.
#[inline(always)]
pub fn bpf_skb_get_tunnel_opt<T>(skb: *const c_void, opt: *mut T, size: u32) -> i64 {
    thunk!(29, fn(*const c_void, *mut T, u32) -> i64)(skb, opt, size)
}

/// `long bpf_skb_get_xfrm_state(struct sk_buff *skb, u32 index, struct bpf_xfrm_state *xfrm_state, u32 size, u64 flags)`.
/// Generic over the caller's xfrm-state scratch struct.
#[inline(always)]
pub fn bpf_skb_get_xfrm_state<T>(
    skb: *const c_void,
    index: u32,
    xfrm_state: *mut T,
    size: u32,
    flags: u64,
) -> i64 {
    thunk!(66, fn(*const c_void, u32, *mut T, u32, u64) -> i64)(skb, index, xfrm_state, size, flags)
}

/// `long bpf_skb_load_bytes_relative(const void *skb, u32 offset, void *to,
/// u32 len, u32 start_header)`: like `bpf_skb_load_bytes`, but `offset` is
/// relative to the start of the requested header (`BPF_HDR_START_MAC` or
/// `BPF_HDR_START_NET`) instead of `skb`'s current data pointer.
#[inline(always)]
pub fn bpf_skb_load_bytes_relative(
    skb: *const c_void,
    offset: u32,
    to: *mut c_void,
    len: u32,
    start_header: u32,
) -> i64 {
    thunk!(68, fn(*const c_void, u32, *mut c_void, u32, u32) -> i64)(
        skb,
        offset,
        to,
        len,
        start_header,
    )
}

/// `long bpf_skb_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)`.
/// Same shape as `bpf_perf_event_output` but for tracing programs whose
/// first argument is a `struct sk_buff *` rather than the program's own ctx.
#[inline(always)]
pub fn bpf_skb_output<M, T>(skb: *const c_void, map: *const M, flags: u64, data: &T, size: u64) -> i64 {
    thunk!(111, fn(*const c_void, *const M, u64, *const c_void, u64) -> i64)(
        skb,
        map,
        flags,
        data as *const T as *const c_void,
        size,
    )
}

/// `long bpf_skb_set_tstamp(struct sk_buff *skb, u64 tstamp, u32 tstamp_type)`.
#[inline(always)]
pub fn bpf_skb_set_tstamp(skb: *const c_void, tstamp: u64, tstamp_type: u32) -> i64 {
    thunk!(192, fn(*const c_void, u64, u32) -> i64)(skb, tstamp, tstamp_type)
}

/// `long bpf_skb_set_tunnel_key(struct sk_buff *skb, struct bpf_tunnel_key
/// *key, u32 size, u64 flags)`. Generic over the caller's
/// `bpf_tunnel_key`-shaped params struct, same pointee-erased-at-the-call-site
/// genericity as `bpf_fib_lookup`.
#[inline(always)]
pub fn bpf_skb_set_tunnel_key<T>(skb: *const c_void, key: *const T, size: u32, flags: u64) -> i64 {
    thunk!(21, fn(*const c_void, *const T, u32, u64) -> i64)(skb, key, size, flags)
}

/// `long bpf_skb_set_tunnel_opt(struct sk_buff *skb, void *opt, u32 size)`.
/// Generic over the caller's tunnel-opt scratch struct.
#[inline(always)]
pub fn bpf_skb_set_tunnel_opt<T>(skb: *const c_void, opt: *const T, size: u32) -> i64 {
    thunk!(30, fn(*const c_void, *const T, u32) -> i64)(skb, opt, size)
}

/// `long bpf_skb_vlan_pop(struct sk_buff *skb)`.
#[inline(always)]
pub fn bpf_skb_vlan_pop(skb: *const c_void) -> i64 {
    thunk!(19, fn(*const c_void) -> i64)(skb)
}

#[inline(always)]
pub fn bpf_skc_to_tcp6_sock(sk: *mut c_void) -> *mut c_void {
    thunk!(136, fn(*mut c_void) -> *mut c_void)(sk)
}

/// `struct udp6_sock *bpf_skc_to_udp6_sock(void *sk)`: BTF-ID-checked cast,
/// returns NULL if `sk` isn't actually a UDPv6 socket.
#[inline(always)]
pub fn bpf_skc_to_udp6_sock(sk: *mut c_void) -> *mut c_void {
    thunk!(140, fn(*mut c_void) -> *mut c_void)(sk)
}

#[inline(always)]
pub fn bpf_skc_to_unix_sock(sk: *mut c_void) -> *mut c_void {
    thunk!(178, fn(*mut c_void) -> *mut c_void)(sk)
}

/// `long bpf_snprintf_btf(char *str, u32 str_size, struct btf_ptr *ptr, u32 btf_ptr_size, u64 flags)`.
#[inline(always)]
pub fn bpf_snprintf_btf(
    str: *mut c_void,
    str_size: u32,
    ptr: *const c_void,
    btf_ptr_size: u32,
    flags: u64,
) -> i64 {
    thunk!(149, fn(*mut c_void, u32, *const c_void, u32, u64) -> i64)(
        str,
        str_size,
        ptr,
        btf_ptr_size,
        flags,
    )
}

/// `struct socket *bpf_sock_from_file(struct file *file)`: returns the
/// `struct socket *` owning `file`, or NULL if `file` isn't a socket file.
/// Generic over the caller's `file`-typed pointer.
#[inline(always)]
pub fn bpf_sock_from_file<T>(file: *mut T) -> *mut c_void {
    thunk!(162, fn(*mut T) -> *mut c_void)(file)
}

/// `long bpf_sys_bpf(u32 cmd, void *attr, u32 attr_size)`. SEC("syscall")
/// programs only.
#[inline(always)]
pub fn bpf_sys_bpf(cmd: u32, attr: *mut c_void, attr_size: u32) -> i64 {
    thunk!(166, fn(u32, *mut c_void, u32) -> i64)(cmd, attr, attr_size)
}

/// `long bpf_sys_close(u32 fd)`. SEC("syscall") programs only.
#[inline(always)]
pub fn bpf_sys_close(fd: u32) -> i64 {
    thunk!(168, fn(u32) -> i64)(fd)
}

/// `long bpf_sysctl_get_current_value(struct bpf_sysctl *ctx, char *buf,
/// size_t buf_len)`: copy the sysctl's current value into `buf`. Generic
/// over the caller's `bpf_sysctl`-typed ctx pointer.
#[inline(always)]
pub fn bpf_sysctl_get_current_value<C>(ctx: *mut C, buf: *mut c_void, buf_len: u64) -> i64 {
    thunk!(102, fn(*mut C, *mut c_void, u64) -> i64)(ctx, buf, buf_len)
}

/// `long bpf_sysctl_get_name(struct bpf_sysctl *ctx, char *buf, size_t
/// buf_len, u64 flags)`: copy the sysctl's name into `buf`. Generic over
/// the caller's `bpf_sysctl`-typed ctx pointer.
#[inline(always)]
pub fn bpf_sysctl_get_name<C>(ctx: *mut C, buf: *mut c_void, buf_len: u64, flags: u64) -> i64 {
    thunk!(101, fn(*mut C, *mut c_void, u64, u64) -> i64)(ctx, buf, buf_len, flags)
}

/// `long bpf_task_storage_delete(struct bpf_map *map, struct task_struct *task)`.
/// Generic over the caller's map-def type and `task_struct`-named ctx type,
/// same pointee-erased genericity as `bpf_task_storage_get`.
#[inline(always)]
pub fn bpf_task_storage_delete<M, T>(map: *const M, task: *mut T) -> i64 {
    thunk!(157, fn(*const M, *mut T) -> i64)(map, task)
}

/// `s64 bpf_tcp_gen_syncookie(void *sk, void *iph, u32 iph_len, struct tcphdr *th, u32 th_len)`.
#[inline(always)]
pub fn bpf_tcp_gen_syncookie<S, I, T>(
    sk: *mut S,
    iph: *const I,
    iph_len: u32,
    th: *const T,
    th_len: u32,
) -> i64 {
    thunk!(110, fn(*mut S, *const I, u32, *const T, u32) -> i64)(sk, iph, iph_len, th, th_len)
}

/// `long bpf_tcp_send_ack(void *tp, u32 rcv_nxt)`.
/// Generic over the caller's `tcp_sock`-shaped pointer, same
/// pointee-erased-at-the-call-site genericity as `bpf_setsockopt`.
#[inline(always)]
pub fn bpf_tcp_send_ack<T>(tp: *mut T, rcv_nxt: u32) -> i64 {
    thunk!(116, fn(*mut T, u32) -> i64)(tp, rcv_nxt)
}

/// `bpf_timer_cancel(timer)`: cancels a running timer, returning 0 on
/// success, -EINVAL if not initialized, -EDEADLK if called from the
/// timer's own callback (or one that would deadlock on its lock).
#[inline(always)]
pub fn bpf_timer_cancel<T>(timer: *mut T) -> i64 {
    thunk!(172, fn(*mut T) -> i64)(timer)
}

/// `long bpf_trace_printk(const char *fmt, u32 fmt_size, u64 arg1)`.
#[inline(always)]
pub fn bpf_trace_printk1(fmt: *const c_void, fmt_size: u32, arg1: u64) -> i64 {
    thunk!(6, fn(*const c_void, u32, u64) -> i64)(fmt, fmt_size, arg1)
}

/// `long bpf_user_ringbuf_drain(struct bpf_map *map, void *callback_fn, void
/// *ctx, u64 flags)`. Same fn-pointer-as-BPF_PSEUDO_FUNC mechanism as
/// `bpf_loop`; the callback signature mirrors the kernel's `long
/// (*callback_fn)(const struct bpf_dynptr *dynptr, void *ctx)`.
#[inline(always)]
pub fn bpf_user_ringbuf_drain<M, C>(
    map: *const M,
    callback_fn: extern "C" fn(*mut c_void, *mut C) -> i64,
    callback_ctx: *mut C,
    flags: u64,
) -> i64 {
    thunk!(209, fn(*const M, extern "C" fn(*mut c_void, *mut C) -> i64, *mut C, u64) -> i64)(
        map,
        callback_fn,
        callback_ctx,
        flags,
    )
}

/// `long bpf_xdp_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)`.
#[inline(always)]
pub fn bpf_xdp_output<X, M, T>(ctx: *const X, map: *const M, flags: u64, data: &T, size: u64) -> i64 {
    thunk!(121, fn(*const X, *const M, u64, *const c_void, u64) -> i64)(
        ctx,
        map,
        flags,
        data as *const T as *const c_void,
        size,
    )
}

/// __sync_fetch_and_add on a plain signed `int`/`__s32` global: same
/// atomic-view-punned-at-the-call-site idea as `sync_fetch_and_add_u32`, but
/// signed so a negative delta (e.g. `__sync_fetch_and_add(&in_use, -1)`)
/// matches C semantics bit-for-bit.
#[inline(always)]
pub fn sync_fetch_and_add_i32(p: *mut i32, v: i32) {
    use core::sync::atomic::{AtomicI32, Ordering};
    unsafe { (*(p as *mut AtomicI32)).fetch_add(v, Ordering::SeqCst) };
}

/// `long bpf_dynptr_read(void *dst, u64 len, const struct bpf_dynptr *src, u64 offset, u64 flags)`.
#[inline(always)]
pub fn bpf_dynptr_read<D>(dst: *mut c_void, len: u64, src: *const D, offset: u64, flags: u64) -> i64 {
    thunk!(201, fn(*mut c_void, u64, *const D, u64, u64) -> i64)(dst, len, src, offset, flags)
}

/// `long bpf_dynptr_write(const struct bpf_dynptr *dst, u64 offset, void *src, u64 len, u64 flags)`.
#[inline(always)]
pub fn bpf_dynptr_write<D>(dst: *const D, offset: u64, src: *mut c_void, len: u64, flags: u64) -> i64 {
    thunk!(202, fn(*const D, u64, *mut c_void, u64, u64) -> i64)(dst, offset, src, len, flags)
}

/// `u64 bpf_get_netns_cookie(void *ctx)`: the cookie (generated by the
/// kernel) of the network namespace `ctx` is associated with; `ctx` may be
/// NULL to get the cookie for the init namespace. Generic over the caller's
/// ctx pointer type.
#[inline(always)]
pub fn bpf_get_netns_cookie<T>(ctx: *const T) -> u64 {
    thunk!(122, fn(*const T) -> u64)(ctx)
}

/// `u64 bpf_get_socket_cookie(struct sock *sk)` (the `bpf_get_socket_ptr_cookie`
/// overload used by tracing/iter program types: `ARG_PTR_TO_BTF_ID_SOCK_COMMON`,
/// so any trusted `sock`/`sock_common`-rooted pointer is accepted). Generic
/// over the caller's socket pointee type, same pointee-erased genericity as
/// `bpf_map_lookup_elem`.
#[inline(always)]
pub fn bpf_get_socket_cookie<T>(sk: *const T) -> u64 {
    thunk!(46, fn(*const c_void) -> u64)(sk as *const c_void)
}

/// `void *bpf_inode_storage_get(struct bpf_map *map, struct inode *inode, void *value, u64 flags)`.
/// Generic over the caller's map-def type and `inode`-named ctx type, same
/// pointee-erased genericity as `bpf_task_storage_get`. Returns null on
/// failure — caller must check.
#[inline(always)]
pub fn bpf_inode_storage_get<M, T>(
    map: *const M,
    inode: *mut T,
    value: *const c_void,
    flags: u64,
) -> *mut c_void {
    thunk!(145, fn(*const M, *mut T, *const c_void, u64) -> *mut c_void)(map, inode, value, flags)
}

/// `long bpf_load_hdr_opt(struct bpf_sock_ops *skops, void *searchby_res,
/// u32 len, u64 flags)`: search for a TCP header option. Generic over the
/// caller's `bpf_sock_ops`-typed ctx pointer, same genericity as
/// `bpf_sock_ops_cb_flags_set`.
#[inline(always)]
pub fn bpf_load_hdr_opt<C>(skops: *mut C, searchby_res: *mut c_void, len: u32, flags: u64) -> i64 {
    thunk!(142, fn(*mut C, *mut c_void, u32, u64) -> i64)(skops, searchby_res, len, flags)
}

/// `long bpf_reserve_hdr_opt(struct bpf_sock_ops *skops, u32 len, u64
/// flags)`: reserve space for a TCP header option to be written later via
/// `bpf_store_hdr_opt`. Generic over the caller's `bpf_sock_ops`-typed ctx
/// pointer, same genericity as `bpf_sock_ops_cb_flags_set`.
#[inline(always)]
pub fn bpf_reserve_hdr_opt<C>(skops: *mut C, len: u32, flags: u64) -> i64 {
    thunk!(144, fn(*mut C, u32, u64) -> i64)(skops, len, flags)
}

/// `struct bpf_sock *bpf_sk_fullsock(struct bpf_sock *sk)`: upgrades a
/// `sock_common` pointer (e.g. `skb->sk`) to a full `struct sock` view;
/// NULL if `sk` isn't a full socket. Generic over the caller's
/// `bpf_sock`-typed pointer, same pointee-erased-at-the-call-site
/// genericity as `bpf_sk_storage_get`.
#[inline(always)]
pub fn bpf_sk_fullsock(sk: *const c_void) -> *mut c_void {
    thunk!(95, fn(*const c_void) -> *mut c_void)(sk)
}

/// `long bpf_sk_redirect_map(struct __sk_buff *skb, struct bpf_map *map, u32 key, u64 flags)`.
#[inline(always)]
pub fn bpf_sk_redirect_map<S, M>(skb: *const S, map: *const M, key: u32, flags: u64) -> i64 {
    thunk!(52, fn(*const S, *const M, u32, u64) -> i64)(skb, map, key, flags)
}

/// `long bpf_sk_select_reuseport(struct sk_reuseport_md *reuse, struct
/// bpf_map *map, void *key, u64 flags)`: picks the listening socket at
/// `*key` in the reuseport-sockarray/sockmap/sockhash `map` to receive
/// this packet. Generic over the caller's ctx and map-def types.
#[inline(always)]
pub fn bpf_sk_select_reuseport<C, M, K>(
    reuse: *const C,
    map: *const M,
    key: &K,
    flags: u64,
) -> i64 {
    thunk!(82, fn(*const C, *const M, *const c_void, u64) -> i64)(
        reuse,
        map,
        key as *const K as *const c_void,
        flags,
    )
}

/// `long bpf_sk_storage_delete(struct bpf_map *map, void *sk)`. Generic
/// over the map-def type and the caller's `sock`-typed pointer, same
/// pointee-erased-at-the-call-site genericity as `bpf_sk_storage_get`.
#[inline(always)]
pub fn bpf_sk_storage_delete<M, T>(map: *const M, sk: *mut T) -> i64 {
    thunk!(108, fn(*const M, *mut T) -> i64)(map, sk)
}

/// `long bpf_skb_vlan_push(struct sk_buff *skb, __be16 vlan_proto, u16 vlan_tci)`.
#[inline(always)]
pub fn bpf_skb_vlan_push<C>(skb: *mut C, vlan_proto: u16, vlan_tci: u16) -> i64 {
    thunk!(18, fn(*mut C, u16, u16) -> i64)(skb, vlan_proto, vlan_tci)
}

/// `struct mptcp_sock *bpf_skc_to_mptcp_sock(void *sk)`. Generic over the
/// caller's `mptcp_sock`-named target type. Returns null on failure.
#[inline(always)]
pub fn bpf_skc_to_mptcp_sock(sk: *const c_void) -> *mut c_void {
    thunk!(196, fn(*const c_void) -> *mut c_void)(sk)
}

/// `struct tcp_request_sock *bpf_skc_to_tcp_request_sock(void *sk)`:
/// BTF-ID-checked cast, returns NULL if `sk` isn't a TCP request socket.
#[inline(always)]
pub fn bpf_skc_to_tcp_request_sock(sk: *const c_void) -> *mut c_void {
    thunk!(139, fn(*const c_void) -> *mut c_void)(sk)
}

/// `struct tcp_sock *bpf_skc_to_tcp_sock(struct sock *sk)`: BTF-ID-checked
/// cast, returns NULL if `sk` isn't actually a TCP socket.
#[inline(always)]
pub fn bpf_skc_to_tcp_sock(sk: *const c_void) -> *mut c_void {
    thunk!(137, fn(*const c_void) -> *mut c_void)(sk)
}

/// `struct tcp_timewait_sock *bpf_skc_to_tcp_timewait_sock(void *sk)`.
/// Generic over the caller's `tcp_timewait_sock`-named target type. Returns
/// null on failure.
#[inline(always)]
pub fn bpf_skc_to_tcp_timewait_sock(sk: *const c_void) -> *mut c_void {
    thunk!(138, fn(*const c_void) -> *mut c_void)(sk)
}

/// `long bpf_sock_map_update(struct bpf_sock_ops *skops, struct bpf_map *map, void *key, u64 flags)`.
#[inline(always)]
pub fn bpf_sock_map_update<C, M, K>(skops: *mut C, map: *const M, key: *const K, flags: u64) -> i64 {
    thunk!(53, fn(*mut C, *const M, *const K, u64) -> i64)(skops, map, key, flags)
}

/// `long bpf_sock_ops_cb_flags_set(struct bpf_sock_ops *bpf_sock, int argval)`.
/// Generic over the caller's `bpf_sock_ops`-shaped ctx pointer, same
/// pointee-erased-at-the-call-site genericity as `bpf_setsockopt`.
#[inline(always)]
pub fn bpf_sock_ops_cb_flags_set<C>(bpf_sock: *mut C, argval: i32) -> i64 {
    thunk!(59, fn(*mut C, i32) -> i64)(bpf_sock, argval)
}

/// `long bpf_store_hdr_opt(struct bpf_sock_ops *skops, const void *from,
/// u32 len, u64 flags)`: write a TCP header option previously reserved via
/// `bpf_reserve_hdr_opt`. Generic over the caller's `bpf_sock_ops`-typed
/// ctx pointer, same genericity as `bpf_sock_ops_cb_flags_set`.
#[inline(always)]
pub fn bpf_store_hdr_opt<C>(skops: *mut C, from: *const c_void, len: u32, flags: u64) -> i64 {
    thunk!(143, fn(*mut C, *const c_void, u32, u64) -> i64)(skops, from, len, flags)
}

/// `long bpf_strtoul(const char *buf, size_t buf_len, u64 flags, unsigned
/// long *res)`: parse `buf` as an unsigned integer, writing the result
/// through `res`.
#[inline(always)]
pub fn bpf_strtoul(buf: *const c_void, buf_len: u64, flags: u64, res: *mut c_void) -> i64 {
    thunk!(106, fn(*const c_void, u64, u64, *mut c_void) -> i64)(buf, buf_len, flags, res)
}

/// `struct bpf_tcp_sock *bpf_tcp_sock(struct bpf_sock *sk)`.
#[inline(always)]
pub fn bpf_tcp_sock(sk: *const c_void) -> *mut c_void {
    thunk!(96, fn(*const c_void) -> *mut c_void)(sk)
}

/// `long bpf_xdp_adjust_head(struct xdp_md *xdp_md, int delta)`. Generic
/// over the caller's `xdp_md`-typed ctx pointer.
#[inline(always)]
pub fn bpf_xdp_adjust_head<C>(xdp: *mut C, delta: i32) -> i64 {
    thunk!(44, fn(*mut C, i32) -> i64)(xdp, delta)
}

/// `long bpf_xdp_adjust_tail(struct xdp_md *xdp_md, int delta)`. Generic
/// over the caller's `xdp_md`-typed ctx pointer.
#[inline(always)]
pub fn bpf_xdp_adjust_tail<C>(xdp: *mut C, delta: i32) -> i64 {
    thunk!(65, fn(*mut C, i32) -> i64)(xdp, delta)
}

/// `u64 bpf_xdp_get_buff_len(struct xdp_md *xdp_md)`.
#[inline(always)]
pub fn bpf_xdp_get_buff_len<X>(xdp_md: *const X) -> u64 {
    thunk!(188, fn(*const X) -> u64)(xdp_md)
}

/// `long bpf_xdp_load_bytes(struct xdp_buff *xdp_md, u32 offset, void *buf, u32 len)`.
#[inline(always)]
pub fn bpf_xdp_load_bytes<T>(xdp: *mut T, offset: u32, buf: *mut c_void, len: u32) -> i64 {
    thunk!(189, fn(*mut T, u32, *mut c_void, u32) -> i64)(xdp, offset, buf, len)
}

/// `long bpf_xdp_store_bytes(struct xdp_md *xdp_md, u32 offset, void *buf,
/// u32 len)`. Generic over the caller's `xdp_md`-typed ctx pointer.
#[inline(always)]
pub fn bpf_xdp_store_bytes<C>(xdp: *mut C, offset: u32, buf: *const c_void, len: u32) -> i64 {
    thunk!(190, fn(*mut C, u32, *const c_void, u32) -> i64)(xdp, offset, buf, len)
}
