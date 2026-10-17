// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_sockmap_mutate.c, translated
// by hand; include!d by the generated progs/verifier_sockmap_mutate.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use btf_macros::btf;
use bpf_rs_core::helpers::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem_ptr, bpf_sk_release, bpf_sock_map_update};

/// bpf_sock_hash_update (helper 70).
#[inline(always)]
fn bpf_sock_hash_update<C, M, K>(skops: *mut C, map: *const M, key: *const K, flags: u64) -> i64 {
    let f: extern "C" fn(*mut C, *const M, *const K, u64) -> i64 = unsafe { core::mem::transmute(70usize) };
    f(skops, map, key, flags)
}

// The C's own `struct bpf_iter__sockmap { union { struct sock *sk; }; }`
// with preserve_access_index: sk is found in the kernel's type by name
// (CO-RE), at its real offset, so the view is a #[btf] one.
// GEN_SKIP_TYPE: bpf_iter__sockmap
#[allow(non_camel_case_types)]
#[btf]
struct sock {}

#[allow(non_camel_case_types)]
#[btf]
struct bpf_iter__sockmap {
    sk: *mut sock,
}

const BPF_ANY: u64 = 0;
const CG_OK: i32 = 1;
const XDP_PASS: i32 = 2;

// The C's always_inline helpers.
#[inline(always)]
fn test_sockmap_delete() {
    unsafe {
        bpf_map_delete_elem(&sockmap, &*core::ptr::addr_of!(zero));
        bpf_map_delete_elem(&sockhash, &*core::ptr::addr_of!(zero));
    }
}

#[inline(always)]
fn test_sockmap_update(sk: *mut c_void) {
    if !sk.is_null() {
        unsafe {
            bpf_map_update_elem_ptr(&sockmap, &*core::ptr::addr_of!(zero), sk, BPF_ANY);
            bpf_map_update_elem_ptr(&sockhash, &*core::ptr::addr_of!(zero), sk, BPF_ANY);
        }
    }
}

#[inline(always)]
fn test_sockmap_lookup_and_update() {
    let sk = bpf_map_lookup_elem(&sockmap, unsafe { &*core::ptr::addr_of!(zero) });
    if !sk.is_null() {
        test_sockmap_update(sk);
        bpf_sk_release(sk);
    }
}

#[inline(always)]
fn test_sockmap_mutate(sk: *mut c_void) {
    test_sockmap_delete();
    test_sockmap_update(sk);
}

#[inline(always)]
fn test_sockmap_lookup_and_mutate() {
    test_sockmap_delete();
    test_sockmap_lookup_and_update();
}

// HAND: test_sched_act -- translate the C below (see the file comment)
//   SEC("action")
//   __failure __msg("cannot update sockmap in this context")
//   int test_sched_act(struct __sk_buff *skb)
//   {
//       test_sockmap_mutate(skb->sk);
//       return 0;
//   }
#[link_section = "action"]
#[no_mangle]
extern "C" fn test_sched_act(ctx: *mut __sk_buff) -> i32 {
    test_sockmap_mutate(unsafe { (*ctx).__anon30.sk });
    0
}

// HAND: test_sched_cls -- translate the C below (see the file comment)
//   SEC("classifier")
//   __failure __msg("cannot update sockmap in this context")
//   int test_sched_cls(struct __sk_buff *skb)
//   {
//       test_sockmap_mutate(skb->sk);
//       return 0;
//   }
#[link_section = "classifier"]
#[no_mangle]
extern "C" fn test_sched_cls(ctx: *mut __sk_buff) -> i32 {
    test_sockmap_mutate(unsafe { (*ctx).__anon30.sk });
    0
}

// HAND: test_flow_dissector_delete -- translate the C below (see the file comment)
//   SEC("flow_dissector")
//   __failure __msg("cannot update sockmap in this context")
//   int test_flow_dissector_delete(struct __sk_buff *skb __always_unused)
//   {
//       test_sockmap_delete();
//       return 0;
//   }
#[link_section = "flow_dissector"]
#[no_mangle]
extern "C" fn test_flow_dissector_delete(ctx: *mut __sk_buff) -> i32 {
    let _ = ctx;
    test_sockmap_delete();
    0
}

// HAND: test_flow_dissector_update -- translate the C below (see the file comment)
//   SEC("flow_dissector")
//   __failure __msg("cannot update sockmap in this context")
//   int test_flow_dissector_update(struct __sk_buff *skb __always_unused)
//   {
//       test_sockmap_lookup_and_update(); /* no access to skb->sk */
//       return 0;
//   }
#[link_section = "flow_dissector"]
#[no_mangle]
extern "C" fn test_flow_dissector_update(ctx: *mut __sk_buff) -> i32 {
    let _ = ctx;
    test_sockmap_lookup_and_update(); // no access to skb->sk
    0
}

// HAND: test_trace_iter -- translate the C below (see the file comment)
//   SEC("iter/sockmap")
//   __success
//   int test_trace_iter(struct bpf_iter__sockmap *ctx)
//   {
//       test_sockmap_mutate(ctx->sk);
//       return 0;
//   }
#[link_section = "iter/sockmap"]
#[no_mangle]
extern "C" fn test_trace_iter(ctx: *mut bpf_iter__sockmap) -> i32 {
    test_sockmap_mutate(*unsafe { &*ctx }.sk().get().unwrap() as *mut c_void);
    0
}

// HAND: test_raw_tp_delete -- translate the C below (see the file comment)
//   SEC("raw_tp/kfree")
//   __failure __msg("cannot update sockmap in this context")
//   int test_raw_tp_delete(const void *ctx __always_unused)
//   {
//       test_sockmap_delete();
//       return 0;
//   }
#[link_section = "raw_tp/kfree"]
#[no_mangle]
extern "C" fn test_raw_tp_delete(ctx: *mut c_void) -> i32 {
    let _ = ctx;
    test_sockmap_delete();
    0
}

// HAND: test_raw_tp_update -- translate the C below (see the file comment)
//   SEC("raw_tp/kfree")
//   __failure __msg("cannot update sockmap in this context")
//   int test_raw_tp_update(const void *ctx __always_unused)
//   {
//       test_sockmap_lookup_and_update();
//       return 0;
//   }
#[link_section = "raw_tp/kfree"]
#[no_mangle]
extern "C" fn test_raw_tp_update(ctx: *mut c_void) -> i32 {
    let _ = ctx;
    test_sockmap_lookup_and_update();
    0
}

// HAND: test_sk_lookup -- translate the C below (see the file comment)
//   SEC("sk_lookup")
//   __success
//   int test_sk_lookup(struct bpf_sk_lookup *ctx)
//   {
//       test_sockmap_mutate(ctx->sk);
//       return 0;
//   }
#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn test_sk_lookup(ctx: *mut bpf_sk_lookup) -> i32 {
    test_sockmap_mutate(unsafe { (*ctx).__anon0.__anon0.sk });
    0
}

// HAND: test_sk_reuseport -- translate the C below (see the file comment)
//   SEC("sk_reuseport")
//   __success
//   int test_sk_reuseport(struct sk_reuseport_md *ctx)
//   {
//       test_sockmap_mutate(ctx->sk);
//       return 0;
//   }
#[link_section = "sk_reuseport"]
#[no_mangle]
extern "C" fn test_sk_reuseport(ctx: *mut sk_reuseport_md) -> i32 {
    test_sockmap_mutate(unsafe { (*ctx).__anon7.sk });
    0
}

// HAND: test_socket_filter -- translate the C below (see the file comment)
//   SEC("socket")
//   __failure __msg("cannot update sockmap in this context")
//   int test_socket_filter(struct __sk_buff *skb)
//   {
//       test_sockmap_mutate(skb->sk);
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn test_socket_filter(ctx: *mut __sk_buff) -> i32 {
    test_sockmap_mutate(unsafe { (*ctx).__anon30.sk });
    0
}

// HAND: test_sockops_delete -- translate the C below (see the file comment)
//   SEC("sockops")
//   __success
//   int test_sockops_delete(struct bpf_sock_ops *ctx __always_unused)
//   {
//       test_sockmap_delete();
//       return CG_OK;
//   }
#[link_section = "sockops"]
#[no_mangle]
extern "C" fn test_sockops_delete(ctx: *mut bpf_sock_ops) -> i32 {
    let _ = ctx;
    test_sockmap_delete();
    CG_OK
}

// HAND: test_sockops_update -- translate the C below (see the file comment)
//   SEC("sockops")
//   __failure __msg("cannot update sockmap in this context")
//   int test_sockops_update(struct bpf_sock_ops *ctx)
//   {
//       test_sockmap_update(ctx->sk);
//       return CG_OK;
//   }
#[link_section = "sockops"]
#[no_mangle]
extern "C" fn test_sockops_update(ctx: *mut bpf_sock_ops) -> i32 {
    test_sockmap_update(unsafe { (*ctx).__anon35.sk });
    CG_OK
}

// HAND: test_sockops_update_dedicated -- translate the C below (see the file comment)
//   SEC("sockops")
//   __success
//   int test_sockops_update_dedicated(struct bpf_sock_ops *ctx)
//   {
//       bpf_sock_map_update(ctx, &sockmap, &zero, BPF_ANY);
//       bpf_sock_hash_update(ctx, &sockhash, &zero, BPF_ANY);
//       return CG_OK;
//   }
#[link_section = "sockops"]
#[no_mangle]
extern "C" fn test_sockops_update_dedicated(ctx: *mut bpf_sock_ops) -> i32 {
    bpf_sock_map_update(ctx, &sockmap, core::ptr::addr_of!(zero), BPF_ANY);
    bpf_sock_hash_update(ctx, &sockhash, core::ptr::addr_of!(zero), BPF_ANY);
    CG_OK
}

// HAND: test_xdp -- translate the C below (see the file comment)
//   SEC("xdp")
//   __failure __msg("cannot update sockmap in this context")
//   int test_xdp(struct xdp_md *ctx __always_unused)
//   {
//       test_sockmap_lookup_and_mutate();
//       return XDP_PASS;
//   }
#[link_section = "xdp"]
#[no_mangle]
extern "C" fn test_xdp(ctx: *mut xdp_md) -> i32 {
    let _ = ctx;
    test_sockmap_lookup_and_mutate();
    XDP_PASS
}
