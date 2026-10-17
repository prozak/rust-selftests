// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_sock.c, translated
// by hand; include!d by the generated progs/verifier_sock.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::bpf_skb_pull_data;

const TCX_PASS: i32 = 0;
const TCX_DROP: i32 = 2;
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

// HAND: skb_pull_data2 -- translate the C below (see the file comment)
//   __noinline
//   long skb_pull_data2(struct __sk_buff *sk, __u32 len)
//   {
//       return bpf_skb_pull_data(sk, len);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn skb_pull_data2(sk: *mut __sk_buff, len: u32) -> i64 {
    bpf_skb_pull_data(sk as *const c_void, len)
}

// HAND: skb_pull_data1 -- translate the C below (see the file comment)
//   __noinline
//   long skb_pull_data1(struct __sk_buff *sk, __u32 len)
//   {
//       return skb_pull_data2(sk, len);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn skb_pull_data1(sk: *mut __sk_buff, len: u32) -> i64 {
    skb_pull_data2(sk, len)
}

// HAND: invalidate_pkt_pointers_from_global_func -- translate the C below (see the file comment)
//   /* global function calls bpf_skb_pull_data(), which invalidates packet
//    * pointers established before global function call.
//    */
//   SEC("tc")
//   __failure __msg("invalid mem access")
//   int invalidate_pkt_pointers_from_global_func(struct __sk_buff *sk)
//   {
//       int *p = (void *)(long)sk->data;
//
//       if ((void *)(p + 1) > (void *)(long)sk->data_end)
//           return TCX_DROP;
//       skb_pull_data1(sk, 0);
//       *p = 42; /* this is unsafe */
//       return TCX_PASS;
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn invalidate_pkt_pointers_from_global_func(sk: *mut __sk_buff) -> i32 {
    let p = unsafe { (*sk).data } as usize as *mut i32;
    if unsafe { p.add(1) } as usize > unsafe { (*sk).data_end } as usize {
        return TCX_DROP;
    }
    skb_pull_data1(sk, 0);
    unsafe { *p = 42 }; // this is unsafe
    TCX_PASS
}

// HAND: xdp_pull_data2 -- translate the C below (see the file comment)
//   __noinline
//   long xdp_pull_data2(struct xdp_md *x, __u32 len)
//   {
//       return bpf_xdp_pull_data(x, len);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn xdp_pull_data2(x: *mut xdp_md, len: u32) -> i64 {
    unsafe { bpf_xdp_pull_data(x as *mut c_void, len) as i64 }
}

// HAND: xdp_pull_data1 -- translate the C below (see the file comment)
//   __noinline
//   long xdp_pull_data1(struct xdp_md *x, __u32 len)
//   {
//       return xdp_pull_data2(x, len);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn xdp_pull_data1(x: *mut xdp_md, len: u32) -> i64 {
    xdp_pull_data2(x, len)
}

// HAND: invalidate_xdp_pkt_pointers_from_global_func -- translate the C below (see the file comment)
//   /* global function calls bpf_xdp_pull_data(), which invalidates packet
//    * pointers established before global function call.
//    */
//   SEC("xdp")
//   __failure __msg("invalid mem access")
//   int invalidate_xdp_pkt_pointers_from_global_func(struct xdp_md *x)
//   {
//       int *p = (void *)(long)x->data;
//
//       if ((void *)(p + 1) > (void *)(long)x->data_end)
//           return XDP_DROP;
//       xdp_pull_data1(x, 0);
//       *p = 42; /* this is unsafe */
//       return XDP_PASS;
//   }
#[link_section = "xdp"]
#[no_mangle]
extern "C" fn invalidate_xdp_pkt_pointers_from_global_func(x: *mut xdp_md) -> i32 {
    let p = unsafe { (*x).data } as usize as *mut i32;
    if unsafe { p.add(1) } as usize > unsafe { (*x).data_end } as usize {
        return XDP_DROP;
    }
    xdp_pull_data1(x, 0);
    unsafe { *p = 42 }; // this is unsafe
    XDP_PASS
}

// HAND: invalidate_xdp_pkt_pointers -- translate the C below (see the file comment)
//   /* XDP packet changing kfunc calls invalidate packet pointers */
//   SEC("xdp")
//   __failure __msg("invalid mem access")
//   int invalidate_xdp_pkt_pointers(struct xdp_md *x)
//   {
//       int *p = (void *)(long)x->data;
//
//       if ((void *)(p + 1) > (void *)(long)x->data_end)
//           return XDP_DROP;
//       bpf_xdp_pull_data(x, 0);
//       *p = 42; /* this is unsafe */
//       return XDP_PASS;
//   }
#[link_section = "xdp"]
#[no_mangle]
extern "C" fn invalidate_xdp_pkt_pointers(x: *mut xdp_md) -> i32 {
    let p = unsafe { (*x).data } as usize as *mut i32;
    if unsafe { p.add(1) } as usize > unsafe { (*x).data_end } as usize {
        return XDP_DROP;
    }
    unsafe { bpf_xdp_pull_data(x as *mut c_void, 0) };
    unsafe { *p = 42 }; // this is unsafe
    XDP_PASS
}

// HAND: tail_call -- translate the C below (see the file comment)
//   __noinline
//   int tail_call(struct __sk_buff *sk)
//   {
//       bpf_tail_call_static(sk, &jmp_table, 0);
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn tail_call(sk: *mut __sk_buff) -> i32 {
    unsafe {
        // bpf_tail_call_static(sk, &jmp_table, 0): bpf_helpers.h's asm
        core::arch::asm!(
            "r1 = {sk};",
            "r2 = {jmp_table} ll;",
            "r3 = 0;",
            "call 12;",
            sk = in(reg) sk,
            jmp_table = sym jmp_table,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _, out("r4") _, out("r5") _,
            options(nostack)
        );
    }
    0
}

// HAND: static_tail_call -- translate the C below (see the file comment)
//   static __noinline
//   int static_tail_call(struct __sk_buff *sk)
//   {
//       int ret = 0;
//
//       bpf_tail_call_static(sk, &jmp_table, 0);
//       barrier_var(ret);
//       return ret;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn static_tail_call(sk: *mut __sk_buff) -> i32 {
    let mut ret: i32 = 0;
    unsafe {
        // bpf_tail_call_static(sk, &jmp_table, 0): bpf_helpers.h's asm
        core::arch::asm!(
            "r1 = {sk};",
            "r2 = {jmp_table} ll;",
            "r3 = 0;",
            "call 12;",
            sk = in(reg) sk,
            jmp_table = sym jmp_table,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _, out("r4") _, out("r5") _,
            options(nostack)
        );
        // barrier_var(ret)
        core::arch::asm!("{0} = {0}", inout(reg) ret, options(nostack, preserves_flags));
    }
    ret
}

// HAND: invalidate_pkt_pointers_by_global_tail_call -- translate the C below (see the file comment)
//   /* Tail calls in sub-programs invalidate packet pointers. */
//   SEC("tc")
//   __failure __msg("invalid mem access")
//   int invalidate_pkt_pointers_by_global_tail_call(struct __sk_buff *sk)
//   {
//       int *p = (void *)(long)sk->data;
//
//       if ((void *)(p + 1) > (void *)(long)sk->data_end)
//           return TCX_DROP;
//       tail_call(sk);
//       *p = 42; /* this is unsafe */
//       return TCX_PASS;
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn invalidate_pkt_pointers_by_global_tail_call(sk: *mut __sk_buff) -> i32 {
    let p = unsafe { (*sk).data } as usize as *mut i32;
    if unsafe { p.add(1) } as usize > unsafe { (*sk).data_end } as usize {
        return TCX_DROP;
    }
    tail_call(sk);
    unsafe { *p = 42 }; // this is unsafe
    TCX_PASS
}

// HAND: invalidate_pkt_pointers_by_static_tail_call -- translate the C below (see the file comment)
//   /* Tail calls in static sub-programs invalidate packet pointers. */
//   SEC("tc")
//   __failure __msg("invalid mem access")
//   int invalidate_pkt_pointers_by_static_tail_call(struct __sk_buff *sk)
//   {
//       int *p = (void *)(long)sk->data;
//       int ret;
//
//       if ((void *)(p + 1) > (void *)(long)sk->data_end)
//           return TCX_DROP;
//       ret = static_tail_call(sk);
//       __sink(ret);
//       *p = 42; /* this is unsafe */
//       return TCX_PASS;
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn invalidate_pkt_pointers_by_static_tail_call(sk: *mut __sk_buff) -> i32 {
    let p = unsafe { (*sk).data } as usize as *mut i32;
    if unsafe { p.add(1) } as usize > unsafe { (*sk).data_end } as usize {
        return TCX_DROP;
    }
    let ret = static_tail_call(sk);
    // __sink(ret)
    unsafe { core::arch::asm!("{0} = {0}", inout(reg) ret => _, options(nostack, preserves_flags)) };
    unsafe { *p = 42 }; // this is unsafe
    TCX_PASS
}

// HAND: invalidate_pkt_pointers_by_tail_call -- translate the C below (see the file comment)
//   /* Direct tail calls do not invalidate packet pointers. */
//   SEC("tc")
//   __success
//   int invalidate_pkt_pointers_by_tail_call(struct __sk_buff *sk)
//   {
//       int *p = (void *)(long)sk->data;
//
//       if ((void *)(p + 1) > (void *)(long)sk->data_end)
//           return TCX_DROP;
//       bpf_tail_call_static(sk, &jmp_table, 0);
//       *p = 42; /* this is NOT unsafe: tail calls don't return */
//       return TCX_PASS;
//   }
#[link_section = "tc"]
#[no_mangle]
extern "C" fn invalidate_pkt_pointers_by_tail_call(sk: *mut __sk_buff) -> i32 {
    let p = unsafe { (*sk).data } as usize as *mut i32;
    if unsafe { p.add(1) } as usize > unsafe { (*sk).data_end } as usize {
        return TCX_DROP;
    }
    unsafe {
        // bpf_tail_call_static(sk, &jmp_table, 0): bpf_helpers.h's asm
        core::arch::asm!(
            "r1 = {sk};",
            "r2 = {jmp_table} ll;",
            "r3 = 0;",
            "call 12;",
            sk = in(reg) sk,
            jmp_table = sym jmp_table,
            out("r0") _, out("r1") _, out("r2") _, out("r3") _, out("r4") _, out("r5") _,
            options(nostack)
        );
    }
    unsafe { *p = 42 }; // this is NOT unsafe: tail calls don't return
    TCX_PASS
}
