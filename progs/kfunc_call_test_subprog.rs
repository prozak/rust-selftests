// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// BTF_KSYM: bpf_prog_active

// Direct translation of tools/testing/selftests/bpf/progs/kfunc_call_test_subprog.c
// (bpf-rs-core idiom). f1 is C's __noinline global subprogram, so it stays a
// #[no_mangle] #[inline(never)] function taking `struct __sk_buff *`; the
// kfuncs are bpf_testmod's, and `bpf_prog_active` is the kernel per-cpu
// variable through BTF_KSYM (scripts/ksym_vars.py), read with bpf_per_cpu_ptr.

use core::ffi::c_void;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_smp_processor_id, bpf_per_cpu_ptr, bpf_sk_fullsock};
use bpf_rs_core::{bpf_object, vload};

extern "C" {
    fn bpf_kfunc_call_test1(sk: *mut c_void, a: u32, b: u64, c: u32, d: u64) -> u64;
    fn bpf_kfunc_call_test3(sk: *mut c_void) -> *mut c_void;
}

extern "C" {
    static bpf_prog_active: i32;
}

#[no_mangle]
static mut active_res: i32 = -1;
#[no_mangle]
static mut sk_state_res: i32 = -1;

// Only the fields up to and including skc_state are used; the rest of the
// real struct sock_common goes unused, matching the byte layout up to that
// point (include/net/sock.h) so the offset the verifier walks against the
// kernel's own BTF for `struct sock` lines up.
#[repr(C)]
#[allow(dead_code)]
struct SockCommon {
    skc_daddr: u32,
    skc_rcv_saddr: u32,
    skc_hash: u32,
    skc_portpair: u32,
    skc_family: u16,
    skc_state: u8,
}

#[no_mangle]
#[inline(never)]
extern "C" fn f1(skb: *const __sk_buff) -> i32 {
    let sk = vload!((*skb).sk) as *mut c_void;
    if sk.is_null() {
        return -1;
    }

    let sk = bpf_sk_fullsock(sk);
    if sk.is_null() {
        return -1;
    }

    let active = bpf_per_cpu_ptr(
        core::ptr::addr_of!(bpf_prog_active) as *const c_void,
        bpf_get_smp_processor_id(),
    ) as *const i32;
    if !active.is_null() {
        unsafe { active_res = *active };
    }

    let sk3 = unsafe { bpf_kfunc_call_test3(sk) };
    unsafe {
        sk_state_res = (*(sk3 as *const SockCommon)).skc_state as i32;
    }

    unsafe { bpf_kfunc_call_test1(sk, 1, 2, 3, 4) as u32 as i32 }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_call_test1(skb: *const __sk_buff) -> i32 {
    f1(skb)
}

bpf_object!("GPL");
