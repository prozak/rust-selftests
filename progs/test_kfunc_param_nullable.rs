// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_kfunc_param_nullable.c,
// bpf-rs-core idiom.
//
// bpf_testmod's bpf_kfunc_dynptr_test(ptr, ptr__nullable) accepts NULL
// only for its second argument (prog_tests/kfunc_param_nullable.c RUN_TESTS
// this object): test1 and test2 load, test3 passes NULL as the first
// argument and is rejected with the message declared below.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::test_tags;
use core::mem::MaybeUninit;

test_tags! {
    kfunc_dynptr_nullable_test3: __failure, __msg("Possibly NULL pointer passed to trusted R1");
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

extern "C" {
    fn bpf_dynptr_from_skb(skb: *mut __sk_buff, flags: u64, ptr__uninit: *mut bpf_dynptr) -> i32;
    fn bpf_kfunc_dynptr_test(ptr: *mut bpf_dynptr, ptr__nullable: *mut bpf_dynptr);
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_dynptr_nullable_test1(skb: *mut __sk_buff) -> i32 {
    let mut data = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb(skb, 0, data.as_mut_ptr());
        bpf_kfunc_dynptr_test(data.as_mut_ptr(), core::ptr::null_mut());
    }

    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_dynptr_nullable_test2(skb: *mut __sk_buff) -> i32 {
    let mut data = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb(skb, 0, data.as_mut_ptr());
        bpf_kfunc_dynptr_test(data.as_mut_ptr(), data.as_mut_ptr());
    }

    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_dynptr_nullable_test3(skb: *mut __sk_buff) -> i32 {
    let mut data = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb(skb, 0, data.as_mut_ptr());
        bpf_kfunc_dynptr_test(core::ptr::null_mut(), data.as_mut_ptr());
    }

    0
}

bpf_object!("GPL");
