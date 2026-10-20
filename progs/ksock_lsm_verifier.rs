// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/ksock_lsm_verifier.c,
// bpf-rs-core idiom (ksock_lsm.rs is the positive counterpart; the shared
// ksock_common.h map, value type and kfuncs live in common/ksock.rs).
//
// A NEGATIVE verifier test (prog_tests/ksock.c RUN_TESTS this object):
// bpf_ksock_send is not in the kfunc set of the socket_sendmsg LSM hook, so
// the call is rejected with the message declared below. The license symbol
// is `__license`, as in the C.

#[path = "common/ksock.rs"]
mod ksock;
use bpf_rs_core::helpers::{bpf_kptr_xchg, bpf_map_lookup_elem};
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::{btf_type_tags, test_tags};
use core::ptr::addr_of_mut;
use ksock::*;

test_tags! {
    ksock_socket_sendmsg: __description("bpf_ksock_send is rejected from socket_sendmsg LSM hook"), __failure, __msg("calling kernel function bpf_ksock_send is not allowed");
}

#[no_mangle]
static mut send_data: [u8; 11] = *b"dummy data\0";

#[no_mangle]
#[link_section = "lsm.s/socket_sendmsg"]
extern "C" fn ksock_socket_sendmsg(ctx: *const u64) -> i32 {
    let ret = fentry_arg(ctx, 3) as i32;
    unsafe {
        let v = bpf_map_lookup_elem(&__ksock_ctx_map, &0u32) as *mut __ksock_ctx_value;
        if v.is_null() {
            return ret;
        }
        let ks = bpf_kptr_xchg(addr_of_mut!((*v).ctx).cast(), core::ptr::null_mut()) as *mut bpf_ksock;
        if ks.is_null() {
            return ret;
        }
        bpf_ksock_send(ks, addr_of_mut!(send_data).cast(), 11);
        bpf_ksock_release(ks);
    }
    ret
}

btf_type_tags! { __ksock_ctx_value.ctx: kptr; }

#[no_mangle]
#[link_section = "license"]
static __license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
