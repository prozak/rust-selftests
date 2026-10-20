// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_qdisc_fail__invalid_dynptr_returned_slice.c,
// bpf-rs-core idiom (the Qdisc_ops mirror and the four __auxiliary
// programs follow bpf_qdisc_dynptr_use_after_invalidate_clone.rs).
//
// A NEGATIVE verifier test (prog_tests/bpf_qdisc.c RUN_TESTS this object):
// a slice returned from a static subprogram whose dynptr lived in that
// frame is a scalar to the caller, so the load through it is rejected.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::test_tags;
use core::ffi::c_void;

const NET_XMIT_DROP: i32 = 0x01;

#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

#[repr(C)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

extern "C" {
    fn bpf_dynptr_from_skb(skb: *mut c_void, flags: u64, ptr: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_slice(ptr: *const bpf_dynptr, offset: u64, buffer: *mut c_void, buffer_sz: u64) -> *mut c_void;
    fn bpf_qdisc_skb_drop(skb: *mut c_void, to_free: *mut c_void);
}

#[no_mangle]
static mut proto: i32 = 0;

// C: static __noinline struct ethhdr *slice_in_subprog(struct sk_buff *skb)
#[inline(never)]
fn slice_in_subprog(skb: *mut c_void) -> *mut ethhdr {
    let mut ptr = bpf_dynptr { __opaque: [0, 0] };

    unsafe {
        bpf_dynptr_from_skb(skb, 0, &mut ptr as *mut bpf_dynptr);
        bpf_dynptr_slice(&ptr as *const bpf_dynptr, 0, core::ptr::null_mut(), core::mem::size_of::<ethhdr>() as u64) as *mut ethhdr
    }
}

test_tags! {
    invalid_dynptr_returned_slice: __failure, __msg("invalid mem access 'scalar'");
    bpf_qdisc_test_dequeue: __auxiliary;
    bpf_qdisc_test_init: __auxiliary;
    bpf_qdisc_test_reset: __auxiliary;
    bpf_qdisc_test_destroy: __auxiliary;
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn invalid_dynptr_returned_slice(ctx: *const u64) -> i32 {
    let skb = fentry_arg(ctx, 0) as *mut c_void;
    let to_free = fentry_arg(ctx, 2) as *mut c_void;

    let hdr = slice_in_subprog(skb);
    if hdr.is_null() {
        unsafe { bpf_qdisc_skb_drop(skb, to_free) };
        return NET_XMIT_DROP;
    }

    unsafe {
        /* this should fail */
        proto = (*hdr).h_proto as i32;

        bpf_qdisc_skb_drop(skb, to_free);
    }

    NET_XMIT_DROP
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_qdisc_test_dequeue(_ctx: *const u64) -> *mut c_void {
    core::ptr::null_mut()
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_qdisc_test_init(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_qdisc_test_reset(_ctx: *const u64) {}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_qdisc_test_destroy(_ctx: *const u64) {}

#[allow(non_camel_case_types)]
#[repr(C)]
struct Qdisc_ops {
    enqueue: extern "C" fn(*const u64) -> i32,
    dequeue: extern "C" fn(*const u64) -> *mut c_void,
    init: extern "C" fn(*const u64) -> i32,
    reset: extern "C" fn(*const u64),
    destroy: extern "C" fn(*const u64),
    id: [u8; 16],
}

unsafe impl Sync for Qdisc_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static test: Qdisc_ops = Qdisc_ops {
    enqueue: invalid_dynptr_returned_slice,
    dequeue: bpf_qdisc_test_dequeue,
    init: bpf_qdisc_test_init,
    reset: bpf_qdisc_test_reset,
    destroy: bpf_qdisc_test_destroy,
    id: *b"bpf_qdisc_test\0\0",
};

bpf_object!("GPL");
