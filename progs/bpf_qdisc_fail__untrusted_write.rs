// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_qdisc_fail__untrusted_write.c,
// bpf-rs-core idiom (the Qdisc_ops mirror and the four __auxiliary
// programs follow bpf_qdisc_dynptr_use_after_invalidate_clone.rs).
//
// A NEGATIVE verifier test (prog_tests/bpf_qdisc.c RUN_TESTS this object):
// a store through the untrusted PTR_TO_BTF_ID reached from the trusted
// sch via sch->next_sched (`next->limit = 1000`) is rejected before
// bpf_qdisc_btf_struct_access() could allow a write to limit.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::test_tags;
use core::ffi::c_void;
use btf_macros::btf;
const NET_XMIT_DROP: i32 = 0x01;

// sch (ctx[1]) is trusted, but the walk of sch->next_sched yields a plain
// PTR_TO_BTF_ID that may fault on a dereference; a store through it has no
// exception-table entry, so the write to next->limit is rejected.
#[btf]
struct Qdisc {
    next_sched: *mut Qdisc,
    limit: u32,
}

extern "C" {
    fn bpf_qdisc_skb_drop(skb: *mut c_void, to_free: *mut c_void);
}

test_tags! {
    untrusted_write: __failure, __msg("only read is supported");
    bpf_qdisc_test_dequeue: __auxiliary;
    bpf_qdisc_test_init: __auxiliary;
    bpf_qdisc_test_reset: __auxiliary;
    bpf_qdisc_test_destroy: __auxiliary;
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn untrusted_write(ctx: *const u64) -> i32 {
    let skb = fentry_arg(ctx, 0) as *mut c_void;
    let sch = fentry_arg(ctx, 1) as *mut Qdisc;
    let to_free = fentry_arg(ctx, 2) as *mut c_void;

    let next = *unsafe { &*sch }.next_sched().get().unwrap();

    unsafe { *(&*next).limit().as_mut_ptr() = 1000 };

    unsafe { bpf_qdisc_skb_drop(skb, to_free) };
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
    enqueue: untrusted_write,
    dequeue: bpf_qdisc_test_dequeue,
    init: bpf_qdisc_test_init,
    reset: bpf_qdisc_test_reset,
    destroy: bpf_qdisc_test_destroy,
    id: *b"bpf_qdisc_test\0\0",
};

bpf_object!("GPL");
