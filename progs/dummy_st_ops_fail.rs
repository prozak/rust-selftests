// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/dummy_st_ops_fail.c,
// bpf-rs-core idiom.
//
// A NEGATIVE test: the program is declared sleepable (`struct_ops.s/test_2`)
// for a bpf_dummy_ops member the kernel does not allow to sleep
// (net/bpf/bpf_dummy_struct_ops.c only marks test_sleepable so), and the
// load is rejected with the message below. The map's other two members are
// NULL in the C, so they are null `*const c_void` here (struct_ops_forgotten_cb.rs
// precedent: a Rust fn pointer cannot be null); libbpf skips a null member.

use bpf_rs_core::bpf_object;
use bpf_rs_core::test_tags;
use core::ffi::c_void;

test_tags! {
    test_unsupported_field_sleepable: __failure, __msg("attach to unsupported member test_2 of struct bpf_dummy_ops");
}

// C: BPF_PROG(test_unsupported_field_sleepable, struct bpf_dummy_ops_state *state,
//             int a1, unsigned short a2, char a3, unsigned long a4) -- none used.
#[link_section = "struct_ops.s/test_2"]
#[no_mangle]
extern "C" fn test_unsupported_field_sleepable(_ctx: *const u64) -> i32 {
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_dummy_ops {
    test_1: *const c_void,
    test_2: extern "C" fn(*const u64) -> i32,
    test_sleepable: *const c_void,
}

unsafe impl Sync for bpf_dummy_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static dummy_1: bpf_dummy_ops = bpf_dummy_ops {
    test_1: core::ptr::null(),
    test_2: test_unsupported_field_sleepable,
    test_sleepable: core::ptr::null(),
};

bpf_object!("GPL");
