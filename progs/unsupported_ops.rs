// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/unsupported_ops.c,
// bpf-rs-core idiom.
//
// A NEGATIVE test: bpf_testmod_ops.unsupported_ops exists in the kernel
// module's struct but the module registers no verifier support for it
// (bpf_testmod.c leaves the member out of its check), so attaching a
// program to that member is rejected at load with the message below.

use bpf_rs_core::bpf_object;
use bpf_rs_core::test_tags;

test_tags! {
    unsupported_ops: __failure, __msg("attach to unsupported member unsupported_ops of struct bpf_testmod_ops");
}

#[link_section = "struct_ops/unsupported_ops"]
#[no_mangle]
extern "C" fn unsupported_ops(_ctx: *const u64) -> i32 {
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    unsupported_ops: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod: bpf_testmod_ops = bpf_testmod_ops { unsupported_ops };

bpf_object!("GPL");
