// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/btf_module_allowlist.c
// (bpf-rs-core idiom): one empty fentry program on a bpf_testmod function;
// the test is about which module BTFs libbpf may consult to resolve it.

use bpf_rs_core::bpf_object;

#[link_section = "fentry/bpf_testmod_loop_test"]
#[no_mangle]
extern "C" fn test_btf_module_allowlist(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
