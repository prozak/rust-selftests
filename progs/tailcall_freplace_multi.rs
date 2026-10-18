// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tailcall_freplace_multi.c
// (bpf-rs-core idiom).
//
// prog_tests/tailcalls.c's tailcall_freplace_multi subtest attaches both
// freplace programs to tc_bpf2bpf's entry_tc / subprog_tc and checks that
// the extended program cannot be stored in jmp_table while either
// extension is attached. The C object names its license global
// `__license`; the internalize keep-list comes from the C object's global
// symbols, so the same name is defined here (see bpf_flow.rs).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::bpf_map;

bpf_map! {
    jmp_table {
        r#type: *const [i32; 3], // BPF_MAP_TYPE_PROG_ARRAY
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "freplace"]
#[no_mangle]
extern "C" fn subprog_freplace(skb: *mut __sk_buff) -> i32 {
    bpf_tail_call(skb as *const c_void, &jmp_table, 0);
    0
}

#[link_section = "freplace"]
#[no_mangle]
extern "C" fn entry_freplace(_skb: *mut __sk_buff) -> i32 {
    0
}

#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
