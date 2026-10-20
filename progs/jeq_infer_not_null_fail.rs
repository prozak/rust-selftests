// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/jeq_infer_not_null_fail.c,
// bpf-rs-core idiom.
//
// A NEGATIVE verifier test (prog_tests/jeq_infer_not_null.c RUN_TESTS this
// object): comparing a map_value_or_null (R8, the lookup result) against a
// PTR_TO_BTF_ID (R9, the map's inner_map_meta read through `(struct bpf_map
// *)&m_hash`) must not mark R8 non-null, so the load through R8 on the
// equal path is rejected with the message declared below. The C pins R8/R9
// with inline asm so the compiler cannot substitute another register once
// it learns val == inner_map; the `asm!` here does the same (lesson 73).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_lookup_elem;
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::test_tags;
use btf_macros::btf;
use core::ffi::c_void;
use core::ptr::addr_of_mut;

test_tags! {
    jeq_infer_not_null_ptr_to_btfid: __failure, __msg("R8 invalid mem access 'map_value_or_null");
}

// The kernel's struct bpf_map, read via CO-RE through the map pointer.
#[btf]
struct bpf_map {
    inner_map_meta: *mut bpf_map,
}

// `static mut`, not `static`: a load through a constant static folds to
// zero before the CO-RE relocation exists (TRANSLATING.md, map_ptr_kern.rs).
#[link_section = ".maps"]
#[no_mangle]
static mut m_hash: BpfMap<u64, u64, { maps::HASH }, 1> = BpfMap::new();

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn jeq_infer_not_null_ptr_to_btfid(_ctx: *mut c_void) -> i32 {
    let map = unsafe { addr_of_mut!(m_hash) } as *mut bpf_map;
    let inner_map = *unsafe { &*map }.inner_map_meta().get().unwrap();
    let key: u64 = 0;
    let mut ret: u64 = 0;

    let val = bpf_map_lookup_elem(map, &key) as *mut u64;
    /* Do not mark ptr as non-null if one of them is
     * PTR_TO_BTF_ID (R9), reject because of invalid
     * access to map value (R8).
     */
    unsafe {
        core::arch::asm!(
            "r8 = {val};",
            "r9 = {inner_map};",
            "if r8 != r9 goto +1;",
            "{ret} = *(u64 *)(r8 +0);",
            val = in(reg) val,
            inner_map = in(reg) inner_map,
            ret = inout(reg) ret,
            out("r8") _,
            out("r9") _,
        );
    }

    ret as i32
}

bpf_object!("GPL");
