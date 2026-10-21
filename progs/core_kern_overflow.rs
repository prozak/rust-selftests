// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of progs/core_kern_overflow.c (bpf-rs-core idiom): one
// program whose load must FAIL (prog_tests/core_kern_overflow.c asserts
// open_and_load returns NULL). bpf_core_type_exists(func_proto_typedef_nested2)
// is a TYPE_EXISTS relocation on a func-proto typedef nested three deep,
// deeper than libbpf's type-compatibility recursion allows, so libbpf
// rejects the relocation. The `// BTF_TYPE_INFO:` extern (scripts/type_id.py)
// carries a full copy of the C object's typedef chain, so the Rust object
// fails the same way.
// BTF_TYPE_INFO: func_proto_typedef_nested2_exists exists typedef func_proto_typedef_nested2

use core::ffi::c_void;

use bpf_rs_core::bpf_object;

extern "C" {
    fn func_proto_typedef_nested2_exists() -> u32;
}

#[no_mangle]
static mut proto_out: i32 = 0;

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn core_relo_proto(_ctx: *mut c_void) -> i32 {
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(proto_out),
            func_proto_typedef_nested2_exists() as i32,
        );
    }
    0
}

bpf_object!("GPL");
