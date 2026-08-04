#![no_std]
#![no_main]

use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::{bpf_map, bpf_object, maps};

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "lsm/file_permission"]
#[no_mangle]
extern "C" fn lsm_file_permission_prog(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "lsm/kernfs_init_security"]
#[no_mangle]
extern "C" fn lsm_kernfs_init_security_prog(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "lsm/kernfs_init_security"]
#[no_mangle]
extern "C" fn lsm_kernfs_init_security_entry(ctx: *const core::ffi::c_void) -> i32 {
    bpf_tail_call(ctx, &jmp_table, 0);
    0
}

bpf_object!("GPL");
