#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/uprobe_multi_consumers.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;

#[no_mangle]
static mut uprobe_result: [u64; 4] = [0; 4];

unsafe fn bump(idx: usize) {
    let p = core::ptr::addr_of_mut!(uprobe_result) as *mut u64;
    *p.add(idx) += 1;
}

#[link_section = "uprobe.multi"]
#[no_mangle]
extern "C" fn uprobe_0(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { bump(0) };
    0
}

#[link_section = "uprobe.multi"]
#[no_mangle]
extern "C" fn uprobe_1(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { bump(1) };
    0
}

#[link_section = "uprobe.session"]
#[no_mangle]
extern "C" fn uprobe_2(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { bump(2) };
    0
}

#[link_section = "uprobe.session"]
#[no_mangle]
extern "C" fn uprobe_3(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { bump(3) };
    1
}

bpf_object!("GPL");
