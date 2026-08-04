#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/uprobe_multi_pid_filter.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;

#[no_mangle]
static mut pids: [u32; 3] = [0; 3];

#[no_mangle]
static mut test: [[u32; 2]; 3] = [[0; 2]; 3];

unsafe fn update_pid(idx: usize) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let pids_ptr = core::ptr::addr_of!(pids) as *const u32;
    let want = *pids_ptr.add(idx);

    let test_ptr = core::ptr::addr_of_mut!(test) as *mut u32;
    if pid == want {
        *test_ptr.add(idx * 2) += 1;
    } else {
        *test_ptr.add(idx * 2 + 1) += 1;
    }
}

#[link_section = "uprobe.multi"]
#[no_mangle]
extern "C" fn uprobe_multi_0(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { update_pid(0) };
    0
}

#[link_section = "uprobe.multi"]
#[no_mangle]
extern "C" fn uprobe_multi_1(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { update_pid(1) };
    0
}

#[link_section = "uprobe.multi"]
#[no_mangle]
extern "C" fn uprobe_multi_2(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { update_pid(2) };
    0
}

bpf_object!("GPL");
