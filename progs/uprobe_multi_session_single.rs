#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/uprobe_multi_session_single.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;

#[no_mangle]
static mut uprobe_session_result: [u64; 3] = [0; 3];

#[no_mangle]
static mut pid: i32 = 0;

unsafe fn uprobe_multi_check(idx: usize) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) as i32 != pid {
        return 1;
    }

    let p = core::ptr::addr_of_mut!(uprobe_session_result) as *mut u64;
    *p.add(idx) += 1;

    // only consumer 1 executes return probe
    if idx == 0 || idx == 2 {
        return 1;
    }

    0
}

#[link_section = "uprobe.session//proc/self/exe:uprobe_multi_func_1"]
#[no_mangle]
extern "C" fn uprobe_0(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { uprobe_multi_check(0) }
}

#[link_section = "uprobe.session//proc/self/exe:uprobe_multi_func_1"]
#[no_mangle]
extern "C" fn uprobe_1(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { uprobe_multi_check(1) }
}

#[link_section = "uprobe.session//proc/self/exe:uprobe_multi_func_1"]
#[no_mangle]
extern "C" fn uprobe_2(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe { uprobe_multi_check(2) }
}

bpf_object!("GPL");
