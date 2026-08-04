#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/uprobe_multi_session.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_copy_from_user, bpf_get_current_pid_tgid, bpf_get_func_ip, bpf_strncmp};
use core::ffi::c_void;

extern "C" {
    fn bpf_session_is_return(ctx: *mut c_void) -> bool;
}

#[no_mangle]
static mut uprobe_multi_func_1_addr: u64 = 0;
#[no_mangle]
static mut uprobe_multi_func_2_addr: u64 = 0;
#[no_mangle]
static mut uprobe_multi_func_3_addr: u64 = 0;

#[no_mangle]
static mut uprobe_session_result: [u64; 3] = [0; 3];
#[no_mangle]
static mut uprobe_multi_sleep_result: u64 = 0;

// `void *user_ptr = 0;` in C -- see kprobe_multi_sleepable.rs: `*mut char` is
// the pointee type whose BTF encoding round-trips to real `void *`.
#[no_mangle]
static mut user_ptr: *mut char = core::ptr::null_mut();

#[no_mangle]
static mut pid: i32 = 0;

unsafe fn uprobe_multi_check(ctx: *mut c_void, _is_return: bool) -> i32 {
    let funcs = [
        uprobe_multi_func_1_addr,
        uprobe_multi_func_2_addr,
        uprobe_multi_func_3_addr,
    ];

    if (bpf_get_current_pid_tgid() >> 32) as i32 != pid {
        return 1;
    }

    let addr = bpf_get_func_ip(ctx);

    let mut i = 0usize;
    while i < funcs.len() {
        if funcs[i] == addr {
            let p = core::ptr::addr_of_mut!(uprobe_session_result) as *mut u64;
            *p.add(i) += 1;
            break;
        }
        i += 1;
    }

    // only uprobe_multi_func_2 executes return probe
    if addr == uprobe_multi_func_1_addr || addr == uprobe_multi_func_3_addr {
        return 1;
    }

    0
}

unsafe fn verify_sleepable_user_copy() -> bool {
    let mut data = [0u8; 9];

    bpf_copy_from_user(
        data.as_mut_ptr() as *mut c_void,
        data.len() as u32,
        user_ptr as *const c_void,
    );

    bpf_strncmp(
        data.as_ptr() as *const c_void,
        data.len() as u32,
        b"test_data\0".as_ptr() as *const c_void,
    ) == 0
}

#[link_section = "uprobe.session//proc/self/exe:uprobe_multi_func_*"]
#[no_mangle]
extern "C" fn uprobe(ctx: *mut c_void) -> i32 {
    unsafe {
        let is_return = bpf_session_is_return(ctx);
        uprobe_multi_check(ctx, is_return)
    }
}

#[link_section = "uprobe.session.s//proc/self/exe:uprobe_multi_func_*"]
#[no_mangle]
extern "C" fn uprobe_sleepable(ctx: *mut c_void) -> i32 {
    unsafe {
        if verify_sleepable_user_copy() {
            uprobe_multi_sleep_result += 1;
        }
        let is_return = bpf_session_is_return(ctx);
        uprobe_multi_check(ctx, is_return)
    }
}

bpf_object!("GPL");
