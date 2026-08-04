#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_attach_probe_manual.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

#[no_mangle]
static mut kprobe_res: i32 = 0;
#[no_mangle]
static mut kretprobe_res: i32 = 0;
#[no_mangle]
static mut uprobe_res: i32 = 0;
#[no_mangle]
static mut uretprobe_res: i32 = 0;
#[no_mangle]
static mut uprobe_byname_res: i32 = 0;
// `void *user_ptr = 0;` in C -- see test_attach_probe.rs for why `char` is
// used as the pointee marker to reach the same `void *` BTF shape.
#[no_mangle]
static mut user_ptr: *mut char = core::ptr::null_mut();

#[link_section = "kprobe"]
#[no_mangle]
extern "C" fn handle_kprobe(_ctx: *const c_void) -> i32 {
    unsafe { kprobe_res = 1 };
    0
}

#[link_section = "kretprobe"]
#[no_mangle]
extern "C" fn handle_kretprobe(_ctx: *const c_void) -> i32 {
    unsafe { kretprobe_res = 2 };
    0
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn handle_uprobe(_ctx: *const c_void) -> i32 {
    unsafe { uprobe_res = 3 };
    0
}

#[link_section = "uretprobe"]
#[no_mangle]
extern "C" fn handle_uretprobe(_ctx: *const c_void) -> i32 {
    unsafe { uretprobe_res = 4 };
    0
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn handle_uprobe_byname(_ctx: *const c_void) -> i32 {
    unsafe { uprobe_byname_res = 5 };
    0
}

bpf_object!("GPL");
