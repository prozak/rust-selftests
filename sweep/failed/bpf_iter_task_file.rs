#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter__task_file {
    meta: *mut c_void,
    task: *mut c_void,
    fd: u32,
    file: *mut c_void,
}

#[no_mangle]
static mut count: i32 = 0;

#[link_section = "iter/task_file"]
#[no_mangle]
extern "C" fn dump_task_file(ctx: *const bpf_iter__task_file) -> i32 {
    let ctx = unsafe { &*ctx };
    let task = ctx.task;

    unsafe { count = task.is_null() as i32 };

    0
}

bpf_object!("GPL");
