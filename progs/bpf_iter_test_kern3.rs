#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_test_kern3.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_seq_write;
use btf_macros::btf;
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__task {
    meta: *mut bpf_iter_meta,
    task: *mut task_struct,
}

#[btf]
struct task_struct {
    tgid: i32,
}

#[link_section = "iter/task"]
#[no_mangle]
extern "C" fn dump_task(ctx: *const bpf_iter__task) -> i32 {
    let ctx = unsafe { &*ctx };
    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;
    let task = unsafe { &*ctx.task };

    let tgid = unsafe { *task.tgid().as_ptr() };
    bpf_seq_write(
        seq,
        &tgid as *const i32 as *const c_void,
        core::mem::size_of::<i32>() as u32,
    );

    0
}

bpf_object!("GPL");
