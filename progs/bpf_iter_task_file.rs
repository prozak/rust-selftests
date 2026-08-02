#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_task_file.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_seq_printf;
use btf_macros::btf;
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__task_file {
    meta: *mut bpf_iter_meta,
    task: *mut task_struct,
    fd: u32,
    file: *mut file,
}

#[btf]
struct task_struct {
    tgid: i32,
    pid: i32,
}

#[btf]
struct file {
    f_op: *const u8,
}

#[no_mangle]
static mut count: i32 = 0;
#[no_mangle]
static mut tgid: i32 = 0;
#[no_mangle]
static mut last_tgid: i32 = 0;
#[no_mangle]
static mut unique_tgid_count: i32 = 0;

#[link_section = "iter/task_file"]
#[no_mangle]
extern "C" fn dump_task_file(ctx: *const bpf_iter__task_file) -> i32 {
    let ctx = unsafe { &*ctx };
    let task = ctx.task;
    let file_ptr = ctx.file;
    let fd = ctx.fd;

    if task.is_null() || file_ptr.is_null() {
        return 0;
    }

    let meta = unsafe { &*ctx.meta };
    let task_ref = unsafe { &*task };
    let file_ref = unsafe { &*file_ptr };

    if meta.seq_num == 0 {
        unsafe { count = 0 };
        static FMT0: [u8; 38] = *b"    tgid      gid       fd      file\n\0";
        bpf_seq_printf(
            meta.seq,
            FMT0.as_ptr() as *const c_void,
            FMT0.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    let task_tgid = unsafe { *task_ref.tgid().as_ptr() };
    let task_pid = unsafe { *task_ref.pid().as_ptr() };

    if unsafe { tgid } == task_tgid && task_tgid != task_pid {
        unsafe { count += 1 };
    }

    if unsafe { last_tgid } != task_tgid {
        unsafe { last_tgid = task_tgid };
        unsafe { unique_tgid_count += 1 };
    }

    let f_op = unsafe { *file_ref.f_op().as_ptr() };
    static FMT1: [u8; 17] = *b"%8d %8d %8d %lx\n\0";
    let params: [u64; 4] = [
        task_tgid as i64 as u64,
        task_pid as i64 as u64,
        fd as u64,
        f_op as u64,
    ];
    bpf_seq_printf(
        meta.seq,
        FMT1.as_ptr() as *const c_void,
        FMT1.len() as u32,
        params.as_ptr() as *const c_void,
        core::mem::size_of_val(&params) as u32,
    );

    0
}

bpf_object!("GPL");
