#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_task_stack.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_task_stack, bpf_seq_printf, bpf_seq_write};
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

#[repr(C)]
struct task_struct {
    pid: i32,
}

const MAX_STACK_TRACE_DEPTH: usize = 64;
const SIZE_OF_ULONG: usize = core::mem::size_of::<u64>();
const BPF_F_USER_STACK: u64 = 1 << 8;

#[no_mangle]
static mut entries: [u64; MAX_STACK_TRACE_DEPTH] = [0; MAX_STACK_TRACE_DEPTH];

#[link_section = "iter/task"]
#[no_mangle]
extern "C" fn dump_task_stack(ctx: *const bpf_iter__task) -> i32 {
    let ctx = unsafe { &*ctx };
    let task = ctx.task;

    if task.is_null() {
        return 0;
    }

    let meta = unsafe { &*ctx.meta };
    let task_ref = unsafe { &*task };

    let retlen = bpf_get_task_stack(
        task,
        unsafe { core::ptr::addr_of_mut!(entries) as *mut c_void },
        (MAX_STACK_TRACE_DEPTH * SIZE_OF_ULONG) as u32,
        0,
    );
    if retlen < 0 {
        return 0;
    }

    static FMT_HEADER: [u8; 27] = *b"pid: %8u num_entries: %8u\n\0";
    let header_params: [u64; 2] = [task_ref.pid as u32 as u64, (retlen / SIZE_OF_ULONG as i64) as u64];
    bpf_seq_printf(
        meta.seq,
        FMT_HEADER.as_ptr() as *const c_void,
        FMT_HEADER.len() as u32,
        header_params.as_ptr() as *const c_void,
        core::mem::size_of_val(&header_params) as u32,
    );

    static FMT_ENTRY: [u8; 11] = *b"[<0>] %pB\n\0";
    for i in 0..MAX_STACK_TRACE_DEPTH {
        if retlen > (i * SIZE_OF_ULONG) as i64 {
            let entry_params: [u64; 1] = [unsafe { entries[i] }];
            bpf_seq_printf(
                meta.seq,
                FMT_ENTRY.as_ptr() as *const c_void,
                FMT_ENTRY.len() as u32,
                entry_params.as_ptr() as *const c_void,
                core::mem::size_of_val(&entry_params) as u32,
            );
        }
    }

    static FMT_NL: [u8; 2] = *b"\n\0";
    bpf_seq_printf(
        meta.seq,
        FMT_NL.as_ptr() as *const c_void,
        FMT_NL.len() as u32,
        core::ptr::null(),
        0,
    );

    0
}

#[no_mangle]
static mut num_user_stacks: i32 = 0;

#[link_section = "iter/task"]
#[no_mangle]
extern "C" fn get_task_user_stacks(ctx: *const bpf_iter__task) -> i32 {
    let ctx = unsafe { &*ctx };
    let task = ctx.task;

    if task.is_null() {
        return 0;
    }

    let meta = unsafe { &*ctx.meta };

    let res = bpf_get_task_stack(
        task,
        unsafe { core::ptr::addr_of_mut!(entries) as *mut c_void },
        (MAX_STACK_TRACE_DEPTH * SIZE_OF_ULONG) as u32,
        BPF_F_USER_STACK,
    );
    if res <= 0 {
        return 0;
    }

    unsafe { num_user_stacks += 1 };

    let buf_sz: u64 = res as u64;

    bpf_seq_write(
        meta.seq,
        core::ptr::addr_of!(entries) as *const c_void,
        buf_sz as u32,
    );

    0
}

bpf_object!("GPL");
