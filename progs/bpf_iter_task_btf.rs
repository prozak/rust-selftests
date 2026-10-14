// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_task_btf.c
// (bpf-rs-core idiom).
//
// This is the C source's `#if __has_builtin(__builtin_btf_type_id)` branch.
// `bpf_core_type_id_kernel(struct task_struct)` is the BTF_TYPE_ID
// declaration below: scripts/type_id.py lowers it to the same
// BPF_TYPE_ID_TARGET relocation the C object carries.

// BTF_TYPE_ID: tid_task_struct struct task_struct

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_seq_printf, bpf_seq_printf_btf};
use core::ffi::c_void;

extern "C" {
    fn tid_task_struct() -> u64;
}

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__task {
    meta: *mut bpf_iter_meta,
    task: *mut c_void,
}

// struct btf_ptr { void *ptr; __u32 type_id; __u32 flags; };
#[allow(non_camel_case_types)]
#[repr(C)]
struct btf_ptr {
    ptr: *mut c_void,
    type_id: u32,
    flags: u32,
}

const ERANGE: i64 = 34;
const E2BIG: i64 = 7;

#[no_mangle]
static mut tasks: isize = 0;
#[no_mangle]
static mut seq_err: isize = 0;
#[no_mangle]
static mut skip: bool = false;

#[link_section = "iter/task"]
#[no_mangle]
extern "C" fn dump_task_struct(ctx: *const bpf_iter__task) -> i32 {
    // C: `static struct btf_ptr ptr = { };`
    #[allow(non_upper_case_globals)]
    static mut ptr: btf_ptr = btf_ptr {
        ptr: core::ptr::null_mut(),
        type_id: 0,
        flags: 0,
    };

    let ctx = unsafe { &*ctx };
    let seq = unsafe { (*ctx.meta).seq };
    let task = ctx.task;

    unsafe {
        ptr.type_id = tid_task_struct() as u32;
        ptr.ptr = task;
    }

    if unsafe { (*ctx.meta).seq_num } == 0 {
        static FMT: [u8; 14] = *b"Raw BTF task\n\0";
        bpf_seq_printf(seq, FMT.as_ptr() as *const c_void, FMT.len() as u32, core::ptr::null(), 0);
    }

    let ret = bpf_seq_printf_btf(
        seq,
        core::ptr::addr_of!(ptr) as *const c_void,
        core::mem::size_of::<btf_ptr>() as u32,
        0,
    );
    match ret {
        0 => unsafe { tasks += 1 },
        // NULL task or task->fs, don't count it as an error.
        r if r == -ERANGE => {}
        r if r == -E2BIG => return 1,
        r => unsafe { seq_err = r as isize },
    }
    0
}

bpf_object!("GPL");
