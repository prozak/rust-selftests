#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/iters_task.c,
// bpf-rs-core idiom.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_task_btf;
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
    tgid: i32,
}

// struct bpf_iter_task { __u64 __opaque[3]; } __attribute__((aligned(8)));
#[repr(C, align(8))]
struct bpf_iter_task {
    __opaque: [u64; 3],
}

extern "C" {
    fn bpf_iter_task_new(it: *mut bpf_iter_task, task: *mut task_struct, flags: u32) -> i32;
    fn bpf_iter_task_next(it: *mut bpf_iter_task) -> *mut task_struct;
    fn bpf_iter_task_destroy(it: *mut bpf_iter_task);
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
}

const BPF_TASK_ITER_ALL_PROCS: u32 = 0;
const BPF_TASK_ITER_ALL_THREADS: u32 = 1;
const BPF_TASK_ITER_PROC_THREADS: u32 = 2;

#[no_mangle]
static mut target_pid: i32 = 0;
#[no_mangle]
static mut procs_cnt: i32 = 0;
#[no_mangle]
static mut threads_cnt: i32 = 0;
#[no_mangle]
static mut proc_threads_cnt: i32 = 0;
#[no_mangle]
static mut invalid_cnt: i32 = 0;

#[link_section = "fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn iter_task_for_each_sleep(_ctx: *const c_void) -> i32 {
    let cur_task: *mut task_struct = bpf_get_current_task_btf();

    if *unsafe { &*cur_task }.pid().get().unwrap() != unsafe { target_pid } {
        return 0;
    }
    unsafe {
        procs_cnt = 0;
        threads_cnt = 0;
        proc_threads_cnt = 0;
    }

    unsafe { bpf_rcu_read_lock() };

    // Below instructions shouldn't be executed for invalid flags.
    let mut it = bpf_iter_task { __opaque: [0; 3] };
    unsafe { bpf_iter_task_new(&mut it, core::ptr::null_mut(), !0u32) };
    loop {
        let pos = unsafe { bpf_iter_task_next(&mut it) };
        if pos.is_null() {
            break;
        }
        unsafe { invalid_cnt += 1 };
    }
    unsafe { bpf_iter_task_destroy(&mut it) };

    // Below instructions shouldn't be executed for invalid task__nullable.
    let mut it = bpf_iter_task { __opaque: [0; 3] };
    unsafe { bpf_iter_task_new(&mut it, core::ptr::null_mut(), BPF_TASK_ITER_PROC_THREADS) };
    loop {
        let pos = unsafe { bpf_iter_task_next(&mut it) };
        if pos.is_null() {
            break;
        }
        unsafe { invalid_cnt += 1 };
    }
    unsafe { bpf_iter_task_destroy(&mut it) };

    let mut it = bpf_iter_task { __opaque: [0; 3] };
    unsafe { bpf_iter_task_new(&mut it, core::ptr::null_mut(), BPF_TASK_ITER_ALL_PROCS) };
    loop {
        let pos = unsafe { bpf_iter_task_next(&mut it) };
        if pos.is_null() {
            break;
        }
        if *unsafe { &*pos }.pid().get().unwrap() == unsafe { target_pid } {
            unsafe { procs_cnt += 1 };
        }
    }
    unsafe { bpf_iter_task_destroy(&mut it) };

    let mut it = bpf_iter_task { __opaque: [0; 3] };
    unsafe { bpf_iter_task_new(&mut it, cur_task, BPF_TASK_ITER_PROC_THREADS) };
    loop {
        let pos = unsafe { bpf_iter_task_next(&mut it) };
        if pos.is_null() {
            break;
        }
        unsafe { proc_threads_cnt += 1 };
    }
    unsafe { bpf_iter_task_destroy(&mut it) };

    let mut it = bpf_iter_task { __opaque: [0; 3] };
    unsafe { bpf_iter_task_new(&mut it, core::ptr::null_mut(), BPF_TASK_ITER_ALL_THREADS) };
    loop {
        let pos = unsafe { bpf_iter_task_next(&mut it) };
        if pos.is_null() {
            break;
        }
        if *unsafe { &*pos }.tgid().get().unwrap() == unsafe { target_pid } {
            unsafe { threads_cnt += 1 };
        }
    }
    unsafe { bpf_iter_task_destroy(&mut it) };

    unsafe { bpf_rcu_read_unlock() };
    0
}

bpf_object!("GPL");
