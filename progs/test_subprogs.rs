#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_subprogs.c,
// bpf-rs-core idiom.
//
// `bpf_get_current_task()` returns a plain scalar (not a trusted
// PTR_TO_BTF_ID), matching the C source's own comment that a real
// `struct task_struct *` argument is rejected by the verifier across a
// global-function call boundary. Both the C original and this translation
// route every task_struct field read through BPF_CORE_READ /
// bpf_probe_read_kernel (via `#[btf]`'s `.as_ptr()` for the CO-RE-relocated
// address) instead of a direct dereference, so it works regardless of the
// pointer's trust level -- see raw-tp-ctx-scalar-needs-probe-read-not-btf-get
// in memory / test_core_retro.rs for the same idiom.
//
// `get_task_tgid` mirrors the C source's `uintptr_t` trick: the task
// pointer is passed across the global-function boundary as a plain
// integer and re-cast to `*const task_struct` inside the callee, since the
// verifier does not accept a bare struct-pointer argument there.

use core::ffi::c_void;

use bpf_rs_core::helpers::{bpf_get_current_task, bpf_loop, bpf_map_lookup_elem, bpf_probe_read_kernel};
use bpf_rs_core::maps::{self, BpfMap};
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
    tgid: i32,
}

#[link_section = ".maps"]
#[no_mangle]
static array: BpfMap<u32, u64, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
#[inline(never)]
extern "C" fn sub1(x: i32) -> i32 {
    let key: u32 = 0;
    bpf_map_lookup_elem(&array, &key);
    x + 1
}

#[inline(never)]
fn sub5(v: i32) -> i32 {
    sub1(v) - 1
}

#[no_mangle]
#[inline(never)]
extern "C" fn sub2(y: i32) -> i32 {
    sub5(y + 2)
}

#[inline(never)]
fn sub3(z: i32) -> i32 {
    z + 3 + sub1(4)
}

#[inline(never)]
fn sub4(w: i32) -> i32 {
    let key: u32 = 0;
    bpf_map_lookup_elem(&array, &key);
    w + sub3(5) + sub1(6)
}

#[no_mangle]
#[inline(never)]
extern "C" fn get_task_tgid(t: usize) -> i32 {
    let task = t as *const task_struct;
    let mut tgid: i32 = 0;
    bpf_probe_read_kernel(
        &mut tgid,
        core::mem::size_of::<i32>() as u32,
        unsafe { &*task }.tgid().as_ptr() as *const c_void,
    );
    tgid
}

fn read_pid(t: *const task_struct) -> i32 {
    let mut pid: i32 = 0;
    bpf_probe_read_kernel(
        &mut pid,
        core::mem::size_of::<i32>() as u32,
        unsafe { &*t }.pid().as_ptr() as *const c_void,
    );
    pid
}

extern "C" fn empty_callback(_index: u64, _data: *mut c_void) -> i64 {
    0
}

#[no_mangle]
static mut res1: i32 = 0;
#[no_mangle]
static mut res2: i32 = 0;
#[no_mangle]
static mut res3: i32 = 0;
#[no_mangle]
static mut res4: i32 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn prog1(_ctx: *const c_void) -> i32 {
    let t = bpf_get_current_task() as *const task_struct;

    if read_pid(t) == 0 || get_task_tgid(t as usize) == 0 {
        return 1;
    }

    unsafe { res1 = sub1(1) + sub3(2) };
    0
}

#[link_section = "raw_tp/sys_exit"]
#[no_mangle]
extern "C" fn prog2(_ctx: *const c_void) -> i32 {
    let t = bpf_get_current_task() as *const task_struct;

    if read_pid(t) == 0 || get_task_tgid(t as usize) == 0 {
        return 1;
    }

    unsafe { res2 = sub2(3) + sub3(4) };
    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn prog3(_ctx: *const c_void) -> i32 {
    let t = bpf_get_current_task() as *const task_struct;

    if read_pid(t) == 0 || get_task_tgid(t as usize) == 0 {
        return 1;
    }

    bpf_loop(1, empty_callback, core::ptr::null_mut(), 0);

    unsafe { res3 = sub3(5) + 6 };
    0
}

#[link_section = "raw_tp/sys_exit"]
#[no_mangle]
extern "C" fn prog4(_ctx: *const c_void) -> i32 {
    let t = bpf_get_current_task() as *const task_struct;

    if read_pid(t) == 0 || get_task_tgid(t as usize) == 0 {
        return 1;
    }

    unsafe { res4 = sub4(7) + sub1(8) };
    0
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
