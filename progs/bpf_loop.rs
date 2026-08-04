#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_loop.c
// (bpf-rs-core idiom).
//
// prog_tests/bpf_loop.c drives every SEC() program below through the
// skeleton's bss/data globals and asserts on nr_loops_returned/g_output/err,
// plus a map1-based stack-preservation check (check_stack). SYS_PREFIX on
// this x86_64 build is "__x64_".

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_loop, bpf_map_lookup_elem, bpf_map_update_elem};
use bpf_rs_core::maps::{self, BpfMap};

#[repr(C)]
struct CallbackCtx {
    output: i32,
}

#[link_section = ".maps"]
#[no_mangle]
static map1: BpfMap<i32, i32, { maps::HASH }, 32> = BpfMap::new();

/* These should be set by the user program */
#[no_mangle]
static mut nested_callback_nr_loops: u32 = 0;
#[no_mangle]
static mut stop_index: u32 = u32::MAX;
#[no_mangle]
static mut nr_loops: u32 = 0;
#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut callback_selector: i32 = 0;

/* Making these global variables so that the userspace program
 * can verify the output through the skeleton */
#[no_mangle]
static mut nr_loops_returned: i32 = 0;
#[no_mangle]
static mut g_output: i32 = 0;
#[no_mangle]
static mut err: i32 = 0;

extern "C" fn callback(index: u64, data: *mut CallbackCtx) -> i64 {
    let idx = index as u32;
    unsafe {
        if idx >= stop_index {
            return 1;
        }
        (*data).output += idx as i32;
    }
    0
}

extern "C" fn empty_callback(_index: u64, _data: *mut c_void) -> i64 {
    0
}

extern "C" fn nested_callback2(_index: u64, data: *mut CallbackCtx) -> i64 {
    let ret = bpf_loop(unsafe { nested_callback_nr_loops }, callback, data, 0);
    unsafe {
        nr_loops_returned += ret as i32;
    }
    0
}

extern "C" fn nested_callback1(_index: u64, data: *mut CallbackCtx) -> i64 {
    bpf_loop(unsafe { nested_callback_nr_loops }, nested_callback2, data, 0);
    0
}

fn current_pid_matches() -> bool {
    (bpf_get_current_pid_tgid() >> 32) == unsafe { pid } as u64
}

#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn test_prog(_ctx: *const c_void) -> i32 {
    let mut data = CallbackCtx { output: 0 };

    if !current_pid_matches() {
        return 0;
    }

    let ret = bpf_loop(unsafe { nr_loops }, callback, &mut data as *mut CallbackCtx, 0);
    // C's `nr_loops_returned` is a 32-bit `int`, and the sign check happens
    // on that truncated value (`if (nr_loops_returned < 0) ...`), not on the
    // raw 64-bit helper return: the verifier's inlined bpf_loop error path
    // (kernel/bpf/fixups.c:inline_bpf_loop) sets r0 via a 32-bit
    // BPF_MOV32_IMM, which zero- (not sign-) extends the upper 32 bits, so
    // comparing the untruncated i64 against 0 misses negative error codes.
    let ret32 = ret as i32;
    unsafe {
        nr_loops_returned = ret32;
    }

    if ret32 < 0 {
        unsafe {
            err = ret32;
        }
    } else {
        unsafe {
            g_output = data.output;
        }
    }

    0
}

#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn prog_null_ctx(_ctx: *const c_void) -> i32 {
    if !current_pid_matches() {
        return 0;
    }

    let ret = bpf_loop(unsafe { nr_loops }, empty_callback, core::ptr::null_mut(), 0);
    unsafe {
        nr_loops_returned = ret as i32;
    }

    0
}

#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn prog_invalid_flags(_ctx: *const c_void) -> i32 {
    let mut data = CallbackCtx { output: 0 };

    if !current_pid_matches() {
        return 0;
    }

    let ret = bpf_loop(unsafe { nr_loops }, callback, &mut data as *mut CallbackCtx, 1);
    unsafe {
        err = ret as i32;
    }

    0
}

#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn prog_nested_calls(_ctx: *const c_void) -> i32 {
    let mut data = CallbackCtx { output: 0 };

    if !current_pid_matches() {
        return 0;
    }

    unsafe {
        nr_loops_returned = 0;
    }
    bpf_loop(unsafe { nr_loops }, nested_callback1, &mut data as *mut CallbackCtx, 0);

    unsafe {
        g_output = data.output;
    }

    0
}

extern "C" fn callback_set_f0(_index: u64, _ctx: *mut c_void) -> i64 {
    unsafe {
        g_output = 0xF0;
    }
    0
}

extern "C" fn callback_set_0f(_index: u64, _ctx: *mut c_void) -> i64 {
    unsafe {
        g_output = 0x0F;
    }
    0
}

/*
 * non-constant callback is a corner case for bpf_loop inline logic
 */
#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn prog_non_constant_callback(_ctx: *const c_void) -> i32 {
    if !current_pid_matches() {
        return 0;
    }

    unsafe {
        g_output = 0;
    }

    let callback: extern "C" fn(u64, *mut c_void) -> i64 = if unsafe { callback_selector } == 0x0F
    {
        callback_set_0f
    } else {
        callback_set_f0
    };

    bpf_loop(1, callback, core::ptr::null_mut(), 0);

    0
}

extern "C" fn stack_check_inner_callback(_index: u64, _ctx: *mut c_void) -> i64 {
    0
}

fn map1_lookup_elem(key: i32) -> i32 {
    let val = bpf_map_lookup_elem(&map1, &key) as *const i32;
    if val.is_null() {
        -1
    } else {
        unsafe { *val }
    }
}

fn map1_update_elem(key: i32, val: i32) {
    bpf_map_update_elem(&map1, &key, &val, 0);
}

extern "C" fn stack_check_outer_callback(_index: u64, _ctx: *mut c_void) -> i64 {
    let a = map1_lookup_elem(1);
    let b = map1_lookup_elem(2);
    let c = map1_lookup_elem(3);
    let d = map1_lookup_elem(4);
    let e = map1_lookup_elem(5);
    let f = map1_lookup_elem(6);

    bpf_loop(1, stack_check_inner_callback, core::ptr::null_mut(), 0);

    map1_update_elem(1, a + 1);
    map1_update_elem(2, b + 1);
    map1_update_elem(3, c + 1);
    map1_update_elem(4, d + 1);
    map1_update_elem(5, e + 1);
    map1_update_elem(6, f + 1);

    0
}

/* Some of the local variables in stack_check and
 * stack_check_outer_callback would be allocated on stack by
 * compiler. This test should verify that stack content for these
 * variables is preserved between calls to bpf_loop (might be an issue
 * if loop inlining allocates stack slots incorrectly). */
#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn stack_check(_ctx: *const c_void) -> i32 {
    if !current_pid_matches() {
        return 0;
    }

    let a = map1_lookup_elem(7);
    let b = map1_lookup_elem(8);
    let c = map1_lookup_elem(9);
    let d = map1_lookup_elem(10);
    let e = map1_lookup_elem(11);
    let f = map1_lookup_elem(12);

    bpf_loop(1, stack_check_outer_callback, core::ptr::null_mut(), 0);

    map1_update_elem(7, a + 1);
    map1_update_elem(8, b + 1);
    map1_update_elem(9, c + 1);
    map1_update_elem(10, d + 1);
    map1_update_elem(11, e + 1);
    map1_update_elem(12, f + 1);

    0
}

bpf_object!("GPL");
