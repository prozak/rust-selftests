// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![allow(non_camel_case_types, non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/user_ringbuf_fail.c
// (bpf-rs-core idiom).
//
// bpf_user_ringbuf_drain() callback rejections (prog_tests/user_ringbuf.c:
// RUN_TESTS(user_ringbuf_fail)). The static callbacks are extern "C" fns
// passed to the helper as in user_ringbuf_success.rs; the dynptr argument
// is `*mut bpf_dynptr` so the C's `dynptr - 1` / `dynptr + 1` /
// `dynptr += 1024` are the same 16-byte-scaled pointer arithmetic. The
// __noinline global subprogram keeps its `struct bpf_dynptr *` parameter
// type (the verifier reads it from BTF). `static int map_value` is a
// private static. bpf_printk is the printk! macro of
// user_ringbuf_success.rs.

use bpf_rs_core::helpers::{
    bpf_dynptr_data, bpf_dynptr_from_mem, bpf_ringbuf_discard_dynptr, bpf_ringbuf_reserve_dynptr,
    bpf_ringbuf_submit_dynptr, bpf_trace_printk, bpf_user_ringbuf_drain,
};
use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;
use core::ptr::{addr_of_mut, null_mut};

macro_rules! printk {
    ($lit:literal $(, $arg:expr)*) => {{
        static FMT: &[u8] = $lit;
        bpf_trace_printk(
            FMT.as_ptr() as *const c_void,
            FMT.len() as u32,
            printk!(@arg 0 $(, $arg)*),
            printk!(@arg 1 $(, $arg)*),
            0,
        )
    }};
    (@arg $n:tt) => { 0u64 };
    (@arg 0, $a:expr) => { $a as u64 };
    (@arg 1, $a:expr) => { 0u64 };
}

#[repr(C)]
struct sample {
    pid: i32,
    seq: i32,
    value: i64,
    comm: [u8; 16],
}

// struct bpf_dynptr { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

bpf_map! {
    user_ringbuf {
        r#type: *const [i32; 31], // BPF_MAP_TYPE_USER_RINGBUF
        max_entries: *const [i32; 4096],
    }
}

bpf_map! {
    ringbuf {
        r#type: *const [i32; 27], // BPF_MAP_TYPE_RINGBUF
        max_entries: *const [i32; 2],
    }
}

static mut map_value: i32 = 0;

extern "C" fn bad_access1(dynptr: *mut c_void, _context: *mut c_void) -> i64 {
    let dynptr = dynptr as *mut bpf_dynptr;

    let _sample = bpf_dynptr_data(
        dynptr.wrapping_sub(1) as *const c_void,
        0,
        core::mem::size_of::<sample>() as u64,
    ) as *const sample;
    printk!(b"Was able to pass bad pointer %lx\n\0", (dynptr as u64).wrapping_sub(1));

    0
}

// A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
// not be able to read before the pointer.
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn user_ringbuf_callback_bad_access1(_ctx: *mut c_void) -> i32 {
    bpf_user_ringbuf_drain(&user_ringbuf, bad_access1, null_mut::<c_void>(), 0);

    0
}

extern "C" fn bad_access2(dynptr: *mut c_void, _context: *mut c_void) -> i64 {
    let dynptr = dynptr as *mut bpf_dynptr;

    let _sample = bpf_dynptr_data(
        dynptr.wrapping_add(1) as *const c_void,
        0,
        core::mem::size_of::<sample>() as u64,
    ) as *const sample;
    printk!(b"Was able to pass bad pointer %lx\n\0", (dynptr as u64).wrapping_add(1));

    0
}

// A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
// not be able to read past the end of the pointer.
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn user_ringbuf_callback_bad_access2(_ctx: *mut c_void) -> i32 {
    bpf_user_ringbuf_drain(&user_ringbuf, bad_access2, null_mut::<c_void>(), 0);

    0
}

extern "C" fn write_forbidden(dynptr: *mut c_void, _context: *mut c_void) -> i64 {
    unsafe { *(dynptr as *mut i64) = 0 };

    0
}

// A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
// not be able to write to that pointer.
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn user_ringbuf_callback_write_forbidden(_ctx: *mut c_void) -> i32 {
    bpf_user_ringbuf_drain(&user_ringbuf, write_forbidden, null_mut::<c_void>(), 0);

    0
}

extern "C" fn null_context_write(_dynptr: *mut c_void, context: *mut c_void) -> i64 {
    unsafe { *(context as *mut u64) = 0 };

    0
}

// A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
// not be able to write to that pointer.
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn user_ringbuf_callback_null_context_write(_ctx: *mut c_void) -> i32 {
    bpf_user_ringbuf_drain(&user_ringbuf, null_context_write, null_mut::<c_void>(), 0);

    0
}

extern "C" fn null_context_read(_dynptr: *mut c_void, context: *mut c_void) -> i64 {
    let id = unsafe { *(context as *const u64) };

    printk!(b"Read id %lu\n\0", id);

    0
}

// A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
// not be able to write to that pointer.
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn user_ringbuf_callback_null_context_read(_ctx: *mut c_void) -> i32 {
    bpf_user_ringbuf_drain(&user_ringbuf, null_context_read, null_mut::<c_void>(), 0);

    0
}

extern "C" fn try_discard_dynptr(dynptr: *mut c_void, _context: *mut c_void) -> i64 {
    bpf_ringbuf_discard_dynptr(dynptr, 0);

    0
}

// A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
// not be able to read past the end of the pointer.
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn user_ringbuf_callback_discard_dynptr(_ctx: *mut c_void) -> i32 {
    bpf_user_ringbuf_drain(&user_ringbuf, try_discard_dynptr, null_mut::<c_void>(), 0);

    0
}

extern "C" fn try_submit_dynptr(dynptr: *mut c_void, _context: *mut c_void) -> i64 {
    bpf_ringbuf_submit_dynptr(dynptr, 0);

    0
}

// A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
// not be able to read past the end of the pointer.
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn user_ringbuf_callback_submit_dynptr(_ctx: *mut c_void) -> i32 {
    bpf_user_ringbuf_drain(&user_ringbuf, try_submit_dynptr, null_mut::<c_void>(), 0);

    0
}

extern "C" fn invalid_drain_callback_return(_dynptr: *mut c_void, _context: *mut c_void) -> i64 {
    2
}

// A callback that accesses a dynptr in a bpf_user_ringbuf_drain callback should
// not be able to write to that pointer.
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn user_ringbuf_callback_invalid_return(_ctx: *mut c_void) -> i32 {
    bpf_user_ringbuf_drain(&user_ringbuf, invalid_drain_callback_return, null_mut::<c_void>(), 0);

    0
}

extern "C" fn try_reinit_dynptr_mem(dynptr: *mut c_void, _context: *mut c_void) -> i64 {
    bpf_dynptr_from_mem(unsafe { addr_of_mut!(map_value) } as *mut c_void, 4, 0, dynptr);
    0
}

extern "C" fn try_reinit_dynptr_ringbuf(dynptr: *mut c_void, _context: *mut c_void) -> i64 {
    bpf_ringbuf_reserve_dynptr(&ringbuf, 8, 0, dynptr);
    0
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn user_ringbuf_callback_reinit_dynptr_mem(_ctx: *mut c_void) -> i32 {
    bpf_user_ringbuf_drain(&user_ringbuf, try_reinit_dynptr_mem, null_mut::<c_void>(), 0);
    0
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn user_ringbuf_callback_reinit_dynptr_ringbuf(_ctx: *mut c_void) -> i32 {
    bpf_user_ringbuf_drain(&user_ringbuf, try_reinit_dynptr_ringbuf, null_mut::<c_void>(), 0);
    0
}

#[no_mangle]
#[inline(never)]
extern "C" fn global_call_bpf_dynptr_data(dynptr: *mut bpf_dynptr) -> i64 {
    bpf_dynptr_data(dynptr as *const c_void, 0xA, 0xA);
    0
}

extern "C" fn callback_adjust_bpf_dynptr_reg_off(dynptr: *mut c_void, _ctx: *mut c_void) -> i64 {
    let dynptr = dynptr as *mut bpf_dynptr;

    // global_call_bpf_dynptr_data(dynptr += 1024)
    global_call_bpf_dynptr_data(dynptr.wrapping_add(1024));
    0
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn user_ringbuf_callback_const_ptr_to_dynptr_reg_off(_ctx: *mut c_void) -> i32 {
    bpf_user_ringbuf_drain(
        &user_ringbuf,
        callback_adjust_bpf_dynptr_reg_off,
        null_mut::<c_void>(),
        0,
    );
    0
}

test_tags! {
    user_ringbuf_callback_bad_access1: __failure, __msg("negative offset dynptr_ptr ptr");
    user_ringbuf_callback_bad_access2: __failure, __msg("dereference of modified dynptr_ptr ptr");
    user_ringbuf_callback_write_forbidden: __failure, __msg("invalid mem access 'dynptr_ptr'");
    user_ringbuf_callback_null_context_write: __failure, __msg("invalid mem access 'scalar'");
    user_ringbuf_callback_null_context_read: __failure, __msg("invalid mem access 'scalar'");
    user_ringbuf_callback_discard_dynptr: __failure, __msg("CONST_PTR_TO_DYNPTR cannot be released");
    user_ringbuf_callback_submit_dynptr: __failure, __msg("CONST_PTR_TO_DYNPTR cannot be released");
    user_ringbuf_callback_invalid_return: __failure, __msg("At callback return the register R0 has ");
    user_ringbuf_callback_reinit_dynptr_mem: __failure, __msg("Dynptr has to be an uninitialized dynptr");
    user_ringbuf_callback_reinit_dynptr_ringbuf: __failure, __msg("Dynptr has to be an uninitialized dynptr");
    user_ringbuf_callback_const_ptr_to_dynptr_reg_off: __failure, __msg("dereference of modified dynptr_ptr ptr R1 off=16384 disallowed");
}

bpf_object!("GPL");
