#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_log_buf.c
// (bpf-rs-core idiom).
//
// `bad_prog` reads a[off] with off = 4000, far outside the 4-element
// array: it is MEANT to fail verification, which is the point of the test
// (prog_tests/log_buf.c checks the verifier log the failure produces). Only
// `good_prog` is loaded successfully.
//
// KNOWN GAP: prog_tests/log_buf.c loads the whole object and libbpf stops
// at the first program that fails, so it needs good_prog to come BEFORE
// bad_prog in the section — which is the order the C source declares them
// in. This pipeline emits functions in alphabetical symbol order instead
// ("bad_prog" < "good_prog"), and swapping the declarations here does not
// change it, so good_prog is never reached and good_log_buf stays empty:
// log_buf/obj_load_log_buf FAILS its `good_log_verbose` assertion. Both
// programs are otherwise byte-identical to the C and prove equivalent.

#![allow(non_upper_case_globals)]

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

#[no_mangle]
static mut a: [i32; 4] = [0; 4];

#[link_section = ".rodata"]
#[no_mangle]
static off: i32 = 4000;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn good_prog(ctx: *const c_void) -> i32 {
    unsafe {
        a[0] = ctx as i64 as i32;
        a[1]
    }
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn bad_prog(_ctx: *const c_void) -> i32 {
    // deliberately out of bounds; `off` is `const volatile` so the read is
    // not folded and the verifier sees the unbounded index
    let i = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(off)) };
    unsafe { *core::ptr::addr_of!(a).cast::<i32>().offset(i as isize) }
}

bpf_object!("GPL");
