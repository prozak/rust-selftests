#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_rdonly_maps.c
// (bpf-rs-core idiom).
//
// `rdonly_values` is a genuinely-const (non-"const volatile") .rodata
// global with a real compile-time initializer; unlike the loader-patched
// config-global idiom (#[link_section = ".rodata"] + read_volatile of the
// global itself), the C source instead hides the *pointer*'s known value
// behind a `volatile`-qualified local (`unsigned * volatile p = ...`) so
// the compiler can't constant-fold the loops away. `helpers::sink()`
// (address materialized through an opaque asm barrier) reproduces that:
// once `p`'s value is opaque, subsequent `*p` reads/`p.add(1)` steps stay
// opaque too, so the loop trip counts are only knowable at verification
// time from the rodata map's real content — exactly what these subtests
// are checking the verifier can do.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::sink;
use core::ffi::c_void;

// Deliberately not 16-byte-aligned in size (a[4] + _y), mirroring the C
// comment: keeps struct-size-multiple-of-16 .rodata.cst16 placement out of
// the way for the clang build; harmless here since #[link_section] forces
// placement explicitly, but kept for layout fidelity.
#[repr(C)]
struct RdonlyValues {
    a: [u32; 4],
    _y: i8,
}

#[link_section = ".rodata"]
#[no_mangle]
static rdonly_values: RdonlyValues = RdonlyValues {
    a: [2, 3, 4, 5],
    _y: 0,
};

#[repr(C)]
struct Res {
    did_run: u32,
    iters: u32,
    sum: u32,
}

#[no_mangle]
static mut res: Res = Res {
    did_run: 0,
    iters: 0,
    sum: 0,
};

#[link_section = "raw_tracepoint/sys_enter:skip_loop"]
#[no_mangle]
extern "C" fn skip_loop(_ctx: *const c_void) -> i32 {
    let mut p = rdonly_values.a.as_ptr() as *mut u32;
    sink(&mut p);
    let mut iters: u32 = 0;
    let mut sum: u32 = 0;

    // we should never enter this loop
    while unsafe { *p } & 1 != 0 {
        iters += 1;
        sum = sum.wrapping_add(unsafe { *p });
        p = unsafe { p.add(1) };
    }

    unsafe {
        res.did_run = 1;
        res.iters = iters;
        res.sum = sum;
    }
    0
}

#[link_section = "raw_tracepoint/sys_enter:part_loop"]
#[no_mangle]
extern "C" fn part_loop(_ctx: *const c_void) -> i32 {
    let mut p = rdonly_values.a.as_ptr() as *mut u32;
    sink(&mut p);
    let mut iters: u32 = 0;
    let mut sum: u32 = 0;

    // validate verifier can derive loop termination
    while unsafe { *p } < 5 {
        iters += 1;
        sum = sum.wrapping_add(unsafe { *p });
        p = unsafe { p.add(1) };
    }

    unsafe {
        res.did_run = 1;
        res.iters = iters;
        res.sum = sum;
    }
    0
}

#[link_section = "raw_tracepoint/sys_enter:full_loop"]
#[no_mangle]
extern "C" fn full_loop(_ctx: *const c_void) -> i32 {
    let mut p = rdonly_values.a.as_ptr() as *mut u32;
    sink(&mut p);
    let mut i: i32 = rdonly_values.a.len() as i32;
    let mut iters: u32 = 0;
    let mut sum: u32 = 0;

    // validate verifier can allow full loop as well
    while i > 0 {
        iters += 1;
        sum = sum.wrapping_add(unsafe { *p });
        p = unsafe { p.add(1) };
        i -= 1;
    }

    unsafe {
        res.did_run = 1;
        res.iters = iters;
        res.sum = sum;
    }
    0
}

bpf_object!("GPL");
