#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/struct_ops_private_stack_fail.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::sink;

extern "C" {
    fn bpf_testmod_ops3_call_test_2();
}

#[no_mangle]
static mut val_i: i32 = 0;
#[no_mangle]
static mut val_j: i32 = 0;

#[inline(never)]
fn subprog2(a: *const i32, b: *const i32) -> i32 {
    unsafe { val_i + *a.add(10) + *b.add(20) }
}

// See struct_ops_private_stack_recur.rs: pin `b`'s pointer via `sink` so the
// 200-byte stack frame survives opt's SROA/IPSCCP instead of being folded
// away, matching the C original's real stack footprint.
#[inline(never)]
fn subprog1(a: *const i32) -> i32 {
    // stack size 200 bytes
    let mut b: [i32; 50] = [0; 50];
    let mut bp: *mut i32 = b.as_mut_ptr();
    sink(&mut bp);
    unsafe { *bp.add(20) = 2 };
    subprog2(a, bp)
}

// struct bpf_testmod_ops3 (bpf_testmod.h): only the members this program
// initializes are declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bad_struct_ops.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops3 {
    test_1: extern "C" fn(*const u64) -> i32,
    test_2: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops3 {}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_1(_ctx: *const u64) -> i32 {
    // stack size 100 bytes
    let mut a: [i32; 25] = [0; 25];
    let mut ap: *mut i32 = a.as_mut_ptr();
    sink(&mut ap);
    unsafe { *ap.add(10) = 1 };
    unsafe { val_i = subprog1(ap) };
    unsafe { bpf_testmod_ops3_call_test_2() };
    0
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_2(_ctx: *const u64) -> i32 {
    // stack size 400 bytes
    let mut a: [i32; 100] = [0; 100];
    let mut ap: *mut i32 = a.as_mut_ptr();
    sink(&mut ap);
    unsafe { *ap.add(10) = 3 };
    unsafe { val_j = subprog1(ap) };
    0
}

#[link_section = ".struct_ops"]
#[no_mangle]
static testmod_1: bpf_testmod_ops3 = bpf_testmod_ops3 { test_1, test_2 };

bpf_object!("GPL");
