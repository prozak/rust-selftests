#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/struct_ops_private_stack_recur.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::sink;

extern "C" {
    fn bpf_testmod_ops3_call_test_1();
}

#[no_mangle]
static mut val_i: i32 = 0;
#[no_mangle]
static mut val_j: i32 = 0;

#[inline(never)]
fn subprog2(a: *const i32, b: *const i32) -> i32 {
    unsafe { val_i + *a.add(1) + *b.add(20) }
}

// The `b` array's real stack footprint (400 bytes, matching the C original)
// must survive optimization for the kernel's private-stack-eligibility check
// (subprog stack depth >= BPF_PRIV_STACK_MIN_SIZE) to fire; a plain local
// array with only compile-time-constant reads/writes gets fully constant
// folded away by the whole-crate LTO-like opt pass despite #[inline(never)],
// collapsing the frame to a few bytes. Pinning the pointer via `sink` marks
// it escaped so SROA/IPSCCP can't see through it to the stack.
#[inline(never)]
fn subprog1(a: *const i32) -> i32 {
    // stack size 400 bytes
    let mut b: [i32; 100] = [0; 100];
    let mut bp: *mut i32 = b.as_mut_ptr();
    sink(&mut bp);
    unsafe { *bp.add(20) = 2 };
    subprog2(a, bp)
}

// struct bpf_testmod_ops3 (bpf_testmod.h): only the member this program
// initializes is declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bad_struct_ops.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops3 {
    test_1: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops3 {}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_1(_ctx: *const u64) -> i32 {
    // stack size 20 bytes
    let mut a: [i32; 5] = [0; 5];
    let mut ap: *mut i32 = a.as_mut_ptr();
    sink(&mut ap);
    unsafe { *ap.add(1) = 1 };
    unsafe { val_j += subprog1(ap) };
    unsafe { bpf_testmod_ops3_call_test_1() };
    0
}

#[link_section = ".struct_ops"]
#[no_mangle]
static testmod_1: bpf_testmod_ops3 = bpf_testmod_ops3 { test_1 };

bpf_object!("GPL");
