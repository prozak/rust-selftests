#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_module.c,
// bpf-rs-core idiom.
//
// prog_tests/test_struct_ops_module.c exercises four .struct_ops.link maps
// against CO-RE flavors of the kernel's struct bpf_testmod_ops:
//  - testmod_1 (bpf_testmod_ops, exact kernel name): test_1/test_2, plus
//    `data` (shadow-rewritten to 13 before load, read back by bpf_testmod.c
//    as the second arg to .test_2 alongside the fixed value 4).
//  - testmod_2 (___v2 flavor): test_1/test_2_v2 (test_2_v2 multiplies
//    instead of adding).
//  - testmod_zeroed (___zeroed flavor): adds `zeroed_op`/`zeroed` fields not
//    present in the real kernel struct; test_struct_ops_not_zeroed() asserts
//    load only succeeds when both are left at their zero value (libbpf
//    requires unknown extra fields to be zeroed).
//  - testmod_incompatible (___incompatible flavor): test_2's local prototype
//    intentionally doesn't match the kernel's, to prove libbpf doesn't
//    enforce prototype equality (the kernel verifier does the real check).
//
// BPF_PROG(test_2, int a, int b) / BPF_PROG(test_3, int a, int b) unpack
// ctx[0]/ctx[1] (see bpf_tracing.h's ___bpf_ctx_cast), same as
// struct_ops_kptr_return.rs.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;

#[no_mangle]
static mut test_1_result: i32 = 0;

#[no_mangle]
static mut test_2_result: i32 = 0;

#[link_section = "struct_ops/test_1"]
#[no_mangle]
extern "C" fn test_1(_ctx: *const u64) -> i32 {
    unsafe { test_1_result = 0xdeadbeefu32 as i32 };
    0
}

#[link_section = "struct_ops/test_2"]
#[no_mangle]
extern "C" fn test_2(ctx: *const u64) {
    let a = arg(ctx, 0) as i32;
    let b = arg(ctx, 1) as i32;
    unsafe { test_2_result = a + b };
}

#[link_section = "?struct_ops/test_3"]
#[no_mangle]
extern "C" fn test_3(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32;
    let b = arg(ctx, 1) as i32;
    let v = a + b + 3;
    unsafe { test_2_result = v };
    v
}

// struct bpf_testmod_ops (bpf_testmod.h): only the members this program
// initializes are declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_1: extern "C" fn(*const u64) -> i32,
    test_2: extern "C" fn(*const u64),
    data: i32,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_1: bpf_testmod_ops = bpf_testmod_ops {
    test_1,
    test_2,
    data: 1,
};

#[link_section = "struct_ops/test_2"]
#[no_mangle]
extern "C" fn test_2_v2(ctx: *const u64) {
    let a = arg(ctx, 0) as i32;
    let b = arg(ctx, 1) as i32;
    unsafe { test_2_result = a * b };
}

// CO-RE flavor of bpf_testmod_ops (___v2 suffix stripped before matching
// against the real kernel type).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops___v2 {
    test_1: extern "C" fn(*const u64) -> i32,
    test_2: extern "C" fn(*const u64),
}

unsafe impl Sync for bpf_testmod_ops___v2 {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_2: bpf_testmod_ops___v2 = bpf_testmod_ops___v2 {
    test_1,
    test_2: test_2_v2,
};

#[link_section = "struct_ops/test_3"]
#[no_mangle]
extern "C" fn zeroed_op(_ctx: *const u64) -> i32 {
    1
}

// CO-RE flavor of bpf_testmod_ops adding `zeroed_op`/`zeroed`, neither of
// which exist in the real kernel type; libbpf requires such extra fields to
// stay at their zero value for the object to load.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops___zeroed {
    test_1: extern "C" fn(*const u64) -> i32,
    test_2: extern "C" fn(*const u64),
    zeroed_op: extern "C" fn(*const u64) -> i32,
    zeroed: i32,
}

unsafe impl Sync for bpf_testmod_ops___zeroed {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_zeroed: bpf_testmod_ops___zeroed = bpf_testmod_ops___zeroed {
    test_1,
    test_2: test_2_v2,
    zeroed_op,
    zeroed: 0,
};

// CO-RE flavor of bpf_testmod_ops whose local `test_2` prototype
// deliberately doesn't match the kernel's (int* arg vs two ints); libbpf
// doesn't enforce prototype equality, only the kernel verifier does, so the
// actual Rust field type here (matching the real `test_2` function) is
// irrelevant to what's being exercised.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops___incompatible {
    test_1: extern "C" fn(*const u64) -> i32,
    test_2: extern "C" fn(*const u64),
    data: i32,
}

unsafe impl Sync for bpf_testmod_ops___incompatible {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_incompatible: bpf_testmod_ops___incompatible = bpf_testmod_ops___incompatible {
    test_1,
    test_2,
    data: 3,
};

bpf_object!("GPL");
