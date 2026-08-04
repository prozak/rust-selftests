#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_autocreate.c,
// bpf-rs-core idiom.
//
// prog_tests/struct_ops_autocreate.c exercises libbpf's struct_ops
// autocreate/autoload behavior across four maps:
//  - testmod_1 (.struct_ops.link, ___v1 flavor matching the real kernel
//    struct bpf_testmod_ops): loadable as-is, attach + test_1() sets
//    test_1_result to 42.
//  - testmod_2 (.struct_ops.link, ___v2 flavor with an extra
//    does_not_exist member): its BTF doesn't match the kernel type, so
//    cant_load_full_object() expects load to fail with ENOTSUP unless its
//    autocreate is disabled first.
//  - optional_map ("?.struct_ops") / optional_map2 ("?.struct_ops.link"):
//    optional maps, autocreate false by default.

use bpf_rs_core::bpf_object;

#[link_section = "struct_ops/test_1"]
#[no_mangle]
extern "C" fn test_1(_ctx: *const u64) -> i32 {
    unsafe { test_1_result = 42 };
    0
}

#[link_section = "struct_ops/test_1"]
#[no_mangle]
extern "C" fn test_2(_ctx: *const u64) -> i32 {
    0
}

#[no_mangle]
static mut test_1_result: i32 = 0;

// struct bpf_testmod_ops___v1 / ___v2 (bpf_testmod.h, CO-RE flavors of the
// kernel's bpf_testmod_ops): only the members these programs initialize are
// declared — libbpf's struct_ops relocation matches local struct members
// against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops___v1 {
    test_1: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops___v1 {}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops___v2 {
    test_1: extern "C" fn(*const u64) -> i32,
    does_not_exist: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops___v2 {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_1: bpf_testmod_ops___v1 = bpf_testmod_ops___v1 { test_1 };

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_2: bpf_testmod_ops___v2 = bpf_testmod_ops___v2 {
    test_1,
    does_not_exist: test_2,
};

#[link_section = "?.struct_ops"]
#[no_mangle]
static optional_map: bpf_testmod_ops___v1 = bpf_testmod_ops___v1 { test_1 };

#[link_section = "?.struct_ops.link"]
#[no_mangle]
static optional_map2: bpf_testmod_ops___v1 = bpf_testmod_ops___v1 { test_1 };

bpf_object!("GPL");
