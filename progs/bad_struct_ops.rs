#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bad_struct_ops.c,
// bpf-rs-core idiom.
//
// prog_tests/bad_struct_ops.c's invalid_prog_reuse() expects
// bad_struct_ops__load() to fail with libbpf's "invalid reuse of prog
// test_1" message: testmod_1.test_1 and testmod_2.test_1 both reference
// the same `test_1` program from two different struct_ops maps, which
// libbpf rejects while resolving struct_ops kernel members. This is a
// libbpf-load-time check, not a verifier __failure/__msg case, so the
// object must still be loadable enough to reach that check.

use bpf_rs_core::bpf_object;

#[link_section = "struct_ops/test_1"]
#[no_mangle]
extern "C" fn test_1(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "struct_ops/test_2"]
#[no_mangle]
extern "C" fn test_2(_ctx: *const u64) -> i32 {
    0
}

// struct bpf_testmod_ops / bpf_testmod_ops2 (bpf_testmod.h): only the
// members these programs initialize are declared — libbpf's struct_ops
// relocation matches local struct members against the kernel type by
// name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_1: extern "C" fn(*const u64) -> i32,
    test_2: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops {}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops2 {
    test_1: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops2 {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_1: bpf_testmod_ops = bpf_testmod_ops {
    test_1,
    test_2,
};

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_2: bpf_testmod_ops2 = bpf_testmod_ops2 { test_1 };

bpf_object!("GPL");
