#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_autocreate2.c,
// bpf-rs-core idiom.
//
// prog_tests/struct_ops_autocreate.c's autoload_and_shadow_vars() opens this
// object with both foo/bar autoload off by default (SEC("?struct_ops/...")),
// then rewrites testmod_1.test_1 from bar to foo via shadow vars before load
// — which must flip foo's autoload to true and leave bar's off.

use bpf_rs_core::bpf_object;

#[link_section = "?struct_ops/test_1"]
#[no_mangle]
extern "C" fn foo(_ctx: *const u64) -> i32 {
    unsafe { test_1_result = 42 };
    0
}

#[link_section = "?struct_ops/test_1"]
#[no_mangle]
extern "C" fn bar(_ctx: *const u64) -> i32 {
    unsafe { test_1_result = 24 };
    0
}

#[no_mangle]
static mut test_1_result: i32 = 0;

// struct bpf_testmod_ops (bpf_testmod.h): only the member this program
// initializes is declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_1: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_1: bpf_testmod_ops = bpf_testmod_ops { test_1: bar };

bpf_object!("GPL");
