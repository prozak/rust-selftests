#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_private_stack.c,
// bpf-rs-core idiom.
//
// prog_tests/struct_ops_private_stack.c's test_private_stack() attaches
// testmod_1, triggers a module read, then asserts skel->bss->val_i == 3 and
// skel->bss->val_j == 8. Large fixed-size local arrays (a[100]/b[50] etc.)
// are kept the same size as the C source to match its stack-depth shape;
// all indexed access goes through raw pointer arithmetic (`.add()`) instead
// of `[]` indexing so no bounds-check panic branch is reachable.

use bpf_rs_core::bpf_object;

extern "C" {
    fn bpf_testmod_ops3_call_test_2();
}

#[no_mangle]
static mut val_i: i32 = 0;
#[no_mangle]
static mut val_j: i32 = 0;

#[inline(never)]
fn subprog2(a: *mut i32, b: *mut i32) -> i32 {
    unsafe { val_i + *a.add(10) + *b.add(20) }
}

#[inline(never)]
fn subprog1(a: *mut i32) -> i32 {
    // stack size 200 bytes
    let mut b: [i32; 50] = [0; 50];
    unsafe {
        *b.as_mut_ptr().add(20) = 2;
    }
    subprog2(a, b.as_mut_ptr())
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_1(_ctx: *const u64) -> i32 {
    // stack size 400 bytes
    let mut a: [i32; 100] = [0; 100];
    unsafe {
        *a.as_mut_ptr().add(10) = 1;
        val_i = subprog1(a.as_mut_ptr());
        bpf_testmod_ops3_call_test_2();
    }
    0
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_2(_ctx: *const u64) -> i32 {
    // stack size 200 bytes
    let mut a: [i32; 50] = [0; 50];
    unsafe {
        *a.as_mut_ptr().add(10) = 3;
        val_j = subprog1(a.as_mut_ptr());
    }
    0
}

// struct bpf_testmod_ops3 (bpf_testmod.h): only the members this program
// initializes are declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops3 {
    test_1: extern "C" fn(*const u64) -> i32,
    test_2: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops3 {}

#[link_section = ".struct_ops"]
#[no_mangle]
static testmod_1: bpf_testmod_ops3 = bpf_testmod_ops3 { test_1, test_2 };

bpf_object!("GPL");
