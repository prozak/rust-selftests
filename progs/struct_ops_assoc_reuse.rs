#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_assoc_reuse.c,
// bpf-rs-core idiom.
//
// prog_tests/test_struct_ops_assoc.c's test_st_ops_assoc_reuse() only
// associates syscall_prog_a/syscall_prog_b (not test_1_a itself, which the
// kernel wouldn't allow anyway - see struct_ops_assoc.c's rejected explicit
// assoc of test_1_a). The same test_1_a program backs both st_ops_map_a's
// and st_ops_map_b's .test_1 member; because that struct_ops association is
// now ambiguous, bpf_kfunc_multi_st_ops_test_1_assoc() called *from inside*
// test_1_a (recursively, guarded by `recur` against the outer syscall_prog
// call already running it) must fail (-1), while a top-level call from
// syscall_prog_a/_b still resolves through the map association picked at
// invocation time and returns MAP_A_MAGIC.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use core::ffi::c_void;

const MAP_A_MAGIC: i32 = 1234;

#[allow(non_camel_case_types)]
#[repr(C)]
struct st_ops_args {
    a: u64,
}

extern "C" {
    fn bpf_kfunc_multi_st_ops_test_1_assoc(args: *mut st_ops_args) -> i32;
}

#[no_mangle]
static mut test_err_a: i32 = 0;

#[no_mangle]
static mut recur: i32 = 0;

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_1_a(ctx: *const u64) -> i32 {
    let args = arg(ctx, 0) as *mut st_ops_args;

    if unsafe { recur } == 0 {
        unsafe { recur += 1 };
        let ret = unsafe { bpf_kfunc_multi_st_ops_test_1_assoc(args) };
        if ret != -1 {
            unsafe { test_err_a += 1 };
        }
        unsafe { recur -= 1 };
    }

    MAP_A_MAGIC
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_prog_a(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    let ret = unsafe { bpf_kfunc_multi_st_ops_test_1_assoc(&mut args) };
    if ret != MAP_A_MAGIC {
        unsafe { test_err_a += 1 };
    }
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_multi_st_ops {
    test_1: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_multi_st_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static st_ops_map_a: bpf_testmod_multi_st_ops = bpf_testmod_multi_st_ops { test_1: test_1_a };

#[no_mangle]
static mut test_err_b: i32 = 0;

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_prog_b(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    let ret = unsafe { bpf_kfunc_multi_st_ops_test_1_assoc(&mut args) };
    if ret != MAP_A_MAGIC {
        unsafe { test_err_b += 1 };
    }
    0
}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static st_ops_map_b: bpf_testmod_multi_st_ops = bpf_testmod_multi_st_ops { test_1: test_1_a };

bpf_object!("GPL");
