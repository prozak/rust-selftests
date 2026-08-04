#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_assoc.c
// (bpf-rs-core idiom). Two independent struct_ops maps (a, b), each with its
// own struct_ops callback, tp_btf/sys_enter tracer, and syscall program that
// all call the same kfunc bpf_kfunc_multi_st_ops_test_1_assoc(). See
// struct_ops_assoc_in_timer.rs for the st_ops_args layout and
// bpf_testmod_multi_st_ops field-by-name relocation idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_task_btf;
use btf_macros::btf;
use core::ffi::c_void;

const MAP_A_MAGIC: i32 = 1234;
const MAP_B_MAGIC: i32 = 5678;

#[btf]
struct task_struct {
    pid: i32,
}

#[repr(C)]
struct st_ops_args {
    a: u64,
}

extern "C" {
    fn bpf_kfunc_multi_st_ops_test_1_assoc(args: *mut st_ops_args) -> i32;
}

#[no_mangle]
static mut test_pid: i32 = 0;

/* Programs associated with st_ops_map_a */

#[no_mangle]
static mut test_err_a: i32 = 0;

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_1_a(_ctx: *const u64) -> i32 {
    MAP_A_MAGIC
}

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn sys_enter_prog_a(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let pid = *unsafe { &*task }.pid().get().unwrap();
    if unsafe { test_pid } == 0 || pid != unsafe { test_pid } {
        return 0;
    }

    let mut args = st_ops_args { a: 0 };
    let ret = unsafe { bpf_kfunc_multi_st_ops_test_1_assoc(&mut args) };
    if ret != MAP_A_MAGIC {
        unsafe { test_err_a += 1 };
    }

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_prog_a(_ctx: *mut c_void) -> i32 {
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

/* Programs associated with st_ops_map_b */

#[no_mangle]
static mut test_err_b: i32 = 0;

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_1_b(_ctx: *const u64) -> i32 {
    MAP_B_MAGIC
}

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn sys_enter_prog_b(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let pid = *unsafe { &*task }.pid().get().unwrap();
    if unsafe { test_pid } == 0 || pid != unsafe { test_pid } {
        return 0;
    }

    let mut args = st_ops_args { a: 0 };
    let ret = unsafe { bpf_kfunc_multi_st_ops_test_1_assoc(&mut args) };
    if ret != MAP_B_MAGIC {
        unsafe { test_err_b += 1 };
    }

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_prog_b(_ctx: *mut c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    let ret = unsafe { bpf_kfunc_multi_st_ops_test_1_assoc(&mut args) };
    if ret != MAP_B_MAGIC {
        unsafe { test_err_b += 1 };
    }

    0
}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static st_ops_map_b: bpf_testmod_multi_st_ops = bpf_testmod_multi_st_ops { test_1: test_1_b };

bpf_object!("GPL");
