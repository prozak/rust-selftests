#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/struct_ops_id_ops_mapping1.c,
// bpf-rs-core idiom.
//
// The C source's macro
//   #define bpf_kfunc_multi_st_ops_test_1(args) bpf_kfunc_multi_st_ops_test_1(args, st_ops_id)
// just threads the `st_ops_id` global through as the kfunc's second arg;
// translated here as an explicit extra argument at each call site.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_task_btf;
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
}

#[repr(C)]
struct st_ops_args {
    a: u64,
}

// struct bpf_testmod_multi_st_ops (bpf_testmod.h): only the member this
// program initializes is declared — libbpf's struct_ops relocation matches
// local struct members against the kernel type by name (see
// struct_ops_autocreate2.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_multi_st_ops {
    test_1: extern "C" fn(*mut st_ops_args) -> i32,
}

unsafe impl Sync for bpf_testmod_multi_st_ops {}

extern "C" {
    fn bpf_kfunc_multi_st_ops_test_1(args: *mut st_ops_args, id: u32) -> i32;
}

const MAP1_MAGIC: i32 = 1234;

#[no_mangle]
static mut st_ops_id: i32 = 0;
#[no_mangle]
static mut test_pid: i32 = 0;
#[no_mangle]
static mut test_err: i32 = 0;

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_1(_args: *mut st_ops_args) -> i32 {
    MAP1_MAGIC
}

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn sys_enter(_ctx: *const u64) -> i32 {
    let mut args = st_ops_args { a: 0 };
    let task: *mut task_struct = bpf_get_current_task_btf();

    let pid = unsafe { test_pid };
    if pid == 0 || *unsafe { &*task }.pid().get().unwrap() != pid {
        return 0;
    }

    let id = unsafe { st_ops_id } as u32;
    let ret = unsafe { bpf_kfunc_multi_st_ops_test_1(&mut args, id) };
    if ret != MAP1_MAGIC {
        unsafe { test_err += 1 };
    }

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_prog(_ctx: *const core::ffi::c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };

    let id = unsafe { st_ops_id } as u32;
    let ret = unsafe { bpf_kfunc_multi_st_ops_test_1(&mut args, id) };
    if ret != MAP1_MAGIC {
        unsafe { test_err += 1 };
    }

    0
}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static st_ops_map: bpf_testmod_multi_st_ops = bpf_testmod_multi_st_ops { test_1 };

bpf_object!("GPL");
