#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/struct_ops_id_ops_mapping2.c,
// bpf-rs-core idiom.
//
// prog_tests/test_struct_ops_id_ops_mapping.c loads this side by side with
// struct_ops_id_ops_mapping1 (an untranslated sibling object): both attach
// their own `st_ops_map` under the kernel module's
// "bpf_testmod_multi_st_ops" struct_ops type, then patch `st_ops_id` from
// the loaded map's own `bpf_map_get_info_by_fd()` id, so the id -> ops
// mapping this kfunc performs is self-referential rather than fixed at
// compile time. `bpf_kfunc_multi_st_ops_test_1(args, id)` looks the
// registered ops up by that id and calls its own `.test_1`, so a correct
// program must return this object's own MAP2_MAGIC.

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

extern "C" {
    fn bpf_kfunc_multi_st_ops_test_1(args: *mut st_ops_args, id: u32) -> i32;
}

#[no_mangle]
static mut st_ops_id: i32 = 0;
#[no_mangle]
static mut test_pid: i32 = 0;
#[no_mangle]
static mut test_err: i32 = 0;

const MAP2_MAGIC: i32 = 4567;

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_1(_ctx: *const u64) -> i32 {
    MAP2_MAGIC
}

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn sys_enter(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();

    let pid = unsafe { test_pid };
    if pid == 0 || *unsafe { &*task }.pid().get().unwrap() != pid {
        return 0;
    }

    let mut args = st_ops_args { a: 0 };
    let id = unsafe { st_ops_id } as u32;
    let ret = unsafe { bpf_kfunc_multi_st_ops_test_1(&mut args, id) };
    if ret != MAP2_MAGIC {
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
    if ret != MAP2_MAGIC {
        unsafe { test_err += 1 };
    }

    0
}

// struct bpf_testmod_multi_st_ops (bpf_testmod.h): only the member this
// program initializes is declared — libbpf's struct_ops relocation matches
// local struct members against the kernel type by name (see
// bad_struct_ops.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_multi_st_ops {
    test_1: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_multi_st_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static st_ops_map: bpf_testmod_multi_st_ops = bpf_testmod_multi_st_ops { test_1 };

bpf_object!("GPL");
