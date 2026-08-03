#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_refcounted.c,
// bpf-rs-core idiom.
//
// The `task` argument's referenced-kptr status (ref_obj_id > 0) comes from
// the kernel module's own BTF stub (bpf_testmod.c tags it `task__ref`),
// entirely independent of this program's source language, so `task_struct`
// here can stay an opaque pointer target — the program never dereferences
// it, only forwards it to bpf_task_release (matches struct_ops_maybe_null_fail.rs's
// pattern of a minimal, single-field local bpf_testmod_ops carrying just the
// member under test).

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;

#[repr(C)]
struct task_struct {
    _opaque: [u8; 0],
}

extern "C" {
    fn bpf_task_release(p: *mut task_struct);
}

#[link_section = "struct_ops/test_refcounted"]
#[no_mangle]
extern "C" fn refcounted(ctx: *const u64) -> i32 {
    let dummy = arg(ctx, 0) as i32;
    let task = arg(ctx, 1) as *mut task_struct;
    if dummy == 1 {
        unsafe { bpf_task_release(task) };
    } else {
        unsafe { bpf_task_release(task) };
    }
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_refcounted: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_refcounted: bpf_testmod_ops = bpf_testmod_ops {
    test_refcounted: refcounted,
};

bpf_object!("GPL");
