#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/find_vma_fail1.c,
// bpf-rs-core idiom.
//
// prog_tests/find_vma.c's test_illegal_write_vma() asserts
// find_vma_fail1__open_and_load() FAILS (ASSERT_ERR_PTR): the
// bpf_find_vma() callback writes into vma->vm_start, a plain kernel struct
// field reached through a trusted PTR_TO_BTF_ID. raw_tp programs have no
// per-prog-type btf_struct_access hook, so verifier.c's
// check_ptr_to_btf_access falls to its default arm, which permits writes
// only through program-allocated objects; any other write is rejected with
// "only read is supported" before the specific field is even considered
// (kernel/bpf/verifier.c). No __failure/__msg BTF decl tag involved — this
// is a real, unconditional verifier rejection, so the straightforward
// translation reproduces it. Mirrors find_vma_fail2.rs's sibling pattern.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_find_vma, bpf_get_current_task_btf};
use btf_macros::btf;

#[btf]
struct vm_area_struct {
    vm_start: u64,
}

#[allow(non_camel_case_types)]
struct callback_ctx {
    dummy: i32,
}

extern "C" fn write_vma(
    _task: *mut c_void,
    vma: *mut vm_area_struct,
    _data: *mut callback_ctx,
) -> i64 {
    // writing to vma, which is illegal
    unsafe {
        *(&*vma).vm_start().as_mut_ptr() = 0xffffffffff600000;
    }

    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handle_getpid(_ctx: *const c_void) -> i32 {
    let task: *mut c_void = bpf_get_current_task_btf();
    let mut data = callback_ctx { dummy: 0 };

    bpf_find_vma(task, 0, write_vma, &mut data, 0);
    0
}

bpf_object!("GPL");
