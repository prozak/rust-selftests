// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/iters_task_vma.c,
// bpf-rs-core idiom. iter_task_vma_for_each translates the C source's
// `bpf_for_each(task_vma, vma, task, 0)` open-coded iterator as literally as
// possible: extern kfuncs bpf_iter_task_vma_new/next/destroy, called
// directly in place of the macro (same pattern as iters_task.rs's
// bpf_iter_task and dmabuf_iter.rs's bpf_iter_dmabuf).
//
// `vm_ranges` is an array of an ANONYMOUS C `struct { __u64 vm_start,
// vm_end; }`; bpftool's skeleton codegen only inlines a struct's fields when
// its BTF name is empty, and a named `struct vm_range vm_ranges[1000]` would
// leave the skeleton with an incomplete type. The Rust struct is named
// vm_range and `// BTF_ANON: vm_range` makes scripts/btf_rename.py blank
// its BTF name, as test_global_percpu_data.rs does for its anonymous struct.
//
// BTF_ANON: vm_range

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_task_btf;
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
}

#[btf]
struct vm_area_struct {
    vm_start: u64,
    vm_end: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct vm_range {
    vm_start: u64,
    vm_end: u64,
}

// struct bpf_iter_task_vma { __u64 __opaque[1]; } __attribute__((aligned(8)));
#[repr(C, align(8))]
struct bpf_iter_task_vma {
    __opaque: [u64; 1],
}

extern "C" {
    fn bpf_iter_task_vma_new(it: *mut bpf_iter_task_vma, task: *mut task_struct, addr: u64) -> i32;
    fn bpf_iter_task_vma_next(it: *mut bpf_iter_task_vma) -> *mut vm_area_struct;
    fn bpf_iter_task_vma_destroy(it: *mut bpf_iter_task_vma);
}

#[no_mangle]
static mut target_pid: i32 = 0;
#[no_mangle]
static mut vmas_seen: u32 = 0;
#[no_mangle]
static mut vm_ranges: [vm_range; 1000] = [vm_range {
    vm_start: 0,
    vm_end: 0,
}; 1000];

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn iter_task_vma_for_each(_ctx: *const c_void) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    let mut seen: u32 = 0;

    if *unsafe { &*task }.pid().get().unwrap() != unsafe { target_pid } {
        return 0;
    }

    if unsafe { vmas_seen } != 0 {
        return 0;
    }

    let mut it = bpf_iter_task_vma { __opaque: [0; 1] };
    unsafe { bpf_iter_task_vma_new(&mut it, task, 0) };

    let ranges_base = unsafe { core::ptr::addr_of_mut!(vm_ranges) as *mut vm_range };
    loop {
        if seen >= 1000 {
            break;
        }
        let vma = unsafe { bpf_iter_task_vma_next(&mut it) };
        if vma.is_null() {
            break;
        }
        let vma_ref = unsafe { &*vma };
        let vm_start = *vma_ref.vm_start().get().unwrap();
        let vm_end = *vma_ref.vm_end().get().unwrap();

        unsafe {
            let slot = ranges_base.add(seen as usize);
            (*slot).vm_start = vm_start;
            (*slot).vm_end = vm_end;
        }
        seen += 1;
    }
    unsafe { bpf_iter_task_vma_destroy(&mut it) };

    unsafe { vmas_seen = seen };
    0
}

bpf_object!("GPL");
