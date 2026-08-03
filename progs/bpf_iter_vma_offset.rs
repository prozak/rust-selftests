#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_vma_offset.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_seq_printf;
use btf_macros::btf;
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__task_vma {
    meta: *mut bpf_iter_meta,
    task: *mut task_struct,
    vma: *mut vm_area_struct,
}

#[btf]
struct task_struct {
    tgid: i32,
}

#[btf]
struct vm_area_struct {
    vm_start: u64,
    vm_end: u64,
    vm_pgoff: u64,
}

#[no_mangle]
static mut unique_tgid_cnt: u32 = 0;
#[no_mangle]
static mut address: u64 = 0;
#[no_mangle]
static mut offset: u64 = 0;
#[no_mangle]
static mut last_tgid: u32 = 0;
#[no_mangle]
static mut pid: u32 = 0;
#[no_mangle]
static mut page_shift: u32 = 0;

#[link_section = "iter/task_vma"]
#[no_mangle]
extern "C" fn get_vma_offset(ctx: *const bpf_iter__task_vma) -> i32 {
    let ctx = unsafe { &*ctx };
    let vma = ctx.vma;
    let task = ctx.task;

    if task.is_null() || vma.is_null() {
        return 0;
    }

    let meta = unsafe { &*ctx.meta };
    let task_ref = unsafe { &*task };
    let vma_ref = unsafe { &*vma };

    let tgid = unsafe { *task_ref.tgid().as_ptr() } as u32;

    if unsafe { last_tgid } != tgid {
        unsafe { unique_tgid_cnt += 1 };
    }
    unsafe { last_tgid = tgid };

    if tgid != unsafe { pid } {
        return 0;
    }

    let vm_start = unsafe { *vma_ref.vm_start().as_ptr() };
    let vm_end = unsafe { *vma_ref.vm_end().as_ptr() };
    let vm_pgoff = unsafe { *vma_ref.vm_pgoff().as_ptr() };

    let addr = unsafe { address };
    if vm_start <= addr && vm_end > addr {
        unsafe {
            offset = addr - vm_start + (vm_pgoff << page_shift);
        }
        static FMT: [u8; 4] = *b"OK\n\0";
        bpf_seq_printf(
            meta.seq,
            FMT.as_ptr() as *const c_void,
            FMT.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    0
}

bpf_object!("GPL");
