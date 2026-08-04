#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_task_vmas.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_d_path, bpf_seq_printf};
use btf_macros::btf;
use core::ffi::c_void;

const VM_READ: u64 = 0x00000001;
const VM_WRITE: u64 = 0x00000002;
const VM_EXEC: u64 = 0x00000004;
const VM_MAYSHARE: u64 = 0x00000080;

const MINORBITS: u32 = 20;
const MINORMASK: u32 = (1u32 << MINORBITS) - 1;

const D_PATH_BUF_SIZE: usize = 1024;

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
struct path {}

#[btf]
struct super_block {
    s_dev: u32,
}

#[btf]
struct inode {
    i_sb: *mut super_block,
    i_ino: u64,
}

#[btf]
struct file {
    f_inode: *mut inode,
    f_path: path,
}

#[btf]
struct vm_area_struct {
    vm_start: u64,
    vm_end: u64,
    vm_flags: u64,
    vm_file: *mut file,
    vm_pgoff: u64,
}

#[no_mangle]
static mut d_path_buf: [u8; D_PATH_BUF_SIZE] = [0; D_PATH_BUF_SIZE];
#[no_mangle]
static mut pid: u32 = 0;
#[no_mangle]
static mut one_task: u32 = 0;
#[no_mangle]
static mut one_task_error: u32 = 0;

#[link_section = "iter/task_vma"]
#[no_mangle]
extern "C" fn proc_maps(ctx: *const bpf_iter__task_vma) -> i32 {
    let ctx = unsafe { &*ctx };
    let vma = ctx.vma;
    let task = ctx.task;

    if task.is_null() || vma.is_null() {
        return 0;
    }

    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;
    let vma_ref = unsafe { &*vma };
    let task_ref = unsafe { &*task };

    let file_ptr = unsafe { *vma_ref.vm_file().as_ptr() };

    let task_tgid = unsafe { *task_ref.tgid().as_ptr() };
    if task_tgid != unsafe { pid } as i32 {
        if unsafe { one_task } != 0 {
            unsafe { one_task_error = 1 };
        }
        return 0;
    }

    let vm_flags = unsafe { *vma_ref.vm_flags().as_ptr() };
    let mut perm_str: [u8; 5] = [0; 5];
    let perm_ptr = perm_str.as_mut_ptr();
    unsafe {
        core::ptr::write_volatile(
            perm_ptr,
            if vm_flags & VM_READ != 0 { b'r' } else { b'-' },
        );
        core::ptr::write_volatile(
            perm_ptr.add(1),
            if vm_flags & VM_WRITE != 0 { b'w' } else { b'-' },
        );
        core::ptr::write_volatile(
            perm_ptr.add(2),
            if vm_flags & VM_EXEC != 0 { b'x' } else { b'-' },
        );
        core::ptr::write_volatile(
            perm_ptr.add(3),
            if vm_flags & VM_MAYSHARE != 0 { b's' } else { b'p' },
        );
        core::ptr::write_volatile(perm_ptr.add(4), 0);
    }

    let vm_start = unsafe { *vma_ref.vm_start().as_ptr() };
    let vm_end = unsafe { *vma_ref.vm_end().as_ptr() };

    static FMT0: [u8; 18] = *b"%08llx-%08llx %s \0";
    let params0: [u64; 3] = [vm_start, vm_end, perm_str.as_ptr() as u64];
    bpf_seq_printf(
        seq,
        FMT0.as_ptr() as *const c_void,
        FMT0.len() as u32,
        params0.as_ptr() as *const c_void,
        core::mem::size_of_val(&params0) as u32,
    );

    if !file_ptr.is_null() {
        let file_ref = unsafe { &*file_ptr };
        let inode_ptr = unsafe { *file_ref.f_inode().as_ptr() };
        let inode_ref = unsafe { &*inode_ptr };
        let sb_ptr = unsafe { *inode_ref.i_sb().as_ptr() };
        let dev = unsafe { *(&*sb_ptr).s_dev().as_ptr() };
        let i_ino = unsafe { *inode_ref.i_ino().as_ptr() };

        let f_path_ptr = file_ref.f_path().field.as_ptr();
        bpf_d_path(
            f_path_ptr,
            core::ptr::addr_of_mut!(d_path_buf) as *mut c_void,
            D_PATH_BUF_SIZE as u32,
        );

        let vm_pgoff = unsafe { *vma_ref.vm_pgoff().as_ptr() };
        static FMT1: [u8; 8] = *b"%08llx \0";
        let params1: [u64; 1] = [vm_pgoff << 12];
        bpf_seq_printf(
            seq,
            FMT1.as_ptr() as *const c_void,
            FMT1.len() as u32,
            params1.as_ptr() as *const c_void,
            core::mem::size_of_val(&params1) as u32,
        );

        static FMT2: [u8; 15] = *b"%02x:%02x %llu\0";
        let major = (dev >> MINORBITS) as u64;
        let minor = (dev & MINORMASK) as u64;
        let params2: [u64; 3] = [major, minor, i_ino];
        bpf_seq_printf(
            seq,
            FMT2.as_ptr() as *const c_void,
            FMT2.len() as u32,
            params2.as_ptr() as *const c_void,
            core::mem::size_of_val(&params2) as u32,
        );

        static FMT3: [u8; 5] = *b"\t%s\n\0";
        let params3: [u64; 1] = [core::ptr::addr_of!(d_path_buf) as u64];
        bpf_seq_printf(
            seq,
            FMT3.as_ptr() as *const c_void,
            FMT3.len() as u32,
            params3.as_ptr() as *const c_void,
            core::mem::size_of_val(&params3) as u32,
        );
    } else {
        static FMT_ELSE: [u8; 16] = *b"%08llx 00:00 0\n\0";
        let params_else: [u64; 1] = [0u64];
        bpf_seq_printf(
            seq,
            FMT_ELSE.as_ptr() as *const c_void,
            FMT_ELSE.len() as u32,
            params_else.as_ptr() as *const c_void,
            core::mem::size_of_val(&params_else) as u32,
        );
    }

    0
}

bpf_object!("GPL");
