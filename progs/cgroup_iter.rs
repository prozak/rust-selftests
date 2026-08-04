#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgroup_iter.c
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
struct bpf_iter__cgroup {
    meta: *mut bpf_iter_meta,
    cgroup: *mut cgroup,
}

#[btf]
struct kernfs_node {
    id: u64,
}

#[btf]
struct cgroup {
    kn: *mut kernfs_node,
}

#[no_mangle]
static mut terminate_early: i32 = 0;
#[no_mangle]
static mut terminal_cgroup: u64 = 0;

fn cgroup_id(cgrp: *mut cgroup) -> u64 {
    let kn = unsafe { *(&*cgrp).kn().as_ptr() };
    unsafe { *(&*kn).id().as_ptr() }
}

#[link_section = "iter/cgroup"]
#[no_mangle]
extern "C" fn cgroup_id_printer(ctx: *const bpf_iter__cgroup) -> i32 {
    let ctx = unsafe { &*ctx };
    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;
    let cgrp = ctx.cgroup;

    if cgrp.is_null() {
        static FMT: [u8; 10] = *b"epilogue\n\0";
        bpf_seq_printf(
            seq,
            FMT.as_ptr() as *const c_void,
            FMT.len() as u32,
            core::ptr::null(),
            0,
        );
        return 0;
    }

    if meta.seq_num == 0 {
        static FMT: [u8; 10] = *b"prologue\n\0";
        bpf_seq_printf(
            seq,
            FMT.as_ptr() as *const c_void,
            FMT.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    let id = cgroup_id(cgrp);
    static FMT2: [u8; 7] = *b"%8llu\n\0";
    let params: [u64; 1] = [id];
    bpf_seq_printf(
        seq,
        FMT2.as_ptr() as *const c_void,
        FMT2.len() as u32,
        params.as_ptr() as *const c_void,
        core::mem::size_of_val(&params) as u32,
    );

    if unsafe { terminal_cgroup } == id {
        return 1;
    }

    if unsafe { terminate_early } != 0 {
        1
    } else {
        0
    }
}

bpf_object!("GPL");
