#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_bpf_link.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_seq_write;
use btf_macros::btf;
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__bpf_link {
    meta: *mut bpf_iter_meta,
    link: *mut bpf_link,
}

#[btf]
struct bpf_link {
    id: u32,
}

#[link_section = "iter/bpf_link"]
#[no_mangle]
extern "C" fn dump_bpf_link(ctx: *const bpf_iter__bpf_link) -> i32 {
    let ctx = unsafe { &*ctx };
    let link = ctx.link;

    if link.is_null() {
        return 0;
    }

    let meta = unsafe { &*ctx.meta };
    let link_ref = unsafe { &*link };
    let link_id = unsafe { *link_ref.id().as_ptr() } as i32;

    bpf_seq_write(
        meta.seq,
        &link_id as *const i32 as *const c_void,
        core::mem::size_of::<i32>() as u32,
    );

    0
}

bpf_object!("GPL");
