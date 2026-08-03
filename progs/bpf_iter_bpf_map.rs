#![no_std]
#![no_main]

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
struct bpf_iter__bpf_map {
    meta: *mut bpf_iter_meta,
    map: *mut bpf_map,
}

#[btf]
struct atomic64_t {
    counter: i64,
}

#[btf]
struct bpf_map {
    id: u32,
    refcnt: atomic64_t,
    usercnt: atomic64_t,
}

#[link_section = "iter/bpf_map"]
#[no_mangle]
extern "C" fn dump_bpf_map(ctx: *const bpf_iter__bpf_map) -> i32 {
    let ctx = unsafe { &*ctx };
    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;
    let seq_num = meta.seq_num;
    let map = ctx.map;

    if map.is_null() {
        static FMT_END: [u8; 25] = *b"      %%%%%% END %%%%%%\n\0";
        bpf_seq_printf(
            seq,
            FMT_END.as_ptr() as *const c_void,
            FMT_END.len() as u32,
            core::ptr::null(),
            0,
        );
        return 0;
    }

    if seq_num == 0 {
        static FMT_HDR: [u8; 39] =
            *b"      id   refcnt  usercnt  locked_vm\n\0";
        bpf_seq_printf(
            seq,
            FMT_HDR.as_ptr() as *const c_void,
            FMT_HDR.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    let map_ref = unsafe { &*map };
    let id = unsafe { *map_ref.id().as_ptr() } as u64;
    let refcnt = unsafe { *map_ref.refcnt().counter().as_ptr() } as u64;
    let usercnt = unsafe { *map_ref.usercnt().counter().as_ptr() } as u64;

    static FMT: [u8; 21] = *b"%8u %8ld %8ld %10lu\n\0";
    let params: [u64; 4] = [id, refcnt, usercnt, 0];
    bpf_seq_printf(
        seq,
        FMT.as_ptr() as *const c_void,
        FMT.len() as u32,
        params.as_ptr() as *const c_void,
        core::mem::size_of_val(&params) as u32,
    );

    0
}

bpf_object!("GPL");
