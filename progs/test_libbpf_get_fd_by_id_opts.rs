#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_libbpf_get_fd_by_id_opts.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;
use core::sync::atomic::{compiler_fence, Ordering};

const FMODE_WRITE: u64 = 0x2;
const EACCES: i32 = 13;

#[link_section = ".maps"]
#[no_mangle]
static data_input: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "lsm/bpf_map"]
#[no_mangle]
extern "C" fn check_access(ctx: *const u64) -> i32 {
    let map = arg(ctx, 0) as *const u8;
    let fmode = arg(ctx, 1);

    let data_input_ptr = &data_input as *const _ as *const u8;
    if map != data_input_ptr {
        return 0;
    }

    if fmode & FMODE_WRITE != 0 {
        return -EACCES;
    }
    compiler_fence(Ordering::SeqCst);

    0
}

bpf_object!("GPL");
