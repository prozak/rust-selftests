#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_perf_branches.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_read_branch_records;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::addr_of_mut;

const BPF_F_GET_BRANCH_RECORDS_SIZE: u64 = 1 << 0;

#[no_mangle]
static mut valid: i32 = 0;
#[no_mangle]
static mut run_cnt: i32 = 0;
#[no_mangle]
static mut required_size_out: i32 = 0;
#[no_mangle]
static mut written_stack_out: i32 = 0;
#[no_mangle]
static mut written_global_out: i32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
struct perf_branch_entry {
    _a: u64,
    _b: u64,
    _c: u64,
}

#[no_mangle]
static mut fpbe: [perf_branch_entry; 30] = [perf_branch_entry {
    _a: 0,
    _b: 0,
    _c: 0,
}; 30];

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn perf_branches(ctx: *const c_void) -> i32 {
    let mut entries: [u64; 12] = [0; 12];

    unsafe { run_cnt += 1 };

    // write to stack
    let written_stack = bpf_read_branch_records(
        ctx,
        entries.as_mut_ptr() as *mut c_void,
        size_of::<[u64; 12]>() as u32,
        0,
    );
    // ignore spurious events
    if written_stack == 0 {
        return 1;
    }

    // get required size
    let required_size = bpf_read_branch_records(
        ctx,
        core::ptr::null_mut(),
        0,
        BPF_F_GET_BRANCH_RECORDS_SIZE,
    );

    let written_global = bpf_read_branch_records(
        ctx,
        addr_of_mut!(fpbe) as *mut c_void,
        size_of::<[perf_branch_entry; 30]>() as u32,
        0,
    );
    // ignore spurious events
    if written_global == 0 {
        return 1;
    }

    unsafe {
        required_size_out = required_size as i32;
        written_stack_out = written_stack as i32;
        written_global_out = written_global as i32;
        valid = 1;
    }

    0
}

bpf_object!("GPL");
