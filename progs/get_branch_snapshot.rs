#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/get_branch_snapshot.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_branch_snapshot;
use core::ffi::c_void;

#[no_mangle]
static mut test1_hits: u64 = 0;
#[no_mangle]
static mut address_low: u64 = 0;
#[no_mangle]
static mut address_high: u64 = 0;
#[no_mangle]
static mut wasted_entries: i32 = 0;
#[no_mangle]
static mut total_entries: i64 = 0;

const ENTRY_CNT: usize = 32;

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
struct perf_branch_entry {
    from: u64,
    to: u64,
    flags: u64,
}

#[no_mangle]
static mut entries: [perf_branch_entry; ENTRY_CNT] = [perf_branch_entry {
    from: 0,
    to: 0,
    flags: 0,
}; ENTRY_CNT];

fn gbs_in_range(val: u64) -> bool {
    let low = unsafe { address_low };
    let high = unsafe { address_high };
    val >= low && val < high
}

#[link_section = "fexit/bpf_testmod_loop_test"]
#[no_mangle]
extern "C" fn test1(_ctx: *const u64) -> i32 {
    let base = core::ptr::addr_of_mut!(entries) as *mut perf_branch_entry;
    let size = (ENTRY_CNT * core::mem::size_of::<perf_branch_entry>()) as u32;

    let mut total = bpf_get_branch_snapshot(base as *mut c_void, size, 0);
    total /= core::mem::size_of::<perf_branch_entry>() as i64;
    unsafe { total_entries = total };

    let mut i: i64 = 0;
    while i < ENTRY_CNT as i64 {
        if i >= total {
            break;
        }

        let from = unsafe { (*base.add(i as usize)).from };
        let to = unsafe { (*base.add(i as usize)).to };

        if gbs_in_range(from) && gbs_in_range(to) {
            unsafe { test1_hits += 1 };
        } else if unsafe { test1_hits } == 0 {
            unsafe { wasted_entries += 1 };
        }

        i += 1;
    }

    0
}

bpf_object!("GPL");
