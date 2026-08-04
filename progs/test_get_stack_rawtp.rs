#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_get_stack_rawtp.c.
//
// Consumed by prog_tests/get_stack_raw_tp.c (test_get_stack_raw_tp): attaches
// bpf_prog1 to raw_tracepoint/sys_enter, then reads two record shapes off
// perfmap - the fixed-size stack_trace_t (kern+user+user_buildid stacks) and
// a raw combined kernel+user stack buffer written into rawdata_map.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_get_stack, bpf_map_lookup_elem, bpf_perf_event_output,
};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

const MAX_STACK_RAWTP: usize = 100;
const BPF_BUILD_ID_SIZE: usize = 20;
const BPF_F_USER_STACK: u64 = 1 << 8;
const BPF_F_USER_BUILD_ID: u64 = 1 << 11;

#[repr(C)]
struct bpf_stack_build_id {
    status: i32,
    build_id: [u8; BPF_BUILD_ID_SIZE],
    offset_or_ip: u64,
}

#[repr(C)]
struct stack_trace_t {
    pid: i32,
    kern_stack_size: i32,
    user_stack_size: i32,
    user_stack_buildid_size: i32,
    kern_stack: [u64; MAX_STACK_RAWTP],
    user_stack: [u64; MAX_STACK_RAWTP],
    user_stack_buildid: [bpf_stack_build_id; MAX_STACK_RAWTP],
}

#[link_section = ".maps"]
#[no_mangle]
static perfmap: BpfMap<i32, u32, { maps::PERF_EVENT_ARRAY }, 2> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stackdata_map: BpfMap<u32, stack_trace_t, { maps::PERCPU_ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static rawdata_map: BpfMap<u32, [u64; 2 * MAX_STACK_RAWTP], { maps::PERCPU_ARRAY }, 1> =
    BpfMap::new();

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn bpf_prog1(ctx: *const c_void) -> i32 {
    let key: u32 = 0;

    let data = bpf_map_lookup_elem(&stackdata_map, &key) as *mut stack_trace_t;
    if data.is_null() {
        return 0;
    }

    let max_len = (MAX_STACK_RAWTP * core::mem::size_of::<u64>()) as u32;
    let max_buildid_len = (MAX_STACK_RAWTP * core::mem::size_of::<bpf_stack_build_id>()) as u32;

    unsafe {
        (*data).pid = bpf_get_current_pid_tgid() as i32;
        (*data).kern_stack_size = bpf_get_stack(
            ctx,
            core::ptr::addr_of_mut!((*data).kern_stack) as *mut c_void,
            max_len,
            0,
        ) as i32;
        (*data).user_stack_size = bpf_get_stack(
            ctx,
            core::ptr::addr_of_mut!((*data).user_stack) as *mut c_void,
            max_len,
            BPF_F_USER_STACK,
        ) as i32;
        (*data).user_stack_buildid_size = bpf_get_stack(
            ctx,
            core::ptr::addr_of_mut!((*data).user_stack_buildid) as *mut c_void,
            max_buildid_len,
            BPF_F_USER_STACK | BPF_F_USER_BUILD_ID,
        ) as i32;
    }

    bpf_perf_event_output(
        ctx,
        &perfmap,
        0,
        unsafe { &*data },
        core::mem::size_of::<stack_trace_t>() as u64,
    );

    // write both kernel and user stacks to the same buffer
    let raw_data = bpf_map_lookup_elem(&rawdata_map, &key) as *mut [u64; 2 * MAX_STACK_RAWTP];
    if raw_data.is_null() {
        return 0;
    }
    let raw_bytes = raw_data as *mut u8;

    let usize_ = bpf_get_stack(ctx, raw_bytes as *mut c_void, max_len, BPF_F_USER_STACK);
    if usize_ < 0 {
        return 0;
    }

    let ksize = bpf_get_stack(
        ctx,
        unsafe { raw_bytes.add(usize_ as usize) as *mut c_void },
        max_len - usize_ as u32,
        0,
    );
    if ksize < 0 {
        return 0;
    }

    let total_size = usize_ + ksize;
    if total_size > 0 && total_size <= max_len as i64 {
        bpf_perf_event_output(ctx, &perfmap, 0, unsafe { &*raw_data }, total_size as u64);
    }

    0
}

bpf_object!("GPL");
