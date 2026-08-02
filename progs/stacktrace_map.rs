#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/stacktrace_map.c,
// bpf-rs-core idiom.
//
// NOTE: verified under the QEMU oracle (FLAVOR=qemu). The UML flavor
// cannot run it — bpf_get_stackid()/bpf_get_stack() never succeed there
// (perf_callchain unwinding is broken for the whole stack-trace test
// class, C originals included).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_stack, bpf_get_stackid, bpf_map_lookup_elem, bpf_map_update_elem,
};
use bpf_rs_core::maps::{self, BpfMap};

const PERF_MAX_STACK_DEPTH: usize = 127;
#[allow(non_camel_case_types)]
type stack_trace_t = [u64; PERF_MAX_STACK_DEPTH];

// taken from /sys/kernel/tracing/events/sched/sched_switch/format
#[repr(C)]
struct sched_switch_args {
    pad: u64,
    prev_comm: [u8; 16],
    prev_pid: i32,
    prev_prio: i32,
    prev_state: i64,
    next_comm: [u8; 16],
    next_pid: i32,
    next_prio: i32,
}

#[link_section = ".maps"]
#[no_mangle]
static control_map: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stackid_hmap: BpfMap<u32, u32, { maps::HASH }, 16384> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stackmap: BpfMap<u32, stack_trace_t, { maps::STACK_TRACE }, 16384> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stack_amap: BpfMap<u32, stack_trace_t, { maps::ARRAY }, 16384> = BpfMap::new();

#[no_mangle]
static mut stack_id: u32 = 0;

#[link_section = "tracepoint/sched/sched_switch"]
#[no_mangle]
extern "C" fn oncpu(ctx: *const sched_switch_args) -> i32 {
    let ctx = ctx as *const core::ffi::c_void;
    let max_len: u32 = PERF_MAX_STACK_DEPTH as u32 * core::mem::size_of::<u64>() as u32;
    let mut key: u32 = 0;
    let val: u32 = 0;

    let value_p = bpf_map_lookup_elem(&control_map, &key);
    if !value_p.is_null() && unsafe { *(value_p as *const u32) } != 0 {
        return 0; // skip if non-zero *value_p
    }

    // The size of stackmap and stackid_hmap should be the same
    let ret = bpf_get_stackid(ctx, &stackmap, 0);
    key = ret as u32;
    if (key as i32) >= 0 {
        unsafe { stack_id = key };
        bpf_map_update_elem(&stackid_hmap, &key, &val, 0);
        let stack_p = bpf_map_lookup_elem(&stack_amap, &key);
        if !stack_p.is_null() {
            bpf_get_stack(ctx, stack_p, max_len, 0);
        }
    }

    0
}

bpf_object!("GPL");
