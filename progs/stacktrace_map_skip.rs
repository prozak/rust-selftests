#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/stacktrace_map_skip.c,
// bpf-rs-core idiom. See progs/stacktrace_map.rs for the sibling program and
// its FLAVOR=qemu note (UML can't do stack unwinding for this test class).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_get_stack, bpf_get_stackid, bpf_map_lookup_elem,
    bpf_map_update_elem,
};
use bpf_rs_core::maps::{self, BpfMap};

const TEST_STACK_DEPTH: u64 = 2;
const TEST_MAX_ENTRIES: usize = 16384;
#[allow(non_camel_case_types)]
type stack_trace_t = [u64; TEST_STACK_DEPTH as usize];

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
static stackmap: BpfMap<u32, stack_trace_t, { maps::STACK_TRACE }, TEST_MAX_ENTRIES> =
    BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stackid_hmap: BpfMap<u32, u32, { maps::HASH }, TEST_MAX_ENTRIES> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stack_amap: BpfMap<u32, stack_trace_t, { maps::ARRAY }, TEST_MAX_ENTRIES> = BpfMap::new();

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut control: i32 = 0;
#[no_mangle]
static mut failed: i32 = 0;

#[link_section = "tracepoint/sched/sched_switch"]
#[no_mangle]
extern "C" fn oncpu(ctx: *const sched_switch_args) -> i32 {
    let ctx = ctx as *const core::ffi::c_void;
    let max_len: u32 = TEST_STACK_DEPTH as u32 * core::mem::size_of::<u64>() as u32;
    let val: u32 = 0;

    if unsafe { pid } != (bpf_get_current_pid_tgid() >> 32) as i32 {
        return 0;
    }

    if unsafe { control } != 0 {
        return 0;
    }

    // it should allow skipping whole buffer size entries
    let ret = bpf_get_stackid(ctx, &stackmap, TEST_STACK_DEPTH);
    let key = ret as u32;
    if (key as i32) >= 0 {
        // The size of stackmap and stack_amap should be the same
        bpf_map_update_elem(&stackid_hmap, &key, &val, 0);
        let stack_p = bpf_map_lookup_elem(&stack_amap, &key);
        if !stack_p.is_null() {
            bpf_get_stack(ctx, stack_p, max_len, TEST_STACK_DEPTH);
            // it wrongly skipped all the entries and filled zero
            if unsafe { *(stack_p as *const u64) } == 0 {
                unsafe { failed = 1 };
            }
        }
    } else {
        // old kernel doesn't support skipping that many entries
        unsafe { failed = 2 };
    }

    0
}

bpf_object!("GPL");
