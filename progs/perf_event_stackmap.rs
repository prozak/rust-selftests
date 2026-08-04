#![no_std]
#![no_main]

use bpf_rs_core::helpers::{bpf_get_stack, bpf_get_stackid, bpf_map_lookup_elem};
use bpf_rs_core::maps::{self, BpfMap};

const PERF_MAX_STACK_DEPTH: usize = 127;
#[allow(non_camel_case_types)]
type stack_trace_t = [u64; PERF_MAX_STACK_DEPTH];

const BPF_F_USER_STACK: u64 = 1 << 8;

#[link_section = ".maps"]
#[no_mangle]
static stackmap: BpfMap<u32, stack_trace_t, { maps::STACK_TRACE }, 16384> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stackdata_map: BpfMap<u32, stack_trace_t, { maps::PERCPU_ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut stackid_kernel: isize = 1;
#[no_mangle]
static mut stackid_user: isize = 1;
#[no_mangle]
static mut stack_kernel: isize = 1;
#[no_mangle]
static mut stack_user: isize = 1;

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn oncpu(ctx: *const core::ffi::c_void) -> i32 {
    let key: u32 = 0;

    let val = bpf_get_stackid(ctx, &stackmap, 0);
    if val >= 0 {
        unsafe { stackid_kernel = 2 };
    }
    let val = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
    if val >= 0 {
        unsafe { stackid_user = 2 };
    }

    let trace = bpf_map_lookup_elem(&stackdata_map, &key);
    if trace.is_null() {
        return 0;
    }

    let val = bpf_get_stack(
        ctx,
        trace,
        core::mem::size_of::<stack_trace_t>() as u32,
        0,
    );
    if val > 0 {
        unsafe { stack_kernel = 2 };
    }

    let val = bpf_get_stack(
        ctx,
        trace,
        core::mem::size_of::<stack_trace_t>() as u32,
        BPF_F_USER_STACK,
    );
    if val > 0 {
        unsafe { stack_user = 2 };
    }

    0
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
