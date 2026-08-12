#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/timer_start_deadlock.c,
// bpf-rs-core idiom.
//
// The map value embeds struct bpf_timer: the kernel recognizes the field
// purely by the member's BTF struct name ("bpf_timer") and size (16), so
// the struct below must reach BTF with exactly that name and layout (see
// timer_start_delete_race.rs / timer_crash.rs).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_timer_init, bpf_timer_set_callback, bpf_timer_start,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg;

const CLOCK_MONOTONIC: u64 = 1;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct elem {
    timer: bpf_timer,
}

#[link_section = ".maps"]
#[no_mangle]
static timer_map: BpfMap<i32, elem, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut in_timer_start: i32 = 0;
#[no_mangle]
static mut tp_called: i32 = 0;

extern "C" fn timer_cb(
    _map: *mut BpfMap<i32, elem, { maps::ARRAY }, 1>,
    _key: *mut i32,
    _value: *mut elem,
) -> i64 {
    0
}

/// BPF_PROG(tp_hrtimer_start, struct hrtimer *hrtimer, enum hrtimer_mode mode, bool was_armed)
#[link_section = "tp_btf/hrtimer_start"]
#[no_mangle]
extern "C" fn tp_hrtimer_start(ctx: *const u64) -> i32 {
    // C's BPF_PROG `bool was_armed` compiles to a test of the FULL 64-bit
    // ctx word (jeq r2, 0) — masking to the low byte here would diverge for
    // words whose low byte is 0 but which are nonzero.
    let was_armed = fentry_arg(ctx, 2);

    if unsafe { in_timer_start } == 0 || was_armed == 0 {
        return 0;
    }

    unsafe {
        tp_called = 1;
    }
    let key: i32 = 0;
    let timer = bpf_map_lookup_elem(&timer_map, &key) as *mut elem;

    // Call bpf_timer_start() from the tracepoint within hrtimer logic on
    // the same timer to make sure it doesn't deadlock.
    unsafe {
        bpf_timer_start(core::ptr::addr_of_mut!((*timer).timer), 1_000_000_000, 0);
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn start_timer(_ctx: *const core::ffi::c_void) -> i32 {
    let key: i32 = 0;
    let timer = bpf_map_lookup_elem(&timer_map, &key) as *mut elem;
    // no NULL check on `timer` here, matching the C original.

    unsafe {
        bpf_timer_init(core::ptr::addr_of_mut!((*timer).timer), &timer_map, CLOCK_MONOTONIC);
        bpf_timer_set_callback(core::ptr::addr_of_mut!((*timer).timer), timer_cb);
    }

    // call hrtimer_start() twice, so that the 2nd call does
    // trace_hrtimer_start(was_armed=1) tracepoint.
    unsafe {
        in_timer_start = 1;
    }
    unsafe {
        bpf_timer_start(core::ptr::addr_of_mut!((*timer).timer), 1_000_000_000, 0);
        bpf_timer_start(core::ptr::addr_of_mut!((*timer).timer), 1_000_000_000, 0);
    }
    unsafe {
        in_timer_start = 0;
    }
    0
}

bpf_object!("GPL");
