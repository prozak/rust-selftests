#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/free_timer.c,
// bpf-rs-core idiom.
//
// The map value embeds struct bpf_timer: the kernel recognizes the field
// purely by the member's BTF struct name ("bpf_timer") and size, so the
// struct below must reach BTF with exactly that name and layout.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_loop, bpf_map_lookup_elem, bpf_map_update_elem, bpf_timer_init, bpf_timer_set_callback,
    bpf_timer_start,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vstore;
use core::ffi::c_void;

const MAX_ENTRIES: usize = 8;
const CLOCK_MONOTONIC: u64 = 1;
const BPF_ANY: u64 = 0;
const BPF_F_TIMER_CPU_PIN: u64 = 1 << 1;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_value {
    timer: bpf_timer,
}

#[link_section = ".maps"]
#[no_mangle]
static map: BpfMap<i32, map_value, { maps::HASH }, MAX_ENTRIES> = BpfMap::new();

// Busy-work callback for bpf_loop, standing in for the C source's
// `bpf_for(i, 0, 1024 * 1024) sum += i;` open-coded iterator: a plain
// compiled loop of this trip count blows the 1M-processed-insn verifier
// cap, so drive it through bpf_loop instead, whose callback body the
// verifier checks once via loop-state convergence rather than unrolling.
extern "C" fn sum_cb(index: u64, ctx: *mut c_void) -> i64 {
    let sum = ctx as *mut i32;
    let cur = unsafe { core::ptr::read_volatile(sum) };
    vstore!(*sum, cur + index as i32);
    0
}

extern "C" fn timer_cb(
    _map: *mut BpfMap<i32, map_value, { maps::HASH }, MAX_ENTRIES>,
    _key: *mut i32,
    _value: *mut map_value,
) -> i64 {
    let mut sum: i32 = 0;
    bpf_loop(1024 * 1024, sum_cb, &mut sum as *mut i32 as *mut c_void, 0);
    0
}

extern "C" fn start_cb(index: u64, _ctx: *mut c_void) -> i64 {
    let key = index as i32;

    let value = bpf_map_lookup_elem(&map, &key) as *mut map_value;
    if value.is_null() {
        return 0;
    }

    unsafe {
        bpf_timer_init(
            core::ptr::addr_of_mut!((*value).timer),
            &map,
            CLOCK_MONOTONIC,
        );
        bpf_timer_set_callback(core::ptr::addr_of_mut!((*value).timer), timer_cb);
        // Hope 100us will be enough to wake-up and run the overwrite thread
        bpf_timer_start(
            core::ptr::addr_of_mut!((*value).timer),
            100_000,
            BPF_F_TIMER_CPU_PIN,
        );
    }

    0
}

extern "C" fn overwrite_cb(index: u64, _ctx: *mut c_void) -> i64 {
    let key = index as i32;
    let zero = map_value {
        timer: bpf_timer { __opaque: [0; 2] },
    };

    // Free the timer which may run on other CPU
    bpf_map_update_elem(&map, &key, &zero, BPF_ANY);

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn start_timer(_ctx: *const c_void) -> i32 {
    bpf_loop(MAX_ENTRIES as u32, start_cb, core::ptr::null_mut(), 0);
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn overwrite_timer(_ctx: *const c_void) -> i32 {
    bpf_loop(MAX_ENTRIES as u32, overwrite_cb, core::ptr::null_mut(), 0);
    0
}

bpf_object!("GPL");
