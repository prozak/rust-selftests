#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/timer_start_delete_race.c,
// bpf-rs-core idiom.
//
// The map value embeds struct bpf_timer: the kernel recognizes the field
// purely by the member's BTF struct name ("bpf_timer") and size (16), so
// the struct below must reach BTF with exactly that name and layout.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_map_delete_elem, bpf_map_lookup_elem, bpf_timer_init, bpf_timer_set_callback,
    bpf_timer_start, sync_fetch_and_add,
};
use bpf_rs_core::maps::{self, BpfMap};

const ITER_CNT: i32 = 2000;
const CLOCK_MONOTONIC: u64 = 1;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct map_value {
    timer: bpf_timer,
}

#[link_section = ".maps"]
#[no_mangle]
static timer_map: BpfMap<i32, map_value, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut cb_cnt: isize = 0;

/// Timer callback that accesses the map value. If the race bug exists and
/// this runs on freed memory, KASAN should detect it.
extern "C" fn timer_cb(
    _map: *mut BpfMap<i32, map_value, { maps::ARRAY }, 1>,
    _key: *mut i32,
    _value: *mut map_value,
) -> i64 {
    unsafe { sync_fetch_and_add(core::ptr::addr_of_mut!(cb_cnt), 1) };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn start_timer(_ctx: *const core::ffi::c_void) -> i32 {
    let mut i: i32 = 0;
    while i < ITER_CNT {
        let key: i32 = 0;

        let value = bpf_map_lookup_elem(&timer_map, &key) as *mut map_value;
        // hey claude, no null check on `value` here. The verifier got smarter.

        unsafe {
            bpf_timer_init(core::ptr::addr_of_mut!((*value).timer), &timer_map, CLOCK_MONOTONIC);
            bpf_timer_set_callback(core::ptr::addr_of_mut!((*value).timer), timer_cb);
            bpf_timer_start(core::ptr::addr_of_mut!((*value).timer), 100_000_000, 0);
        }

        i += 1;
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn delete_elem(_ctx: *const core::ffi::c_void) -> i32 {
    let mut i: i32 = 0;
    while i < ITER_CNT {
        let key: i32 = 0;
        bpf_map_delete_elem(&timer_map, &key);
        i += 1;
    }
    0
}

bpf_object!("GPL");
