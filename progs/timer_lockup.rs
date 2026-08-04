#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/timer_lockup.c,
// bpf-rs-core idiom.
//
// The map value embeds struct bpf_timer: the kernel recognizes the field
// purely by the member's BTF struct name ("bpf_timer") and size (16), so
// the struct below must reach BTF with exactly that name and layout.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_timer_cancel, bpf_timer_init, bpf_timer_set_callback,
    bpf_timer_start,
};
use bpf_rs_core::maps::{self, BpfMap};

const CLOCK_BOOTTIME: u64 = 7;
const BPF_F_TIMER_CPU_PIN: u64 = 2;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct elem {
    t: bpf_timer,
}

#[link_section = ".maps"]
#[no_mangle]
static timer1_map: BpfMap<i32, elem, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static timer2_map: BpfMap<i32, elem, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut timer1_err: i32 = 0;
#[no_mangle]
static mut timer2_err: i32 = 0;

extern "C" fn timer_cb1(
    _map: *mut BpfMap<i32, elem, { maps::ARRAY }, 1>,
    _key: *mut i32,
    _value: *mut elem,
) -> i64 {
    let key: i32 = 0;
    let timer = bpf_map_lookup_elem(&timer2_map, &key) as *mut bpf_timer;
    if !timer.is_null() {
        let err = bpf_timer_cancel(timer);
        unsafe { timer2_err = err as i32 };
    }
    0
}

extern "C" fn timer_cb2(
    _map: *mut BpfMap<i32, elem, { maps::ARRAY }, 1>,
    _key: *mut i32,
    _value: *mut elem,
) -> i64 {
    let key: i32 = 0;
    let timer = bpf_map_lookup_elem(&timer1_map, &key) as *mut bpf_timer;
    if !timer.is_null() {
        let err = bpf_timer_cancel(timer);
        unsafe { timer1_err = err as i32 };
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn timer1_prog(_ctx: *const core::ffi::c_void) -> i32 {
    let key: i32 = 0;
    let value = bpf_map_lookup_elem(&timer1_map, &key) as *mut elem;
    if !value.is_null() {
        unsafe {
            let timer = core::ptr::addr_of_mut!((*value).t);
            bpf_timer_init(timer, &timer1_map, CLOCK_BOOTTIME);
            bpf_timer_set_callback(timer, timer_cb1);
            bpf_timer_start(timer, 1, BPF_F_TIMER_CPU_PIN);
        }
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn timer2_prog(_ctx: *const core::ffi::c_void) -> i32 {
    let key: i32 = 0;
    let value = bpf_map_lookup_elem(&timer2_map, &key) as *mut elem;
    if !value.is_null() {
        unsafe {
            let timer = core::ptr::addr_of_mut!((*value).t);
            bpf_timer_init(timer, &timer2_map, CLOCK_BOOTTIME);
            bpf_timer_set_callback(timer, timer_cb2);
            bpf_timer_start(timer, 1, BPF_F_TIMER_CPU_PIN);
        }
    }
    0
}

bpf_object!("GPL");
