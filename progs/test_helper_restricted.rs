#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_helper_restricted.c, bpf-rs-core
// idiom.
//
// prog_tests/helper_restricted.c autoloads every program in this object at
// once and asserts the *load* fails: bpf_timer_* / bpf_spin_lock are
// restricted from raw_tp/tp/kprobe/perf_event programs by the verifier, so
// this translation only has to preserve that same helper usage per program
// type for the kernel to reject it the same way.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_spin_lock, bpf_spin_unlock, bpf_timer_cancel, bpf_timer_init,
    bpf_timer_set_callback, bpf_timer_start,
};
use bpf_rs_core::maps::{self, BpfMap};

const CLOCK_MONOTONIC: u64 = 1;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct timer {
    t: bpf_timer,
}

// struct bpf_spin_lock { __u32 val; };  -- matched by BTF struct name.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct lock {
    l: bpf_spin_lock,
}

#[link_section = ".maps"]
#[no_mangle]
static timers: BpfMap<u32, timer, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static locks: BpfMap<u32, lock, { maps::ARRAY }, 1> = BpfMap::new();

extern "C" fn timer_cb(
    _map: *mut BpfMap<u32, timer, { maps::ARRAY }, 1>,
    _key: *mut i32,
    _timer: *mut timer,
) -> i64 {
    0
}

fn timer_work() {
    let key: u32 = 0;

    let t = bpf_map_lookup_elem(&timers, &key) as *mut timer;
    if !t.is_null() {
        unsafe {
            let bt = core::ptr::addr_of_mut!((*t).t);
            bpf_timer_init(bt, &timers, CLOCK_MONOTONIC);
            bpf_timer_set_callback(bt, timer_cb);
            bpf_timer_start(bt, 10_000_000_000, 0);
            bpf_timer_cancel(bt);
        }
    }
}

fn spin_lock_work() {
    let key: u32 = 0;

    let l = bpf_map_lookup_elem(&locks, &key) as *mut lock;
    if !l.is_null() {
        unsafe {
            let bl = core::ptr::addr_of_mut!((*l).l);
            bpf_spin_lock(bl);
            bpf_spin_unlock(bl);
        }
    }
}

#[link_section = "?raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn raw_tp_timer(_ctx: *const core::ffi::c_void) -> i32 {
    timer_work();
    0
}

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn tp_timer(_ctx: *const core::ffi::c_void) -> i32 {
    timer_work();
    0
}

#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn kprobe_timer(_ctx: *const core::ffi::c_void) -> i32 {
    timer_work();
    0
}

#[link_section = "?perf_event"]
#[no_mangle]
extern "C" fn perf_event_timer(_ctx: *const core::ffi::c_void) -> i32 {
    timer_work();
    0
}

#[link_section = "?raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn raw_tp_spin_lock(_ctx: *const core::ffi::c_void) -> i32 {
    spin_lock_work();
    0
}

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn tp_spin_lock(_ctx: *const core::ffi::c_void) -> i32 {
    spin_lock_work();
    0
}

#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn kprobe_spin_lock(_ctx: *const core::ffi::c_void) -> i32 {
    spin_lock_work();
    0
}

#[link_section = "?perf_event"]
#[no_mangle]
extern "C" fn perf_event_spin_lock(_ctx: *const core::ffi::c_void) -> i32 {
    spin_lock_work();
    0
}

bpf_object!("GPL");
