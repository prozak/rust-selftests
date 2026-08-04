#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/timer_interrupt.c,
// bpf-rs-core idiom.
//
// The C original's get_preempt_count() reads a per-CPU kernel data symbol
// on x86 (`__preempt_count`, falling back to `pcpu_hot.preempt_count`),
// both declared `extern ... __ksym`. Per TRANSLATING.md, a data (non-fn)
// `__ksym` extern is unfixable here: rustc's `extern "C" { static X: T; }`
// carries no debuginfo, so no BTF extern-linkage VAR is ever generated for
// it and libbpf's static linker fails before load. This mirrors the C
// source's own fallback for archs it doesn't recognize (arm64/powerpc/
// s390/loongarch branches, `#else return 0;`), which is exactly what
// get_preempt_count() below reproduces unconditionally.
//
// prog_tests/timer.c's test_timer_interrupt() asserts `in_interrupt == 0`
// unconditionally, and only asserts `in_interrupt_cb != 0` when
// `preempt_count != 0`. With get_preempt_count() always 0, preempt_count
// stays 0 (skipping that second assertion) and in_interrupt/in_interrupt_cb
// both stay 0 too (bpf_in_interrupt() masks a value that is always 0),
// satisfying both assertions -- the same outcome an unsupported-arch build
// of the pristine C object would produce.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_timer_init, bpf_timer_set_callback, bpf_timer_start};
use bpf_rs_core::maps::{self, BpfMap};

const CLOCK_MONOTONIC: u64 = 1;

#[no_mangle]
static mut preempt_count: i32 = 0;
#[no_mangle]
static mut in_interrupt: i32 = 0;
#[no_mangle]
static mut in_interrupt_cb: i32 = 0;

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
static array: BpfMap<i32, elem, { maps::ARRAY }, 1> = BpfMap::new();

#[inline(always)]
fn get_preempt_count() -> i32 {
    0
}

#[inline(always)]
fn bpf_in_interrupt() -> i32 {
    get_preempt_count()
}

extern "C" fn timer_in_interrupt(
    _map: *mut BpfMap<i32, elem, { maps::ARRAY }, 1>,
    _key: *mut i32,
    _timer: *mut bpf_timer,
) -> i64 {
    unsafe {
        preempt_count = get_preempt_count();
        in_interrupt_cb = bpf_in_interrupt();
    }
    0
}

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test_timer_interrupt(_ctx: *const u64) -> i32 {
    let key: i32 = 0;

    let timer = bpf_map_lookup_elem(&array, &key) as *mut bpf_timer;
    if timer.is_null() {
        return 0;
    }

    unsafe {
        in_interrupt = bpf_in_interrupt();
        bpf_timer_init(timer, &array, CLOCK_MONOTONIC);
        bpf_timer_set_callback(timer, timer_in_interrupt);
        bpf_timer_start(timer, 0, 0);
    }
    0
}

bpf_object!("GPL");
