// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// translint allow(kconfig): the C object's LINUX_HAS_BPF_COOKIE .kconfig
// extern is read only by usdt.bpf.h's library functions (bpf_usdt_arg & co.)
// in .text; bench_trigger_usdt takes no usdt args and calls none of them
// translint: allow(kconfig)
#![feature(linkage, used_with_arg)]
#![allow(non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/trigger_bench.c
// (bpf-rs-core idiom). benchs/bench_trigger.c sets `batch_iters` and
// `stacktrace` through `skel->rodata` at open time, enables one `?` program
// per benchmark, attaches it and reads the per-CPU `hits[].value`
// counters (`struct counter` is 128-byte aligned to match bench.h).
//
// `batch_iters` and `stacktrace` are the C's `const volatile` .rodata
// globals: every read is a volatile load, so the driver loops re-read
// `batch_iters` each iteration as clang does. `bpf_modify_return_test_tp`
// is the C's weak kfunc extern (`// BTF_KSYM:` below, scripts/ksym_vars.py
// mirrors the C object's prototype and weakness). The two usdt.bpf.h maps
// are the ones libbpf fills when it attaches the "usdt" program
// (uprobe_multi_usdt.rs).

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_numa_node_id, bpf_get_smp_processor_id, bpf_get_stack, bpf_map_lookup_elem,
    sync_fetch_and_add,
};
use bpf_rs_core::maps::{self, BpfMap};

// Pinned usdt.bpf.h ABI (see uprobe_multi_usdt.rs).
#[repr(C)]
struct UsdtArgSpec {
    val_off: u64,
    arg_type: u8,
    _pad_arg_type: u8,
    idx_reg_off_scale_bitshift: u16,
    reserved: u8,
    _pad_reserved: u8,
    reg_off: i16,
    arg_signed: bool,
    arg_bitshift: i8,
    _pad_tail: [u8; 6],
}

#[repr(C)]
struct UsdtSpec {
    args: [UsdtArgSpec; 12],
    usdt_cookie: u64,
    arg_cnt: i16,
    _pad_tail: [u8; 6],
}

#[used(compiler)]
#[linkage = "weak"]
#[link_section = ".maps"]
#[no_mangle]
static mut __bpf_usdt_specs: BpfMap<i32, UsdtSpec, { maps::ARRAY }, 256> = BpfMap::new();

#[used(compiler)]
#[linkage = "weak"]
#[link_section = ".maps"]
#[no_mangle]
static mut __bpf_usdt_ip_to_spec_id: BpfMap<i64, u32, { maps::HASH }, 1024> = BpfMap::new();

const CPU_MASK: u32 = 255;
const MAX_CPUS: usize = (CPU_MASK + 1) as usize; /* should match MAX_BUCKETS in benchs/bench_trigger.c */

/* matches struct counter in bench.h */
#[allow(non_camel_case_types)]
#[repr(C, align(128))]
struct counter {
    value: i64,
}

#[no_mangle]
static mut hits: [counter; MAX_CPUS] = [const { counter { value: 0 } }; MAX_CPUS];

#[inline(always)]
fn inc_counter() {
    let cpu = bpf_get_smp_processor_id();

    sync_fetch_and_add(
        unsafe { addr_of_mut!(hits[(cpu & CPU_MASK) as usize].value) } as *mut isize,
        1,
    );
}

#[link_section = ".rodata"]
#[no_mangle]
static stacktrace: i32 = 0;

#[allow(non_camel_case_types)]
type stack_trace_t = [u64; 128];

#[link_section = ".maps"]
#[no_mangle]
static stack_heap: BpfMap<u32, stack_trace_t, { maps::PERCPU_ARRAY }, 1> = BpfMap::new();

#[inline(always)]
fn do_stacktrace(ctx: *const c_void) {
    if unsafe { read_volatile(addr_of!(stacktrace)) } == 0 {
        return;
    }

    let zero: u32 = 0;
    let ptr = bpf_map_lookup_elem(&stack_heap, &zero);

    if !ptr.is_null() {
        bpf_get_stack(ctx, ptr, core::mem::size_of::<stack_trace_t>() as u32, 0);
    }
}

#[inline(always)]
fn handle(ctx: *const c_void) {
    inc_counter();
    do_stacktrace(ctx);
}

#[link_section = "?uprobe"]
#[no_mangle]
extern "C" fn bench_trigger_uprobe(_ctx: *const c_void) -> i32 {
    inc_counter();
    0
}

#[link_section = "?uprobe.multi"]
#[no_mangle]
extern "C" fn bench_trigger_uprobe_multi(_ctx: *const c_void) -> i32 {
    inc_counter();
    0
}

#[link_section = ".rodata"]
#[no_mangle]
static batch_iters: i32 = 0;

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn trigger_kernel_count(_ctx: *const c_void) -> i32 {
    let mut i: i32 = 0;
    while i < unsafe { read_volatile(addr_of!(batch_iters)) } {
        inc_counter();
        bpf_get_numa_node_id();
        i += 1;
    }

    0
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn trigger_driver(_ctx: *const c_void) -> i32 {
    let mut i: i32 = 0;
    while i < unsafe { read_volatile(addr_of!(batch_iters)) } {
        bpf_get_numa_node_id(); /* attach point for benchmarking */
        i += 1;
    }

    0
}

// BTF_KSYM: bpf_modify_return_test_tp
extern "C" {
    fn bpf_modify_return_test_tp(nonce: i32) -> i32;
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn trigger_driver_kfunc(_ctx: *const c_void) -> i32 {
    let mut i: i32 = 0;
    while i < unsafe { read_volatile(addr_of!(batch_iters)) } {
        unsafe { bpf_modify_return_test_tp(0) }; /* attach point for benchmarking */
        i += 1;
    }

    0
}

#[link_section = "?kprobe/bpf_get_numa_node_id"]
#[no_mangle]
extern "C" fn bench_trigger_kprobe(ctx: *const c_void) -> i32 {
    handle(ctx);
    0
}

#[link_section = "?kretprobe/bpf_get_numa_node_id"]
#[no_mangle]
extern "C" fn bench_trigger_kretprobe(ctx: *const c_void) -> i32 {
    handle(ctx);
    0
}

#[link_section = "?kprobe.multi/bpf_get_numa_node_id"]
#[no_mangle]
extern "C" fn bench_trigger_kprobe_multi(ctx: *const c_void) -> i32 {
    handle(ctx);
    0
}

#[link_section = "?kprobe.multi/bpf_get_numa_node_id"]
#[no_mangle]
extern "C" fn bench_kprobe_multi_empty(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "?kretprobe.multi/bpf_get_numa_node_id"]
#[no_mangle]
extern "C" fn bench_trigger_kretprobe_multi(ctx: *const c_void) -> i32 {
    handle(ctx);
    0
}

#[link_section = "?kretprobe.multi/bpf_get_numa_node_id"]
#[no_mangle]
extern "C" fn bench_kretprobe_multi_empty(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "?fentry/bpf_get_numa_node_id"]
#[no_mangle]
extern "C" fn bench_trigger_fentry(ctx: *const c_void) -> i32 {
    handle(ctx);
    0
}

#[link_section = "?fexit/bpf_get_numa_node_id"]
#[no_mangle]
extern "C" fn bench_trigger_fexit(ctx: *const c_void) -> i32 {
    handle(ctx);
    0
}

#[link_section = "?fmod_ret/bpf_modify_return_test_tp"]
#[no_mangle]
extern "C" fn bench_trigger_fmodret(ctx: *const c_void) -> i32 {
    handle(ctx);
    -22
}

#[link_section = "?tp/bpf_test_run/bpf_trigger_tp"]
#[no_mangle]
extern "C" fn bench_trigger_tp(ctx: *const c_void) -> i32 {
    handle(ctx);
    0
}

#[link_section = "?raw_tp/bpf_trigger_tp"]
#[no_mangle]
extern "C" fn bench_trigger_rawtp(ctx: *const c_void) -> i32 {
    handle(ctx);
    0
}

#[link_section = "?usdt"]
#[no_mangle]
extern "C" fn bench_trigger_usdt(_ctx: *const c_void) -> i32 {
    inc_counter();
    0
}

bpf_object!("GPL");
