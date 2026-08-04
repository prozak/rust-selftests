#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_unpriv_bpf_disabled.c
// (bpf-rs-core idiom).
//
// array/percpu_array/hash/percpu_hash use __type(key,value) so they take
// the BpfMap<K,V,TYPE,MAX> generic; perfbuf (no max_entries, sized by
// libbpf to nr_cpus) and prog_array (key_size/value_size instead of
// __type) need the bpf_map! escape hatch, same shape as
// test_perf_buffer.rs / tailcall1.rs.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_perf_event_output, bpf_ringbuf_output,
};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

#[no_mangle]
static mut perfbuf_val: u32 = 0;
#[no_mangle]
static mut ringbuf_val: u32 = 0;

#[no_mangle]
static mut test_pid: i32 = 0;

#[link_section = ".maps"]
#[no_mangle]
static array: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static percpu_array: BpfMap<u32, u32, { maps::PERCPU_ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static hash: BpfMap<u32, u32, { maps::HASH }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static percpu_hash: BpfMap<u32, u32, { maps::PERCPU_HASH }, 1> = BpfMap::new();

bpf_map! {
    perfbuf {
        r#type: *const [i32; maps::PERF_EVENT_ARRAY],
        key: *const u32,
        value: *const u32,
    }
}

bpf_map! {
    ringbuf {
        r#type: *const [i32; maps::RINGBUF],
        max_entries: *const [i32; 4096], // 1 << 12
    }
}

bpf_map! {
    prog_array {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

const BPF_F_CURRENT_CPU: u64 = 0xffffffff;

#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn sys_nanosleep_enter(ctx: *const c_void) -> i32 {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    if cur_pid != unsafe { test_pid } {
        return 0;
    }

    let pval: u32 = unsafe { perfbuf_val };
    let rval: u32 = unsafe { ringbuf_val };

    bpf_perf_event_output(
        ctx,
        &perfbuf,
        BPF_F_CURRENT_CPU,
        &pval,
        core::mem::size_of::<u32>() as u64,
    );
    bpf_ringbuf_output(
        &ringbuf,
        &rval as *const u32 as *const c_void,
        core::mem::size_of::<u32>() as u64,
        0,
    );

    0
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn handle_perf_event(_ctx: *const c_void) -> i32 {
    0
}

bpf_object!("GPL");
