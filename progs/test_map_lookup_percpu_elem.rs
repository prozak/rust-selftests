#![no_std]
#![no_main]

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_loop, bpf_map_lookup_percpu_elem};
use bpf_rs_core::maps::{self, BpfMap};

#[no_mangle]
static mut percpu_array_elem_sum: u64 = 0;
#[no_mangle]
static mut percpu_hash_elem_sum: u64 = 0;
#[no_mangle]
static mut percpu_lru_hash_elem_sum: u64 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static nr_cpus: i32 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static my_pid: i32 = 0;

#[link_section = ".maps"]
#[no_mangle]
static percpu_array_map: BpfMap<u32, u64, { maps::PERCPU_ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static percpu_hash_map: BpfMap<u64, u64, { maps::PERCPU_HASH }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static percpu_lru_hash_map: BpfMap<u64, u64, { maps::LRU_PERCPU_HASH }, 1> = BpfMap::new();

struct ReadPercpuElemCtx {
    map: *const c_void,
    sum: u64,
}

extern "C" fn read_percpu_elem_callback(index: u64, ctx: *mut ReadPercpuElemCtx) -> i64 {
    let key: u64 = 0;
    let value = bpf_map_lookup_percpu_elem(unsafe { (*ctx).map }, &key, index as u32) as *const u64;
    if !value.is_null() {
        unsafe { (*ctx).sum += *value };
    }
    0
}

#[link_section = "tp/syscalls/sys_enter_getuid"]
#[no_mangle]
extern "C" fn sysenter_getuid(_ctx: *const c_void) -> i32 {
    let pid = unsafe { core::ptr::read_volatile(&my_pid) };
    if pid != (bpf_get_current_pid_tgid() >> 32) as i32 {
        return 0;
    }

    let cpus = unsafe { core::ptr::read_volatile(&nr_cpus) } as u32;

    let mut map_ctx = ReadPercpuElemCtx {
        map: &percpu_array_map as *const _ as *const c_void,
        sum: 0,
    };
    bpf_loop(
        cpus,
        read_percpu_elem_callback,
        &mut map_ctx as *mut ReadPercpuElemCtx,
        0,
    );
    unsafe { percpu_array_elem_sum = map_ctx.sum };

    map_ctx.map = &percpu_hash_map as *const _ as *const c_void;
    map_ctx.sum = 0;
    bpf_loop(
        cpus,
        read_percpu_elem_callback,
        &mut map_ctx as *mut ReadPercpuElemCtx,
        0,
    );
    unsafe { percpu_hash_elem_sum = map_ctx.sum };

    map_ctx.map = &percpu_lru_hash_map as *const _ as *const c_void;
    map_ctx.sum = 0;
    bpf_loop(
        cpus,
        read_percpu_elem_callback,
        &mut map_ctx as *mut ReadPercpuElemCtx,
        0,
    );
    unsafe { percpu_lru_hash_elem_sum = map_ctx.sum };

    0
}

bpf_object!("GPL");
