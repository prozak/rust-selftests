// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Hengqi Chen */
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_prog_array_init.c
// (bpf-rs-core idiom).
//
// prog_array_init[1] is statically &tailcall_1 (`.values = { [1] =
// (void *)&tailcall_1 }`) and slot 0 is empty. A Rust fn pointer cannot be
// null and `Option<fn>` in a map definition crashes llc's BTF emitter
// (BTFDebug::visitMapDefType on the enum), so the slots are `*const c_void`
// with the program's address cast in: that emits the slot storage with a
// null slot 0 and the .rel.maps entry for slot 1, and scripts/
// btf_map_slots.py rewrites the BTF member to the zero-length array of
// function pointers libbpf demands.

use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_tail_call};
use bpf_rs_core::{bpf_object, maps};
use core::ffi::c_void;

// const volatile pid_t my_pid = 0;
#[link_section = ".rodata"]
#[no_mangle]
static my_pid: i32 = 0;

#[no_mangle]
static mut value: i32 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn tailcall_1(_ctx: *const c_void) -> i32 {
    unsafe { value = 42 };
    0
}

type TailcallFn = extern "C" fn(*const c_void) -> i32;

#[allow(non_camel_case_types)]
#[repr(C)]
struct prog_array_init_def {
    r#type: *const [i32; maps::PROG_ARRAY],
    max_entries: *const [i32; 2],
    key_size: *const [i32; 4],
    values: [*const c_void; 2],
}
unsafe impl Sync for prog_array_init_def {}

#[link_section = ".maps"]
#[no_mangle]
static prog_array_init: prog_array_init_def = prog_array_init_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [core::ptr::null(), tailcall_1 as TailcallFn as *const c_void],
};

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn entry(ctx: *const c_void) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    if pid != unsafe { core::ptr::read_volatile(&my_pid) } {
        return 0;
    }

    bpf_tail_call(ctx, &prog_array_init, 1);
    0
}

bpf_object!("GPL");
