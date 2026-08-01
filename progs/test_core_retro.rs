#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_core_retro.c, bpf-rs-core idiom.
//
// The C source declares a minimal local `struct task_struct { int tgid; }`
// with preserve_access_index and reads it via BPF_CORE_READ, i.e. a
// bpf_probe_read_kernel of the CO-RE-relocated field address (the pointer
// from bpf_get_current_task() is a scalar, not a BTF-typed pointer, so a
// direct dereference would be rejected). The `#[btf]` macro reproduces the
// local BTF struct; `.tgid().as_ptr()` yields the relocated address.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_task, bpf_map_lookup_elem, bpf_map_update_elem,
    bpf_probe_read_kernel,
};
use bpf_rs_core::maps::{self, BpfMap};
use btf_macros::btf;

#[btf]
struct task_struct {
    tgid: i32,
}

#[link_section = ".maps"]
#[no_mangle]
static exp_tgid_map: BpfMap<i32, i32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static results: BpfMap<i32, i32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "tp/raw_syscalls/sys_enter"]
#[no_mangle]
extern "C" fn handle_sys_enter(_ctx: *const core::ffi::c_void) -> i32 {
    let task = bpf_get_current_task() as *const task_struct;
    let mut tgid: i32 = 0;
    bpf_probe_read_kernel(
        &mut tgid,
        core::mem::size_of::<i32>() as u32,
        unsafe { &*task }.tgid().as_ptr() as *const core::ffi::c_void,
    );

    let zero: i32 = 0;
    let real_tgid = (bpf_get_current_pid_tgid() >> 32) as i32;
    let exp_tgid = bpf_map_lookup_elem(&exp_tgid_map, &zero);

    // only pass through sys_enters from test process
    if exp_tgid.is_null() || unsafe { *(exp_tgid as *const i32) } != real_tgid {
        return 0;
    }

    bpf_map_update_elem(&results, &zero, &tgid, 0);

    0
}

bpf_object!("GPL");
