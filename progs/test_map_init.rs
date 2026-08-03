#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_map_init.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_map_update_elem};
use bpf_rs_core::maps::{self, BpfMap};

#[no_mangle]
static mut inKey: u64 = 0;
#[no_mangle]
static mut inValue: u64 = 0;
#[no_mangle]
static mut inPid: u32 = 0;

#[link_section = ".maps"]
#[no_mangle]
static hashmap1: BpfMap<u64, u64, { maps::PERCPU_HASH }, 2> = BpfMap::new();

const BPF_NOEXIST: u64 = 1;

#[link_section = "tp/syscalls/sys_enter_getpgid"]
#[no_mangle]
extern "C" fn sysenter_getpgid(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        let cur_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if cur_pid == inPid {
            bpf_map_update_elem(&hashmap1, &inKey, &inValue, BPF_NOEXIST);
        }
    }
    0
}

bpf_object!("GPL");
