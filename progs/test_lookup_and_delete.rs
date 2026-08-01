#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_lookup_and_delete.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_map_update_elem};
use bpf_rs_core::maps::{self, BpfMap};

#[link_section = ".maps"]
#[no_mangle]
static hash_map: BpfMap<u64, u64, { maps::HASH }, 2> = BpfMap::new();

#[no_mangle]
static mut set_pid: u32 = 0;
#[no_mangle]
static mut set_key: u64 = 0;
#[no_mangle]
static mut set_value: u64 = 0;

const BPF_NOEXIST: u64 = 1;

#[link_section = "tp/syscalls/sys_enter_getpgid"]
#[no_mangle]
extern "C" fn bpf_lookup_and_delete_test(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        if set_pid as u64 == bpf_get_current_pid_tgid() >> 32 {
            bpf_map_update_elem(&hash_map, &set_key, &set_value, BPF_NOEXIST);
        }
    }
    0
}

bpf_object!("GPL");
