#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/prepare.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

#[no_mangle]
static mut err: i32 = 0;

// BPF_MAP_TYPE_RINGBUF: type + max_entries only, no key/value.
bpf_rs_core::bpf_map! {
    ringbuf {
        r#type: *const [i32; maps::RINGBUF],
        max_entries: *const [i32; 4096],
    }
}

#[link_section = ".maps"]
#[no_mangle]
static array_map: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn program(_skb: *const c_void) -> i32 {
    unsafe { err = 0 };
    0
}

bpf_object!("GPL");
