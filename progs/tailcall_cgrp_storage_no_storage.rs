#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/tailcall_cgrp_storage_no_storage.c,
// bpf-rs-core idiom.
//
// prog_array has explicit key_size/value_size (not key/value types), so it
// needs the bpf_map! escape hatch rather than the BpfMap<K,V,TYPE,MAX>
// generic.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::{bpf_map, bpf_object, maps};

bpf_map! {
    prog_array {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn caller_prog(skb: *const __sk_buff) -> i32 {
    bpf_tail_call(skb as *const core::ffi::c_void, &prog_array, 0);
    1
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn leaf_prog(_skb: *const __sk_buff) -> i32 {
    1
}

bpf_object!("GPL");
