#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgroup_skb_direct_packet_access.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::vload;

#[no_mangle]
static mut data_end: u32 = 0;

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn direct_packet_access(skb: *const __sk_buff) -> i32 {
    unsafe { data_end = vload!((*skb).data_end) };
    1
}

bpf_object!("GPL");
