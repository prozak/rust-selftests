#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tc_bpf.c
// (bpf-rs-core idiom).
//
// Two dummy TC programs exercising the TC-BPF API (bpf_tc_hook_create /
// bpf_tc_attach / bpf_tc_query / bpf_tc_detach) from userspace:
// - `cls` (SEC("tc")): always accepts, used as the fd attached/queried by
//   the tc_bpf_root subtest.
// - `pkt_ptr` (SEC("tcx/ingress")): a data/data_end bounds check (eth + ip
//   header), used to verify tc-bpf works without CAP_SYS_ADMIN/CAP_PERFMON
//   in the tc_bpf_non_root subtest.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::vload;

const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn cls(_skb: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tcx/ingress"]
#[no_mangle]
extern "C" fn pkt_ptr(skb: *const __sk_buff) -> i32 {
    let data = vload!((*skb).data) as usize;
    let data_end = vload!((*skb).data_end) as usize;
    let iph = data + ETH_HDR_LEN;

    if iph + IP_HDR_LEN > data_end {
        return 1;
    }
    0
}

bpf_object!("GPL");
