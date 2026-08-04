#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_sockmap_strp.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_sk_redirect_map, bpf_skb_change_tail};
use bpf_rs_core::maps::BpfMap;
use bpf_rs_core::vload;

const SK_PASS: i32 = 1;

#[no_mangle]
static mut verdict_max_size: i32 = 10000;

// BPF_MAP_TYPE_SOCKMAP == 15.
#[link_section = ".maps"]
#[no_mangle]
static sock_map: BpfMap<i32, i32, 15, 20> = BpfMap::new();

#[link_section = "sk_skb/stream_verdict"]
#[no_mangle]
extern "C" fn prog_skb_verdict(skb: *const __sk_buff) -> i32 {
    let one: u32 = 1;

    let len = vload!((*skb).len);
    let max_size = unsafe { verdict_max_size };
    if len as i32 > max_size {
        return SK_PASS;
    }

    bpf_sk_redirect_map(skb as *const core::ffi::c_void, &sock_map, one, 0) as i32
}

#[link_section = "sk_skb/stream_verdict"]
#[no_mangle]
extern "C" fn prog_skb_verdict_pass(_skb: *const __sk_buff) -> i32 {
    SK_PASS
}

#[link_section = "sk_skb/stream_parser"]
#[no_mangle]
extern "C" fn prog_skb_parser(skb: *const __sk_buff) -> i32 {
    vload!((*skb).len) as i32
}

#[link_section = "sk_skb/stream_parser"]
#[no_mangle]
extern "C" fn prog_skb_parser_partial(skb: *const __sk_buff) -> i32 {
    // agreement with the test program on a 4-byte size header
    // and 6-byte body.
    if vload!((*skb).len) < 4 {
        // need more header to determine full length
        return 0;
    }
    // return full length decoded from header.
    // the return value may be larger than skb->len which
    // means framework must wait body coming.
    10
}

#[link_section = "sk_skb/stream_parser"]
#[no_mangle]
extern "C" fn prog_skb_parser_resize(skb: *const __sk_buff) -> i32 {
    let len = vload!((*skb).len);
    bpf_skb_change_tail(skb as *const core::ffi::c_void, len, 0);
    vload!((*skb).len) as i32
}

bpf_object!("GPL");
