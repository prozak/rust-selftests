#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_pkt_md_access.c
// (little-endian variant), bpf-rs-core idiom.
//
// A TC (SCHED_CLS) program whose whole point is narrow context loads: each
// __sk_buff u32 field is read back as u8, u16, and u32 and cross-checked.
// Volatile reads keep LLVM from merging the accesses, mirroring the C
// `*(volatile TYPE *)&skb->FIELD` pattern; the verifier rewrites each
// narrow ctx load individually.

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::{bpf_object, vload, vload_as};

macro_rules! test_field {
    ($skb:expr, $field:ident, $ty:ty, $mask:expr) => {{
        let tmp = vload_as!((*$skb).$field, $ty);
        let full = vload!((*$skb).$field);
        if tmp as u32 != (full & $mask) {
            return TC_ACT_SHOT;
        }
    }};
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_pkt_md_access(skb: *const __sk_buff) -> i32 {
    test_field!(skb, len, u8, 0xFF);
    test_field!(skb, len, u16, 0xFFFF);
    test_field!(skb, len, u32, 0xFFFF_FFFF);
    test_field!(skb, protocol, u16, 0xFFFF);
    test_field!(skb, protocol, u32, 0xFFFF_FFFF);
    test_field!(skb, hash, u8, 0xFF);
    test_field!(skb, hash, u16, 0xFFFF);
    test_field!(skb, hash, u32, 0xFFFF_FFFF);
    TC_ACT_OK
}

bpf_object!("GPL");
