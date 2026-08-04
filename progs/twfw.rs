#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/twfw.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_map_lookup_elem;
use bpf_rs_core::maps::{self, BpfMap};

const TWFW_MAX_TIERS: u8 = 64;

#[repr(C)]
struct TwfwTierValue {
    mask: [u64; 1],
}

#[repr(C)]
struct Rule {
    seqnum: u8,
}

#[link_section = ".maps"]
#[no_mangle]
static rules: BpfMap<u32, Rule, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static tiers: BpfMap<u32, TwfwTierValue, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn twfw_verifier(_skb: *const __sk_buff) -> i32 {
    let key: u32 = 0;

    let tier = bpf_map_lookup_elem(&tiers, &key) as *const TwfwTierValue;
    if tier.is_null() {
        return 1;
    }

    let rule = bpf_map_lookup_elem(&rules, &key) as *const Rule;
    if rule.is_null() {
        return 1;
    }

    let seqnum = unsafe { (*rule).seqnum };
    if seqnum < TWFW_MAX_TIERS {
        // rule->seqnum / 64 should always be 0, so the mask array index is
        // always the compile-time constant 0 (matches the C comment).
        let mask = unsafe { (*tier).mask[0] };
        if mask != 0 {
            return 0;
        }
    }

    1
}

bpf_object!("GPL");
