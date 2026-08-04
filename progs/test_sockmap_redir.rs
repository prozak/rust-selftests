#![no_std]
#![no_main]

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_msg_redirect_hash, bpf_msg_redirect_map, bpf_sk_redirect_hash,
    bpf_sk_redirect_map,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_map, bpf_object};

const BPF_MAP_TYPE_SOCKMAP: i32 = 15;
const BPF_MAP_TYPE_SOCKHASH: i32 = 18;
const __MAX_BPF_MAP_TYPE: i32 = 36;

bpf_map! {
    nop_map {
        r#type: *const [i32; 15], // BPF_MAP_TYPE_SOCKMAP
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u64,
    }
}

bpf_map! {
    sock_map {
        r#type: *const [i32; 15], // BPF_MAP_TYPE_SOCKMAP
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u64,
    }
}

bpf_map! {
    nop_hash {
        r#type: *const [i32; 18], // BPF_MAP_TYPE_SOCKHASH
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u64,
    }
}

bpf_map! {
    sock_hash {
        r#type: *const [i32; 18], // BPF_MAP_TYPE_SOCKHASH
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u64,
    }
}

#[link_section = ".maps"]
#[no_mangle]
static verdict_map: BpfMap<i32, u32, { maps::ARRAY }, 2> = BpfMap::new();

/* Set by user space */
#[no_mangle]
static mut redirect_type: i32 = 0;
#[no_mangle]
static mut redirect_flags: i32 = 0;

/// UAPI struct sk_msg_md (bpf.h). data/data_end/sk are __bpf_md_ptr, kept as
/// u64 like __sk_buff's flow_keys/sk (same overlay representation).
#[allow(non_camel_case_types)]
#[repr(C)]
struct sk_msg_md {
    data: u64,
    data_end: u64,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [u32; 4],
    local_ip6: [u32; 4],
    remote_port: u32,
    local_port: u32,
    size: u32,
    sk: u64,
}

#[inline(never)]
fn record_verdict(verdict: i32) {
    let count = bpf_map_lookup_elem(&verdict_map, &verdict) as *mut u32;
    if !count.is_null() {
        unsafe {
            *count += 1;
        }
    }
}

#[link_section = "sk_skb"]
#[no_mangle]
extern "C" fn prog_skb_verdict(skb: *const __sk_buff) -> i32 {
    let rtype = unsafe { redirect_type };
    let rflags = unsafe { redirect_flags } as u64;
    let key: u32 = 0;

    let verdict: i32 = if rtype == BPF_MAP_TYPE_SOCKMAP {
        bpf_sk_redirect_map(skb, &sock_map, key, rflags) as i32
    } else if rtype == BPF_MAP_TYPE_SOCKHASH {
        bpf_sk_redirect_hash(skb, &sock_hash, &key, rflags) as i32
    } else {
        rtype - __MAX_BPF_MAP_TYPE
    };

    record_verdict(verdict);
    verdict
}

#[link_section = "sk_msg"]
#[no_mangle]
extern "C" fn prog_msg_verdict(msg: *const sk_msg_md) -> i32 {
    let rtype = unsafe { redirect_type };
    let rflags = unsafe { redirect_flags } as u64;
    let key: u32 = 0;

    let verdict: i32 = if rtype == BPF_MAP_TYPE_SOCKMAP {
        bpf_msg_redirect_map(msg, &sock_map, key, rflags) as i32
    } else if rtype == BPF_MAP_TYPE_SOCKHASH {
        bpf_msg_redirect_hash(msg, &sock_hash, &key, rflags) as i32
    } else {
        rtype - __MAX_BPF_MAP_TYPE
    };

    record_verdict(verdict);
    verdict
}

bpf_object!("GPL");
