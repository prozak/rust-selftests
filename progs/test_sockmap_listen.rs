#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_sockmap_listen.c
// (bpf-rs-core idiom).

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_msg_redirect_hash, bpf_msg_redirect_map, bpf_sk_redirect_hash,
    bpf_sk_redirect_map, bpf_sk_select_reuseport,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;
use bpf_rs_core::{bpf_map, bpf_object};

const BPF_F_INGRESS: u64 = 1;

const SK_DROP: i32 = 0;
const SK_PASS: i32 = 1;

bpf_map! {
    sock_map {
        r#type: *const [i32; 15], // BPF_MAP_TYPE_SOCKMAP
        max_entries: *const [i32; 2],
        key: *const u32,
        value: *const u64,
    }
}

bpf_map! {
    nop_map {
        r#type: *const [i32; 15], // BPF_MAP_TYPE_SOCKMAP
        max_entries: *const [i32; 2],
        key: *const u32,
        value: *const u64,
    }
}

bpf_map! {
    sock_hash {
        r#type: *const [i32; 18], // BPF_MAP_TYPE_SOCKHASH
        max_entries: *const [i32; 2],
        key: *const u32,
        value: *const u64,
    }
}

#[link_section = ".maps"]
#[no_mangle]
static verdict_map: BpfMap<i32, u32, { maps::ARRAY }, 2> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static parser_map: BpfMap<i32, i32, { maps::ARRAY }, 1> = BpfMap::new();

/* toggled by user-space */
#[no_mangle]
// C declares these `bool`; clang compiles the tests as `!= 1` (jne 1), so
// they are true only for the byte value 1. Mirror with u8 + `== 1`.
static mut test_sockmap: u8 = 0;
#[no_mangle]
static mut test_ingress: u8 = 0;

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

/// UAPI struct sk_reuseport_md (linux/bpf.h). `data`/`data_end`/`sk`/
/// `migrating_sk` are all `__bpf_md_ptr` (real 64-bit pointers on this
/// arch), unlike xdp_md's plain u32 offsets.
#[allow(non_camel_case_types)]
#[repr(C)]
struct sk_reuseport_md {
    data: u64,
    data_end: u64,
    len: u32,
    eth_protocol: u32,
    ip_protocol: u32,
    bind_inany: u32,
    hash: u32,
    sk: u64,
    migrating_sk: u64,
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

#[link_section = "sk_skb/stream_parser"]
#[no_mangle]
extern "C" fn prog_stream_parser(skb: *const __sk_buff) -> i32 {
    let key: i32 = 0;
    let value = bpf_map_lookup_elem(&parser_map, &key) as *const i32;
    if !value.is_null() {
        let v = unsafe { *value };
        if v != 0 {
            return v;
        }
    }

    vload!((*skb).len) as i32
}

#[link_section = "sk_skb/stream_verdict"]
#[no_mangle]
extern "C" fn prog_stream_verdict(skb: *const __sk_buff) -> i32 {
    let zero: u32 = 0;
    let sockmap = unsafe { test_sockmap } == 1;

    let verdict: i32 = if sockmap {
        bpf_sk_redirect_map(skb, &sock_map, zero, 0) as i32
    } else {
        bpf_sk_redirect_hash(skb, &sock_hash, &zero, 0) as i32
    };

    record_verdict(verdict);
    verdict
}

#[link_section = "sk_skb"]
#[no_mangle]
extern "C" fn prog_skb_verdict(skb: *const __sk_buff) -> i32 {
    let zero: u32 = 0;
    let sockmap = unsafe { test_sockmap } == 1;
    let flags: u64 = if unsafe { test_ingress } == 1 {
        BPF_F_INGRESS
    } else {
        0
    };

    let verdict: i32 = if sockmap {
        bpf_sk_redirect_map(skb, &sock_map, zero, flags) as i32
    } else {
        bpf_sk_redirect_hash(skb, &sock_hash, &zero, flags) as i32
    };

    record_verdict(verdict);
    verdict
}

#[link_section = "sk_msg"]
#[no_mangle]
extern "C" fn prog_msg_verdict(msg: *const sk_msg_md) -> i32 {
    let zero: u32 = 0;
    let sockmap = unsafe { test_sockmap } == 1;

    let verdict: i32 = if sockmap {
        bpf_msg_redirect_map(msg, &sock_map, zero, 0) as i32
    } else {
        bpf_msg_redirect_hash(msg, &sock_hash, &zero, 0) as i32
    };

    record_verdict(verdict);
    verdict
}

#[link_section = "sk_reuseport"]
#[no_mangle]
extern "C" fn prog_reuseport(reuse: *mut sk_reuseport_md) -> i32 {
    let zero: u32 = 0;
    // clang compiles this particular `if (test_sockmap)` as `!= 0` (jne 0)
    // while the sk_skb/sk_msg sites compile as `!= 1` — the per-site
    // variance of the _Bool compare class, mirrored per site.
    let sockmap = unsafe { test_sockmap } != 0;

    let err: i64 = if sockmap {
        bpf_sk_select_reuseport(reuse, &sock_map, &zero, 0)
    } else {
        bpf_sk_select_reuseport(reuse, &sock_hash, &zero, 0)
    };

    let verdict = if err != 0 { SK_DROP } else { SK_PASS };

    record_verdict(verdict);
    verdict
}

bpf_object!("GPL");
