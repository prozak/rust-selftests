#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_stack_map.c
// (which is `#define MAP_TYPE BPF_MAP_TYPE_STACK` + progs/test_queue_stack_map.h)
// (bpf-rs-core idiom).

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{bpf_map_pop_elem, bpf_map_push_elem};
use bpf_rs_core::{bpf_map, bpf_object, vload};

// struct ethhdr (linux/if_ether.h) — packed.
#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// struct iphdr (linux/ip.h) — packed (follows a 14-byte ethhdr, so never
// 4-byte aligned); only through daddr, no options.
#[repr(C, packed)]
struct iphdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

bpf_map! {
    map_in {
        r#type: *const [i32; 23],   // BPF_MAP_TYPE_STACK
        max_entries: *const [i32; 32],
        map_flags: *const [i32; 0],
        key_size: *const [i32; 0],
        value_size: *const [i32; 4], // sizeof(__u32)
    }
}

bpf_map! {
    map_out {
        r#type: *const [i32; 23],   // BPF_MAP_TYPE_STACK
        max_entries: *const [i32; 32],
        map_flags: *const [i32; 0],
        key_size: *const [i32; 0],
        value_size: *const [i32; 4], // sizeof(__u32)
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn _test(skb: *const __sk_buff) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    if data + core::mem::size_of::<ethhdr>() > data_end {
        return TC_ACT_SHOT;
    }

    let iph = (data + core::mem::size_of::<ethhdr>()) as *mut iphdr;
    if iph as usize + core::mem::size_of::<iphdr>() > data_end {
        return TC_ACT_SHOT;
    }

    let mut value: u32 = 0;
    let err = bpf_map_pop_elem(&map_in, &mut value);
    if err != 0 {
        return TC_ACT_SHOT;
    }

    unsafe {
        (*iph).daddr = value;
    }

    let saddr = unsafe { (*iph).saddr };
    let err = bpf_map_push_elem(&map_out, &saddr, 0);
    if err != 0 {
        return TC_ACT_SHOT;
    }

    TC_ACT_OK
}

bpf_object!("GPL");
