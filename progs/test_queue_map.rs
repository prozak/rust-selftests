#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_queue_map.c
// (which is tools/testing/selftests/bpf/progs/test_queue_stack_map.h with
// MAP_TYPE = BPF_MAP_TYPE_QUEUE), bpf-rs-core idiom.

use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{bpf_map_pop_elem, bpf_map_push_elem};
use bpf_rs_core::{bpf_map, bpf_object, maps, vload};

// enum bpf_map_type: BPF_MAP_TYPE_QUEUE.
const BPF_MAP_TYPE_QUEUE: usize = 22;

bpf_map! {
    map_in {
        r#type: *const [i32; BPF_MAP_TYPE_QUEUE],
        max_entries: *const [i32; 32],
        map_flags: *const [i32; 0],
        key_size: *const [i32; 0],
        value_size: *const [i32; 4], // sizeof(__u32)
    }
}

bpf_map! {
    map_out {
        r#type: *const [i32; BPF_MAP_TYPE_QUEUE],
        max_entries: *const [i32; 32],
        map_flags: *const [i32; 0],
        key_size: *const [i32; 0],
        value_size: *const [i32; 4], // sizeof(__u32)
    }
}

// struct ethhdr (linux/if_ether.h) — packed.
#[repr(C, packed)]
struct ethhdr {
    #[allow(dead_code)]
    h_dest: [u8; 6],
    #[allow(dead_code)]
    h_source: [u8; 6],
    #[allow(dead_code)]
    h_proto: u16,
}

// struct iphdr (linux/ip.h) — packed (follows a 14-byte ethhdr, so never
// 4-byte aligned); only through daddr, no options.
#[repr(C, packed)]
struct iphdr {
    #[allow(dead_code)]
    version_ihl: u8,
    #[allow(dead_code)]
    tos: u8,
    #[allow(dead_code)]
    tot_len: u16,
    #[allow(dead_code)]
    id: u16,
    #[allow(dead_code)]
    frag_off: u16,
    #[allow(dead_code)]
    ttl: u8,
    #[allow(dead_code)]
    protocol: u8,
    #[allow(dead_code)]
    check: u16,
    saddr: u32,
    daddr: u32,
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
