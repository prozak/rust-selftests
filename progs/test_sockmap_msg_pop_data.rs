#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_msg_pop_data;
use bpf_rs_core::maps::BpfMap;
use bpf_rs_core::vload;

const BPF_MAP_TYPE_SOCKMAP: usize = 15;

#[link_section = ".maps"]
#[no_mangle]
static sock_map: BpfMap<i32, i32, BPF_MAP_TYPE_SOCKMAP, 1> = BpfMap::new();

const POP_START: u32 = 0x48a3;
const POP_LEN: u32 = 0xfffffffd;

#[no_mangle]
static mut pop_data_ret: isize = 1;

// UAPI struct sk_msg_md fields through `size` (bpf.h). `data`/`data_end`
// are __bpf_md_ptr (8-byte-padded pointer unions); represented as u64 like
// __sk_buff.sk in other translations. `sk` after `size` is unused by this
// program and omitted; layout/offsets up to `size` must match the kernel
// struct exactly since the verifier rewrites this field access by byte
// offset.
#[allow(non_camel_case_types, dead_code)]
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
}

#[link_section = "sk_msg"]
#[no_mangle]
extern "C" fn prog_msg_pop_data(msg: *mut sk_msg_md) -> i32 {
    let size = vload!((*msg).size);

    if size <= POP_START {
        return 1; // SK_PASS
    }

    unsafe {
        pop_data_ret = bpf_msg_pop_data(msg, POP_START, POP_LEN, 0) as isize;
    }
    1 // SK_PASS
}

bpf_object!("GPL");
