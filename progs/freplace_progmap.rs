#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/freplace_progmap.c,
// bpf-rs-core idiom.
//
// cpu_map's value type is struct bpf_cpumap_val { __u32 qsize; union { int
// fd; __u32 id; } bpf_prog; } (8 bytes); the kernel's cpumap alloc_check only
// enforces value_size == offsetofend(qsize) (4) or offsetofend(bpf_prog.fd)
// (8) and never inspects BTF field names (map_check_btf = map_check_no_btf),
// so a plain two-u32 struct of the same size suffices.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_redirect_map;
use bpf_rs_core::maps::BpfMap;

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

/// UAPI struct xdp_md (linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

// struct bpf_cpumap_val { __u32 qsize; union { int fd; __u32 id; } bpf_prog; };
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_cpumap_val {
    pub qsize: u32,
    pub bpf_prog: u32,
}

const CPUMAP: usize = 16; // BPF_MAP_TYPE_CPUMAP

#[link_section = ".maps"]
#[no_mangle]
static cpu_map: BpfMap<u32, bpf_cpumap_val, { CPUMAP }, 1> = BpfMap::new();

#[link_section = "xdp/cpumap"]
#[no_mangle]
extern "C" fn xdp_drop_prog(_ctx: *const xdp_md) -> i32 {
    XDP_DROP
}

#[link_section = "freplace"]
#[no_mangle]
extern "C" fn xdp_cpumap_prog(_ctx: *const xdp_md) -> i32 {
    bpf_redirect_map(&cpu_map, 0, XDP_PASS as u64) as i32
}

bpf_object!("GPL");
