#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_xdp_with_cpumap_frags_helpers.c,
// bpf-rs-core idiom.
//
// Maps-only-plus-two-trivial-progs object: a CPUMAP whose entries carry an
// XDP program fd (bpf_prog_get_info_by_fd / bpf_map_update_elem consumer is
// prog_tests/xdp_cpumap_attach.c). BPF_MAP_TYPE_CPUMAP isn't in the
// generic's TYPE list, and the C source declares key_size/value_size (not
// key/value pointer types), so the bpf_map! escape hatch is required.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;

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

bpf_map! {
    cpu_map {
        r#type: *const [i32; 16],       // BPF_MAP_TYPE_CPUMAP = 16
        key_size: *const [i32; 4],      // sizeof(__u32)
        value_size: *const [i32; 8],    // sizeof(struct bpf_cpumap_val)
        max_entries: *const [i32; 4],
    }
}

#[link_section = "xdp/cpumap"]
#[no_mangle]
extern "C" fn xdp_dummy_cm(_ctx: *const xdp_md) -> i32 {
    XDP_PASS
}

#[link_section = "xdp.frags/cpumap"]
#[no_mangle]
extern "C" fn xdp_dummy_cm_frags(_ctx: *const xdp_md) -> i32 {
    XDP_PASS
}

bpf_object!("GPL");
