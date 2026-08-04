#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_xdp_with_cpumap_helpers.c
// (bpf-rs-core idiom).
//
// cpu_map uses key_size/value_size (not __type) in the C source, so its BTF
// map struct is the bpf_map! escape hatch (type/key_size/value_size/
// max_entries members, same __uint(...) pointer-array encoding as the C
// original's field order).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_smp_processor_id, bpf_redirect_map};
use bpf_rs_core::vload;

const IFINDEX_LO: u32 = 1;

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

bpf_map! {
    cpu_map {
        r#type: *const [i32; 16],      // BPF_MAP_TYPE_CPUMAP
        key_size: *const [i32; 4],     // sizeof(__u32)
        value_size: *const [i32; 8],   // sizeof(struct bpf_cpumap_val)
        max_entries: *const [i32; 4],
    }
}

#[no_mangle]
static mut redirect_count: u32 = 0;

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_redir_prog(_ctx: *const xdp_md) -> i32 {
    bpf_redirect_map(&cpu_map, 0, 0) as i32
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_dummy_prog(_ctx: *const xdp_md) -> i32 {
    XDP_PASS
}

#[link_section = "xdp/cpumap"]
#[no_mangle]
extern "C" fn xdp_dummy_cm(ctx: *const xdp_md) -> i32 {
    if bpf_get_smp_processor_id() == 0 {
        unsafe { redirect_count += 1 };
    }

    let ingress_ifindex = vload!((*ctx).ingress_ifindex);
    if ingress_ifindex == IFINDEX_LO {
        return XDP_DROP;
    }

    XDP_PASS
}

#[link_section = "xdp.frags/cpumap"]
#[no_mangle]
extern "C" fn xdp_dummy_cm_frags(_ctx: *const xdp_md) -> i32 {
    XDP_PASS
}

bpf_object!("GPL");
