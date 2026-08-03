#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp_context_test_run.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_xdp_adjust_meta;
use bpf_rs_core::vload;

const XDP_ABORTED: i32 = 0;

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

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_context(ctx: *const xdp_md) -> i32 {
    let data = vload!((*ctx).data) as usize as *const u32;
    let metadata = vload!((*ctx).data_meta) as usize as *const u32;

    if unsafe { metadata.wrapping_add(1) } as usize > data as usize {
        return XDP_ABORTED;
    }
    let ret = unsafe { core::ptr::read_volatile(metadata) };
    if unsafe { bpf_xdp_adjust_meta(ctx as *mut xdp_md, 4) } != 0 {
        return XDP_ABORTED;
    }
    ret as i32
}

bpf_object!("GPL");
