#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp_update_frags.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_xdp_load_bytes, bpf_xdp_store_bytes};
use bpf_rs_core::vload;

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

#[no_mangle]
#[link_section = "version"]
static _version: i32 = 1;

#[link_section = "xdp.frags"]
#[no_mangle]
extern "C" fn xdp_adjust_frags(xdp: *const xdp_md) -> i32 {
    let data_end = vload!((*xdp).data_end) as usize;
    let data = vload!((*xdp).data) as usize;

    if data + core::mem::size_of::<u32>() > data_end {
        return XDP_DROP;
    }

    let offset = unsafe { core::ptr::read_unaligned(data as *const u32) };

    let mut val: [u8; 16] = [0u8; 16];
    let err = bpf_xdp_load_bytes(
        xdp as *mut c_void,
        offset,
        val.as_mut_ptr() as *mut c_void,
        val.len() as u32,
    );
    if err < 0 {
        return XDP_DROP;
    }

    if val[0] != 0xaa || val[15] != 0xaa {
        return XDP_DROP;
    }

    val[0] = 0xbb;
    val[15] = 0xbb;
    let err = bpf_xdp_store_bytes(
        xdp as *mut c_void,
        offset,
        val.as_ptr() as *const c_void,
        val.len() as u32,
    );
    if err < 0 {
        return XDP_DROP;
    }

    XDP_PASS
}

bpf_object!("GPL");
