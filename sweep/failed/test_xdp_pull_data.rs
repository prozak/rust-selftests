#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp_pull_data.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::vload;

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

const XDP_PACKET_HEADROOM: i32 = 256;
const __PAGE_SIZE: i32 = 4096;

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

/// struct xdp_frame (net/core/xdp.c / vmlinux.h), used only for its size.
#[repr(C)]
struct xdp_frame {
    data: *mut core::ffi::c_void,
    len: u32,
    headroom: u32,
    metasize: u32,
    mem_type: u32,
    dev_rx: *mut core::ffi::c_void,
    frame_sz: u32,
    flags: u32,
}

extern "C" {
    fn bpf_xdp_pull_data(ctx: *mut xdp_md, len: u32) -> i32;
}

#[no_mangle]
static mut xdpf_sz: i32 = 0;
#[no_mangle]
static mut sinfo_sz: i32 = 0;
#[no_mangle]
static mut data_len: i32 = 0;
#[no_mangle]
static mut pull_len: i32 = 0;

#[link_section = "xdp.frags"]
#[no_mangle]
extern "C" fn xdp_find_sizes(ctx: *const xdp_md) -> i32 {
    unsafe { xdpf_sz = core::mem::size_of::<xdp_frame>() as i32 };

    let data_end = vload!((*ctx).data_end) as i32;
    let data = vload!((*ctx).data) as i32;
    unsafe { sinfo_sz = __PAGE_SIZE - XDP_PACKET_HEADROOM - (data_end - data) };

    XDP_PASS
}

#[link_section = "xdp.frags"]
#[no_mangle]
extern "C" fn xdp_pull_data_prog(ctx: *const xdp_md) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize;
    let data = vload!((*ctx).data) as usize;

    if unsafe { data_len } != (data_end - data) as i32 {
        return XDP_DROP;
    }

    let err = unsafe { bpf_xdp_pull_data(ctx as *mut xdp_md, pull_len as u32) };
    if err != 0 {
        return XDP_DROP;
    }

    let data = vload!((*ctx).data) as usize;
    let val_p = data + 1024;
    let data_end = vload!((*ctx).data_end) as usize;
    if val_p + 1 > data_end {
        return XDP_DROP;
    }

    let v = unsafe { core::ptr::read_volatile(val_p as *const u8) };
    if v != 0xbb {
        return XDP_DROP;
    }

    XDP_PASS
}

bpf_object!("GPL");
