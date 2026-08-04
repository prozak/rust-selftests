#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp_adjust_tail_shrink.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_xdp_adjust_tail, bpf_xdp_get_buff_len};

const XDP_DROP: i32 = 1;
const XDP_TX: i32 = 3;

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
extern "C" fn _xdp_adjust_tail_shrink(ctx: *const xdp_md) -> i32 {
    let data_end = unsafe { (*ctx).data_end } as usize as *const u8;
    let data = unsafe { (*ctx).data } as usize as *const u8;
    let offset: i32;

    match bpf_xdp_get_buff_len(ctx as *mut xdp_md) {
        54 => {
            /* sizeof(pkt_v4) */
            offset = 256; /* shrink too much */
        }
        9000 => {
            /* non-linear buff test cases */
            if unsafe { data.add(1) } > data_end {
                return XDP_DROP;
            }

            let b0 = unsafe { core::ptr::read_volatile(data) };
            match b0 {
                0 => offset = 10,
                1 => offset = 4100,
                2 => offset = 8200,
                _ => return XDP_DROP,
            }
        }
        _ => {
            offset = 20;
        }
    }

    if bpf_xdp_adjust_tail(ctx as *mut xdp_md, 0 - offset) != 0 {
        return XDP_DROP;
    }
    XDP_TX
}

bpf_object!("GPL");
