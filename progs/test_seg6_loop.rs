#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_seg6_loop.c
// (bpf-rs-core idiom). Loaded only (verifier-scale test, BPF_PROG_TYPE_LWT_
// SEG6LOCAL, never run) -- see prog_tests/bpf_verif_scale.c
// test_verif_scale_seg6_loop(). Packet parsing/mutation mirrors
// test_lwt_seg6local.rs's __add_egr_x: direct packet access into packed
// structs plus the bpf_lwt_seg6_* / bpf_skb_load_bytes helpers.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_lwt_seg6_action, bpf_lwt_seg6_adjust_srh, bpf_lwt_seg6_store_bytes, bpf_skb_load_bytes,
};
use bpf_rs_core::vload;

const BPF_DROP: i32 = 2;
const BPF_REDIRECT: i32 = 7;

const SEG6_LOCAL_ACTION_END_X: u32 = 2;

const SR6_TLV_PADDING: u8 = 4;
const SR6_TLV_HMAC: u8 = 5;

const SR6_FLAG_ALERT: u8 = 1 << 4;

const EINVAL: i32 = 22;

#[inline(always)]
fn cpu_to_be64(x: u64) -> u64 {
    x.to_be()
}

// struct ip6_t (packed): only the fields actually read/sized are named
// individually; the 4+8+20-bit bitfield trio collapses into one opaque u32,
// matching the C struct's packed byte layout exactly (40 bytes total, same
// as a real IPv6 fixed header).
#[repr(C, packed)]
struct Ip6Hdr {
    #[allow(dead_code)]
    ver_priority_flow: u32,
    #[allow(dead_code)]
    payload_len: u16,
    next_header: u8,
    #[allow(dead_code)]
    hop_limit: u8,
    #[allow(dead_code)]
    src_hi: u64,
    #[allow(dead_code)]
    src_lo: u64,
    #[allow(dead_code)]
    dst_hi: u64,
    #[allow(dead_code)]
    dst_lo: u64,
}

// struct ip6_addr_t (packed), 16 bytes.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Ip6AddrT {
    hi: u64,
    lo: u64,
}

// struct ip6_srh_t (packed), 8-byte fixed header (the `segments[0]` flexible
// array that follows in the real SRH lives in packet memory past this
// struct and is never given a Rust-side representation).
#[repr(C, packed)]
struct Ip6SrhT {
    #[allow(dead_code)]
    nexthdr: u8,
    hdrlen: u8,
    r#type: u8,
    #[allow(dead_code)]
    segments_left: u8,
    first_segment: u8,
    flags: u8,
    #[allow(dead_code)]
    tag: u16,
}

const IP6_SRH_FLAGS_OFFSET: u32 = 5;

// struct sr6_tlv_t (packed), 2-byte fixed header.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Sr6TlvT {
    r#type: u8,
    len: u8,
}

#[inline(always)]
fn get_srh(skb: *const __sk_buff) -> *mut Ip6SrhT {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;

    // The version-byte check is folded into the ip6 header bounds check
    // (the version nibble is the header's first byte) rather than issued
    // as its own `+ 1 > data_end` compare: a bare 1-byte check gets
    // strength-reduced by LLVM into a 32-bit (w-register) comparison that
    // this kernel's verifier can't range-track for packet pointers, unlike
    // the `ptr + N > data_end` (N > 1) form used throughout this file.
    if data + core::mem::size_of::<Ip6Hdr>() > data_end {
        return core::ptr::null_mut();
    }
    let ip = data as *const Ip6Hdr;
    let ipver = unsafe { *(data as *const u8) };
    if (ipver >> 4) != 6 {
        return core::ptr::null_mut();
    }
    if unsafe { (*ip).next_header } != 43 {
        return core::ptr::null_mut();
    }

    let srh_addr = data + core::mem::size_of::<Ip6Hdr>();
    if srh_addr + core::mem::size_of::<Ip6SrhT>() > data_end {
        return core::ptr::null_mut();
    }
    let srh = srh_addr as *mut Ip6SrhT;
    if unsafe { (*srh).r#type } != 4 {
        return core::ptr::null_mut();
    }

    srh
}

#[inline(always)]
fn update_tlv_pad(skb: *const __sk_buff, new_pad: u32, old_pad: u32, pad_off: u32) -> i32 {
    if new_pad != old_pad {
        let err = bpf_lwt_seg6_adjust_srh(
            skb as *const c_void,
            pad_off,
            new_pad as i32 - old_pad as i32,
        );
        if err != 0 {
            return err as i32;
        }
    }

    if new_pad > 0 {
        let mut pad_tlv_buf = [0u8; 16];
        pad_tlv_buf[0] = SR6_TLV_PADDING;
        pad_tlv_buf[1] = (new_pad - 2) as u8;

        let err = bpf_lwt_seg6_store_bytes(
            skb as *const c_void,
            pad_off,
            pad_tlv_buf.as_ptr() as *const c_void,
            new_pad,
        );
        if err != 0 {
            return err as i32;
        }
    }

    0
}

#[inline(always)]
fn is_valid_tlv_boundary(
    skb: *const __sk_buff,
    srh: *const Ip6SrhT,
    tlv_off: &mut u32,
    pad_size: &mut u32,
    pad_off: &mut u32,
) -> i32 {
    let data = vload!((*skb).data) as usize;
    let srh_off = (srh as usize - data) as u32;
    let hdrlen = unsafe { (*srh).hdrlen };
    let first_segment = unsafe { (*srh).first_segment };

    let mut cur_off = srh_off
        + core::mem::size_of::<Ip6SrhT>() as u32
        + core::mem::size_of::<Ip6AddrT>() as u32 * (first_segment as u32 + 1);

    let mut offset_valid = false;
    *pad_off = 0;

    // C: `for (long i = 0; i < 100; i++)` under __pragma_loop_no_unroll --
    // this is the scale test's namesake loop (~10x test_lwt_seg6local's
    // bound), stressing the bounded-loop verifier path rather than being
    // executed against real packets.
    let mut i = 0u32;
    while i < 100 {
        if cur_off == *tlv_off {
            offset_valid = true;
        }

        if cur_off >= srh_off + ((hdrlen as u32 + 1) << 3) {
            break;
        }

        let mut tlv: Sr6TlvT = unsafe { core::mem::zeroed() };
        let err = bpf_skb_load_bytes(
            skb as *const c_void,
            cur_off,
            &mut tlv as *mut Sr6TlvT as *mut c_void,
            core::mem::size_of::<Sr6TlvT>() as u32,
        );
        if err != 0 {
            return err as i32;
        }

        if tlv.r#type == SR6_TLV_PADDING {
            *pad_size = tlv.len as u32 + core::mem::size_of::<Sr6TlvT>() as u32;
            *pad_off = cur_off;

            if *tlv_off == srh_off {
                *tlv_off = cur_off;
                offset_valid = true;
            }
            break;
        } else if tlv.r#type == SR6_TLV_HMAC {
            break;
        }

        cur_off += core::mem::size_of::<Sr6TlvT>() as u32 + tlv.len as u32;
        i += 1;
    }

    if *pad_off == 0 {
        *pad_off = cur_off;
    }

    if *tlv_off == u32::MAX {
        *tlv_off = cur_off;
    } else if !offset_valid {
        return -EINVAL;
    }

    0
}

#[inline(always)]
fn add_tlv(
    skb: *const __sk_buff,
    srh: *const Ip6SrhT,
    tlv_off_in: u32,
    itlv: *const Sr6TlvT,
    tlv_size: u8,
) -> i32 {
    let data = vload!((*skb).data) as usize;
    let srh_off = (srh as usize - data) as u32;

    let mut tlv_off = tlv_off_in;
    let mut pad_off: u32 = 0;
    let mut pad_size: u32 = 0;

    if tlv_off != u32::MAX {
        tlv_off += srh_off;
    }

    let itlv_type = unsafe { (*itlv).r#type };
    let itlv_len = unsafe { (*itlv).len };

    if itlv_type == SR6_TLV_PADDING || itlv_type == SR6_TLV_HMAC {
        return -EINVAL;
    }

    let err = is_valid_tlv_boundary(skb, srh, &mut tlv_off, &mut pad_size, &mut pad_off);
    if err != 0 {
        return err;
    }

    let err = bpf_lwt_seg6_adjust_srh(
        skb as *const c_void,
        tlv_off,
        core::mem::size_of::<Sr6TlvT>() as i32 + itlv_len as i32,
    );
    if err != 0 {
        return err as i32;
    }

    let err = bpf_lwt_seg6_store_bytes(
        skb as *const c_void,
        tlv_off,
        itlv as *const c_void,
        tlv_size as u32,
    );
    if err != 0 {
        return err as i32;
    }

    // the following can't be moved inside update_tlv_pad because the bpf
    // verifier has some issues with it
    pad_off = pad_off
        .wrapping_add(core::mem::size_of::<Sr6TlvT>() as u32)
        .wrapping_add(itlv_len as u32);
    let partial_srh_len = pad_off.wrapping_sub(srh_off);
    let len_remaining = (partial_srh_len % 8) as u8;
    let mut new_pad = 8u8 - len_remaining;

    if new_pad == 1 {
        new_pad = 9;
    } else if new_pad == 8 {
        new_pad = 0;
    }

    update_tlv_pad(skb, new_pad as u32, pad_size, pad_off)
}

// Add an Egress TLV fc00::4, add the flag A,
// and apply End.X action to fc42::1
#[link_section = "lwt_seg6local"]
#[no_mangle]
extern "C" fn __add_egr_x(skb: *const __sk_buff) -> i32 {
    let hi: u64 = 0xfc42000000000000;
    let lo: u64 = 0x1;

    let srh = get_srh(skb);
    if srh.is_null() {
        return BPF_DROP;
    }

    let new_flags: u8 = SR6_FLAG_ALERT;

    let tlv: [u8; 20] = [
        2, 18, 0, 0, 0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x4,
    ];

    let hdrlen = unsafe { (*srh).hdrlen };
    let err = add_tlv(
        skb,
        srh,
        (hdrlen as u32 + 1) << 3,
        tlv.as_ptr() as *const Sr6TlvT,
        20,
    );
    if err != 0 {
        return BPF_DROP;
    }

    let offset = core::mem::size_of::<Ip6Hdr>() as u32 + IP6_SRH_FLAGS_OFFSET;
    let err = bpf_lwt_seg6_store_bytes(
        skb as *const c_void,
        offset,
        &new_flags as *const u8 as *const c_void,
        1,
    );
    if err != 0 {
        return BPF_DROP;
    }

    let mut addr: Ip6AddrT = unsafe { core::mem::zeroed() };
    addr.lo = cpu_to_be64(lo);
    addr.hi = cpu_to_be64(hi);

    let err = bpf_lwt_seg6_action(
        skb as *const c_void,
        SEG6_LOCAL_ACTION_END_X,
        &addr as *const Ip6AddrT as *mut c_void,
        core::mem::size_of::<Ip6AddrT>() as u32,
    );
    if err != 0 {
        return BPF_DROP;
    }

    BPF_REDIRECT
}

bpf_object!("GPL");
