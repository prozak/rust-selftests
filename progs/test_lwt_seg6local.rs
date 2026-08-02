#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_lwt_seg6local.c
// (bpf-rs-core idiom).
//
// All packet parsing/mutation goes through `skb->data`/`data_end` direct
// packet access (bound-checked raw pointer derefs into packed structs, same
// as the C source's cursor_advance idiom) and the bpf_lwt_seg6_* / bpf_skb_*
// helpers — never through the map/global machinery.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_lwt_push_encap, bpf_lwt_seg6_action, bpf_lwt_seg6_adjust_srh, bpf_lwt_seg6_store_bytes,
    bpf_skb_load_bytes,
};
use bpf_rs_core::vload;

const BPF_OK: i32 = 0;
const BPF_DROP: i32 = 2;
const BPF_REDIRECT: i32 = 7;

const SEG6_LOCAL_ACTION_END_X: u32 = 2;
const SEG6_LOCAL_ACTION_END_T: u32 = 3;

const SR6_TLV_EGRESS: u8 = 2;
const SR6_TLV_PADDING: u8 = 4;
const SR6_TLV_HMAC: u8 = 5;

const SR6_FLAG_ALERT: u8 = 1 << 4;

const EINVAL: i32 = 22;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

#[inline(always)]
fn cpu_to_be64(x: u64) -> u64 {
    x.to_be()
}

#[inline(always)]
fn be64_to_cpu(x: u64) -> u64 {
    u64::from_be(x)
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
    tag: u16,
}

const IP6_SRH_FLAGS_OFFSET: u32 = 5;
const IP6_SRH_TAG_OFFSET: u32 = 6;

// struct sr6_tlv_t (packed), 2-byte fixed header.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Sr6TlvT {
    r#type: u8,
    len: u8,
}

// srh_buf layout for `encap_srh`: fixed SRH header + 4 fd00::N segments,
// 72 bytes total (8 + 4*16), same as the C stack buffer.
#[repr(C, packed)]
struct EncapSrhBuf {
    srh: Ip6SrhT,
    segments: [Ip6AddrT; 4],
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

    // C uses #pragma unroll for a max-10-TLV walk (BPF stack limit); a
    // plain bounded loop verifies the same way under the kernel's bounded-
    // loop support.
    let mut i = 0u32;
    while i < 10 {
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

#[inline(always)]
fn delete_tlv(skb: *const __sk_buff, srh: *const Ip6SrhT, tlv_off_in: u32) -> i32 {
    let data = vload!((*skb).data) as usize;
    let srh_off = (srh as usize - data) as u32;

    let mut tlv_off = tlv_off_in + srh_off;
    let mut pad_off: u32 = 0;
    let mut pad_size: u32 = 0;

    let err = is_valid_tlv_boundary(skb, srh, &mut tlv_off, &mut pad_size, &mut pad_off);
    if err != 0 {
        return err;
    }

    let mut tlv: Sr6TlvT = unsafe { core::mem::zeroed() };
    let err = bpf_skb_load_bytes(
        skb as *const c_void,
        tlv_off,
        &mut tlv as *mut Sr6TlvT as *mut c_void,
        core::mem::size_of::<Sr6TlvT>() as u32,
    );
    if err != 0 {
        return err as i32;
    }

    let err = bpf_lwt_seg6_adjust_srh(
        skb as *const c_void,
        tlv_off,
        -(core::mem::size_of::<Sr6TlvT>() as i32 + tlv.len as i32),
    );
    if err != 0 {
        return err as i32;
    }

    pad_off = pad_off.wrapping_sub(core::mem::size_of::<Sr6TlvT>() as u32 + tlv.len as u32);
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

#[inline(always)]
fn has_egr_tlv(skb: *const __sk_buff, srh: *const Ip6SrhT) -> i32 {
    let first_segment = unsafe { (*srh).first_segment };
    let tlv_offset = core::mem::size_of::<Ip6Hdr>() as u32
        + core::mem::size_of::<Ip6SrhT>() as u32
        + ((first_segment as u32 + 1) << 4);

    let mut tlv: Sr6TlvT = unsafe { core::mem::zeroed() };
    let err = bpf_skb_load_bytes(
        skb as *const c_void,
        tlv_offset,
        &mut tlv as *mut Sr6TlvT as *mut c_void,
        core::mem::size_of::<Sr6TlvT>() as u32,
    );
    if err != 0 {
        return 0;
    }

    if tlv.r#type == SR6_TLV_EGRESS && tlv.len == 18 {
        let mut egr_addr: Ip6AddrT = unsafe { core::mem::zeroed() };
        let err = bpf_skb_load_bytes(
            skb as *const c_void,
            tlv_offset + 4,
            &mut egr_addr as *mut Ip6AddrT as *mut c_void,
            16,
        );
        if err != 0 {
            return 0;
        }

        if be64_to_cpu(egr_addr.hi) == 0xfd00000000000000 && be64_to_cpu(egr_addr.lo) == 0x4 {
            return 1;
        }
    }

    0
}

// This function will push a SRH with segments fd00::1, fd00::2, fd00::3,
// fd00::4
#[link_section = "encap_srh"]
#[no_mangle]
extern "C" fn __encap_srh(skb: *const __sk_buff) -> i32 {
    let hi: u64 = 0xfd00000000000000;
    let mut buf: EncapSrhBuf = unsafe { core::mem::zeroed() };

    buf.srh.nexthdr = 0;
    buf.srh.hdrlen = 8;
    buf.srh.r#type = 4;
    buf.srh.segments_left = 3;
    buf.srh.first_segment = 3;
    buf.srh.flags = 0;
    buf.srh.tag = 0;

    let mut lo: u64 = 0;
    while lo < 4 {
        buf.segments[lo as usize].lo = cpu_to_be64(4 - lo);
        buf.segments[lo as usize].hi = cpu_to_be64(hi);
        lo += 1;
    }

    let err = bpf_lwt_push_encap(
        skb as *const c_void,
        0,
        &buf as *const EncapSrhBuf as *const c_void,
        core::mem::size_of::<EncapSrhBuf>() as u32,
    );
    if err != 0 {
        return BPF_DROP;
    }

    BPF_REDIRECT
}

// Add an Egress TLV fc00::4, add the flag A,
// and apply End.X action to fc42::1
#[link_section = "add_egr_x"]
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

// Pop the Egress TLV, reset the flags, change the tag 2442 and finally do a
// simple End action
#[link_section = "pop_egr"]
#[no_mangle]
extern "C" fn __pop_egr(skb: *const __sk_buff) -> i32 {
    let srh = get_srh(skb);
    if srh.is_null() {
        return BPF_DROP;
    }

    let new_tag: u16 = htons(2442);
    let new_flags: u8 = 0;

    let flags = unsafe { (*srh).flags };
    if flags != SR6_FLAG_ALERT {
        return BPF_DROP;
    }

    let hdrlen = unsafe { (*srh).hdrlen };
    if hdrlen != 11 {
        // 4 segments + Egress TLV + Padding TLV
        return BPF_DROP;
    }

    if has_egr_tlv(skb, srh) == 0 {
        return BPF_DROP;
    }

    let first_segment = unsafe { (*srh).first_segment };
    let err = delete_tlv(skb, srh, 8 + (first_segment as u32 + 1) * 16);
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

    let offset = core::mem::size_of::<Ip6Hdr>() as u32 + IP6_SRH_TAG_OFFSET;
    let err = bpf_lwt_seg6_store_bytes(
        skb as *const c_void,
        offset,
        &new_tag as *const u16 as *const c_void,
        2,
    );
    if err != 0 {
        return BPF_DROP;
    }

    BPF_OK
}

// Inspect if the Egress TLV and flag have been removed, if the tag is
// correct, then apply a End.T action to reach the last segment
#[link_section = "inspect_t"]
#[no_mangle]
extern "C" fn __inspect_t(skb: *const __sk_buff) -> i32 {
    let srh = get_srh(skb);
    if srh.is_null() {
        return BPF_DROP;
    }

    let flags = unsafe { (*srh).flags };
    if flags != 0 {
        return BPF_DROP;
    }

    let tag = unsafe { (*srh).tag };
    if tag != htons(2442) {
        return BPF_DROP;
    }

    let hdrlen = unsafe { (*srh).hdrlen };
    if hdrlen != 8 {
        // 4 segments
        return BPF_DROP;
    }

    let table: i32 = 117;
    let err = bpf_lwt_seg6_action(
        skb as *const c_void,
        SEG6_LOCAL_ACTION_END_T,
        &table as *const i32 as *mut c_void,
        core::mem::size_of::<i32>() as u32,
    );
    if err != 0 {
        return BPF_DROP;
    }

    BPF_REDIRECT
}

bpf_object!("GPL");
