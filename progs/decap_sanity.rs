#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/decap_sanity.c
// (bpf-rs-core idiom). The C original reads `kskb->ip_summed`, a bitfield
// packed into one byte together with pkt_type/ignore_df/dst_pending_confirm
// (include/linux/skbuff.h's `struct_group(headers, ...)`). The #[btf] macro
// only emits a plain FIELD_BYTE_OFFSET relocation (no LSHIFT/RSHIFT bitfield
// relocations); pointing that straight at a bitfield member (`ip_summed:
// u8`) makes libbpf's bpf_core_calc_relo see local size 1 (plain u8) vs.
// target size 0 (unset for bitfields) and poison the load ("accesses field
// incorrectly") - confirmed by a real load failure. Instead, target the
// zero-length marker array `__pkt_type_offset` that sits at the same byte:
// as a same-kind, same-size (0-byte) array on both sides, its byte-offset
// relocation is unambiguous and gives the address of the packed byte
// without ever touching a bitfield relocation. Read that one byte with
// bpf_probe_read_kernel (a helper call, not a raw BTF-checked field load)
// and unpack ip_summed's bits (5:6, LE bitfield order, after pkt_type:3,
// ignore_df:1, dst_pending_confirm:1) by hand - stable for this exact
// kernel tree, which is what this whole harness builds and tests against.

use bpf_rs_core::ctx::{TC_ACT_SHOT, __sk_buff};
use bpf_rs_core::helpers::{bpf_probe_read_kernel, bpf_skb_adjust_room, bpf_skb_load_bytes};
use bpf_rs_core::vload;
use btf_macros::btf;
use core::ffi::c_void;

const ETH_HLEN: u32 = 14;
const ETH_P_IPV6: u16 = 0x86dd;
const IPPROTO_UDP: u8 = 17;
const UDP_TEST_PORT: u16 = 7777;
const BPF_F_ADJ_ROOM_FIXED_GSO: u64 = 1 << 0;

const CHECKSUM_NONE: u8 = 0;
const CHECKSUM_PARTIAL: u8 = 3;

#[repr(C)]
struct ipv6hdr {
    _priority_version: u8,
    _flow_lbl: [u8; 3],
    _payload_len: u16,
    nexthdr: u8,
    _hop_limit: u8,
    _saddr: [u8; 16],
    _daddr: [u8; 16],
}

#[repr(C)]
struct udphdr {
    _source: u16,
    dest: u16,
    _len: u16,
    _check: u16,
}

#[btf]
struct sk_buff {
    len: u32,
    data_len: u32,
    data: *mut u8,
    head: *mut u8,
    csum_start: u16,
    __pkt_type_offset: [u8; 0],
}

extern "C" {
    fn bpf_cast_to_kern_ctx(obj: *const c_void) -> *mut c_void;
}

#[no_mangle]
static mut init_csum_partial: bool = false;
#[no_mangle]
static mut final_csum_none: bool = false;
#[no_mangle]
static mut broken_csum_start: bool = false;

#[inline(always)]
fn read_ip_summed(kskb: &sk_buff) -> u8 {
    let field_ptr = kskb.__pkt_type_offset().as_ptr() as *const c_void;
    let mut byte: u8 = 0;
    bpf_probe_read_kernel(&mut byte, 1, field_ptr);
    (byte >> 5) & 0x3
}

#[inline(always)]
fn skb_headlen(kskb: &sk_buff) -> u32 {
    let len = unsafe { *kskb.len().as_ptr() };
    let data_len = unsafe { *kskb.data_len().as_ptr() };
    len.wrapping_sub(data_len)
}

#[inline(always)]
fn skb_headroom(kskb: &sk_buff) -> u32 {
    let data = unsafe { *kskb.data().as_ptr() } as u64;
    let head = unsafe { *kskb.head().as_ptr() } as u64;
    data.wrapping_sub(head) as u32
}

#[inline(always)]
fn skb_checksum_start_offset(kskb: &sk_buff) -> u32 {
    let csum_start = unsafe { *kskb.csum_start().as_ptr() };
    (csum_start as u32).wrapping_sub(skb_headroom(kskb))
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn decap_sanity(skb: *const __sk_buff) -> i32 {
    let protocol = vload!((*skb).protocol);
    if protocol != ETH_P_IPV6.to_be() as u32 {
        return TC_ACT_SHOT;
    }

    let mut ip6h = core::mem::MaybeUninit::<ipv6hdr>::uninit();
    let ret = bpf_skb_load_bytes(
        skb as *const c_void,
        ETH_HLEN,
        ip6h.as_mut_ptr() as *mut c_void,
        core::mem::size_of::<ipv6hdr>() as u32,
    );
    if ret != 0 {
        return TC_ACT_SHOT;
    }
    let ip6h = unsafe { ip6h.assume_init() };

    if ip6h.nexthdr != IPPROTO_UDP {
        return TC_ACT_SHOT;
    }

    let mut udph = core::mem::MaybeUninit::<udphdr>::uninit();
    let ret = bpf_skb_load_bytes(
        skb as *const c_void,
        ETH_HLEN + core::mem::size_of::<ipv6hdr>() as u32,
        udph.as_mut_ptr() as *mut c_void,
        core::mem::size_of::<udphdr>() as u32,
    );
    if ret != 0 {
        return TC_ACT_SHOT;
    }
    let udph = unsafe { udph.assume_init() };

    if udph.dest != UDP_TEST_PORT.to_be() {
        return TC_ACT_SHOT;
    }

    let kskb = unsafe { bpf_cast_to_kern_ctx(skb as *const c_void) } as *const sk_buff;
    let kskb_ref = unsafe { &*kskb };

    unsafe { init_csum_partial = read_ip_summed(kskb_ref) == CHECKSUM_PARTIAL };

    let adjust_len = -((ETH_HLEN + core::mem::size_of::<ipv6hdr>() as u32
        + core::mem::size_of::<udphdr>() as u32) as i32);
    let err = bpf_skb_adjust_room(
        skb as *const c_void,
        adjust_len,
        1,
        BPF_F_ADJ_ROOM_FIXED_GSO,
    );
    if err != 0 {
        return TC_ACT_SHOT;
    }

    let ip_summed = read_ip_summed(kskb_ref);
    unsafe { final_csum_none = ip_summed == CHECKSUM_NONE };
    if ip_summed == CHECKSUM_PARTIAL && skb_checksum_start_offset(kskb_ref) >= skb_headlen(kskb_ref)
    {
        unsafe { broken_csum_start = true };
    }

    TC_ACT_SHOT
}

// bpf_object!("GPL") emits a static named `_license`, but this C source
// declares its license global as `__license` (matched against `bld/*.keep`
// derived from the pristine clang object's global symbols) - hand-write it
// under the C-correct name so a fresh `.corig` capture doesn't internalize
// it away and break the bpf_cast_to_kern_ctx GPL-only kfunc call. See
// bpf_object-macro-license-symbol-mismatch in project memory.
#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
