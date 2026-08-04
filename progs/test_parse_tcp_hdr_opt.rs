#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_parse_tcp_hdr_opt.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::vload;

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

const TCPOPT_EOL: u8 = 0;
const TCPOPT_NOP: u8 = 1;

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

// struct ethhdr (linux/if_ether.h) / struct ipv6hdr (linux/ipv6.h) — only
// used for their packed on-wire size, fields are never read.
#[allow(dead_code)]
#[repr(C, packed)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[allow(dead_code)]
#[repr(C, packed)]
struct Ipv6Hdr {
    version_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

const TCP_OFFSET: usize = core::mem::size_of::<EthHdr>() + core::mem::size_of::<Ipv6Hdr>();
// sizeof(struct tcphdr): only the doff nibble (byte 12, high 4 bits) is read.
const TCPHDR_LEN: usize = 20;

/* Kind number used for experiments */
#[link_section = ".rodata"]
#[no_mangle]
static tcp_hdr_opt_kind_tpr: u32 = 0xFD;
/* Length of the tcp header option */
#[link_section = ".rodata"]
#[no_mangle]
static tcp_hdr_opt_len_tpr: u32 = 6;
/* maximum number of header options to check to lookup server_id */
#[link_section = ".rodata"]
#[no_mangle]
static tcp_hdr_opt_max_opt_checks: u32 = 15;

#[no_mangle]
static mut server_id: u32 = 0;

struct HdrOptState {
    server_id: u32,
    byte_offset: u8,
    hdr_bytes_remaining: u8,
}

#[inline(never)]
fn parse_hdr_opt(data: usize, data_end: usize, state: &mut HdrOptState) -> i32 {
    let tcp_opt = data + state.byte_offset as usize;
    if tcp_opt + 1 > data_end {
        return -1;
    }

    let kind = unsafe { *(tcp_opt as *const u8) };

    if kind == TCPOPT_EOL {
        return -1;
    }

    if kind == TCPOPT_NOP {
        state.hdr_bytes_remaining = state.hdr_bytes_remaining.wrapping_sub(1);
        state.byte_offset = state.byte_offset.wrapping_add(1);
        return 0;
    }

    if state.hdr_bytes_remaining < 2 || tcp_opt + 2 > data_end {
        return -1;
    }

    let hdr_len = unsafe { *((tcp_opt + 1) as *const u8) };
    if hdr_len > state.hdr_bytes_remaining {
        return -1;
    }

    let kind_tpr = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(tcp_hdr_opt_kind_tpr)) };
    if kind as u32 == kind_tpr {
        let len_tpr =
            unsafe { core::ptr::read_volatile(core::ptr::addr_of!(tcp_hdr_opt_len_tpr)) };
        if hdr_len as u32 != len_tpr {
            return -1;
        }

        if tcp_opt + len_tpr as usize > data_end {
            return -1;
        }

        state.server_id = unsafe { core::ptr::read_unaligned((tcp_opt + 2) as *const u32) };
        return 1;
    }

    state.hdr_bytes_remaining = state.hdr_bytes_remaining.wrapping_sub(hdr_len);
    state.byte_offset = state.byte_offset.wrapping_add(hdr_len);
    0
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_ingress_v6(xdp: *const xdp_md) -> i32 {
    let data = vload!((*xdp).data) as usize;
    let data_end = vload!((*xdp).data_end) as usize;

    if data + TCP_OFFSET + TCPHDR_LEN > data_end {
        return XDP_DROP;
    }

    let doff_byte = unsafe { *((data + TCP_OFFSET + 12) as *const u8) };
    let doff = doff_byte >> 4;
    let tcp_hdr_opt_len = doff.wrapping_mul(4).wrapping_sub(TCPHDR_LEN as u8);

    let len_tpr = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(tcp_hdr_opt_len_tpr)) };
    if (tcp_hdr_opt_len as u32) < len_tpr {
        return XDP_DROP;
    }

    let mut opt_state = HdrOptState {
        server_id: 0,
        byte_offset: (TCPHDR_LEN + TCP_OFFSET) as u8,
        hdr_bytes_remaining: tcp_hdr_opt_len,
    };

    let max_checks =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(tcp_hdr_opt_max_opt_checks)) };

    // max number of bytes of options in tcp header is 40 bytes
    let mut i: u32 = 0;
    while i < max_checks {
        let err = parse_hdr_opt(data, data_end, &mut opt_state);

        if err != 0 || opt_state.hdr_bytes_remaining == 0 {
            break;
        }
        i += 1;
    }

    if opt_state.server_id == 0 {
        return XDP_DROP;
    }

    unsafe { server_id = opt_state.server_id };

    XDP_PASS
}

bpf_object!("GPL");
