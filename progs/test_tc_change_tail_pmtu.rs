// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_tc_change_tail_pmtu.c (bpf-rs-core
// idiom). On the client's egress the program turns the first TCP data
// segment to the server port into an ICMP "fragmentation needed" message
// carrying the configured PMTU and the first 28 bytes of the original
// packet, and redirects it back to the ingress of the same device;
// prog_tests/tc_change_tail_pmtu.c sets server_port and pmtu, checks the
// helper results and that the client's MSS dropped. The headers are read
// and written through packet pointers with the C's offsets and widths.

use core::ffi::c_void;
use core::ptr::{read_unaligned, write_unaligned};

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_csum_diff, bpf_redirect, bpf_skb_adjust_room, bpf_skb_change_tail};
use bpf_rs_core::{bpf_object, vload};

const TCX_PASS: i32 = 0;
const TCX_DROP: i32 = 2;

const ETH_HLEN: u32 = 14;
const ETH_P_IP_BE: u16 = 0x0008; // bpf_htons(ETH_P_IP)
const IPPROTO_TCP: u8 = 6;
const IPPROTO_ICMP: u8 = 1;
const ICMP_DEST_UNREACH: u8 = 3;
const ICMP_FRAG_NEEDED: u8 = 4;

const BPF_ADJ_ROOM_MAC: u32 = 1;
const BPF_F_ADJ_ROOM_NO_CSUM_RESET: u64 = 1 << 5;
const BPF_F_INGRESS: u64 = 1;

const IPHDR_LEN: u32 = 20;
const ICMPHDR_LEN: u32 = 8;
const ICMP_SAMPLE_LEN: u32 = IPHDR_LEN + 8;
const ICMP_HDRS_LEN: u32 = IPHDR_LEN + ICMPHDR_LEN;

#[no_mangle]
static mut server_port: u16 = 0; // __be16
#[no_mangle]
static mut pmtu: u16 = 0;

#[no_mangle]
static mut change_tail_ret: i64 = 1;
#[no_mangle]
static mut adjust_room_ret: i64 = 0;
// C bools, branched on: u8 with the C object's byte compares
#[no_mangle]
static mut icmp_sent: u8 = 0;
#[no_mangle]
static mut icmp_err: u8 = 0;

#[inline(always)]
fn htons(v: u16) -> u16 {
    v.swap_bytes()
}

#[inline(always)]
fn csum_fold(csum: u32) -> u16 {
    let csum = (csum & 0xffff) + (csum >> 16);
    let csum = (csum & 0xffff) + (csum >> 16);

    !csum as u16
}

#[link_section = "tc/egress"]
#[no_mangle]
extern "C" fn change_tail_icmp(skb: *mut __sk_buff) -> i32 {
    unsafe {
        if icmp_sent != 0 || (icmp_err & 1) != 0 {
            return TCX_PASS;
        }

        let data = vload!((*skb).data) as u64 as *mut u8;
        let data_end = vload!((*skb).data_end) as u64 as *mut u8;

        let eth = data;
        if eth.add(14) > data_end {
            return TCX_PASS;
        }
        if read_unaligned(eth.add(12) as *const u16) != ETH_P_IP_BE {
            return TCX_PASS;
        }

        let ip = eth.add(14);
        if ip.add(20) > data_end {
            return TCX_PASS;
        }
        // ip->ihl is the low nibble of the first byte
        if (*ip & 0xf) != 5 || *ip.add(9) != IPPROTO_TCP {
            return TCX_PASS;
        }

        let tcp = ip.add(20);
        if tcp.add(20) > data_end {
            return TCX_PASS;
        }
        if read_unaligned(tcp.add(2) as *const u16) != server_port {
            return TCX_PASS;
        }
        // tcp->doff is the high nibble of byte 12
        let doff = (*tcp.add(12) >> 4) as u32;
        if (htons(read_unaligned(ip.add(2) as *const u16)) as u32) <= IPHDR_LEN + doff * 4 {
            return TCX_PASS;
        }

        // __builtin_memcpy(smac, eth->h_source, ETH_ALEN) and the same for
        // dmac, as a u32 + u16 pair each: an array copy would become a
        // bpf_arena_memcpy kfunc call the C object does not make
        let smac_lo = read_unaligned(eth.add(6) as *const u32);
        let smac_hi = read_unaligned(eth.add(10) as *const u16);
        let dmac_lo = read_unaligned(eth as *const u32);
        let dmac_hi = read_unaligned(eth.add(4) as *const u16);
        let saddr = read_unaligned(ip.add(12) as *const u32);
        let daddr = read_unaligned(ip.add(16) as *const u32);

        change_tail_ret = bpf_skb_change_tail(skb as *const c_void, ETH_HLEN + ICMP_SAMPLE_LEN, 0);
        if change_tail_ret != 0 {
            icmp_err = 1;
            return TCX_PASS;
        }

        adjust_room_ret = bpf_skb_adjust_room(
            skb as *const c_void,
            ICMP_HDRS_LEN as i32,
            BPF_ADJ_ROOM_MAC,
            BPF_F_ADJ_ROOM_NO_CSUM_RESET,
        );
        if adjust_room_ret != 0 {
            icmp_err = 1;
            return TCX_DROP;
        }

        let data = vload!((*skb).data) as u64 as *mut u8;
        let data_end = vload!((*skb).data_end) as u64 as *mut u8;

        let eth = data;
        let ip = eth.add(14);
        let icmp = ip.add(20);
        if icmp.add((ICMPHDR_LEN + ICMP_SAMPLE_LEN) as usize) > data_end {
            icmp_err = 1;
            return TCX_DROP;
        }

        write_unaligned(eth as *mut u32, smac_lo);
        write_unaligned(eth.add(4) as *mut u16, smac_hi);
        write_unaligned(eth.add(6) as *mut u32, dmac_lo);
        write_unaligned(eth.add(10) as *mut u16, dmac_hi);

        // struct icmphdr: type, code, checksum, un.frag { __unused, mtu }
        write_unaligned(icmp as *mut u64, 0);
        *icmp = ICMP_DEST_UNREACH;
        *icmp.add(1) = ICMP_FRAG_NEEDED;
        write_unaligned(icmp.add(6) as *mut u16, htons(pmtu));

        // struct iphdr: version/ihl, tos, tot_len, id, frag_off, ttl, protocol,
        // check, saddr, daddr
        write_unaligned(ip as *mut u64, 0);
        write_unaligned(ip.add(8) as *mut u64, 0);
        write_unaligned(ip.add(16) as *mut u32, 0);
        *ip = (4 << 4) | 5;
        *ip.add(8) = 64;
        *ip.add(9) = IPPROTO_ICMP;
        write_unaligned(ip.add(2) as *mut u16, htons((ICMP_HDRS_LEN + ICMP_SAMPLE_LEN) as u16));
        write_unaligned(ip.add(12) as *mut u32, daddr);
        write_unaligned(ip.add(16) as *mut u32, saddr);

        let csum = bpf_csum_diff(
            core::ptr::null(),
            0,
            icmp as *const c_void,
            ICMPHDR_LEN + ICMP_SAMPLE_LEN,
            0,
        ) as u32;
        write_unaligned(icmp.add(2) as *mut u16, csum_fold(csum));
        let csum = bpf_csum_diff(core::ptr::null(), 0, ip as *const c_void, IPHDR_LEN, 0) as u32;
        write_unaligned(ip.add(10) as *mut u16, csum_fold(csum));
        icmp_sent = 1;
        bpf_redirect(vload!((*skb).ifindex), BPF_F_INGRESS) as i32
    }
}

bpf_object!("GPL");
