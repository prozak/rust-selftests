#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tc_link.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_probe_read_kernel, bpf_skb_change_type, bpf_skb_load_bytes, bpf_skb_store_bytes,
};
use bpf_rs_core::{bpf_object, vload};
use btf_macros::btf;

const TCX_NEXT: i32 = -1;
const TCX_PASS: i32 = 0;

const ETH_P_IP: u16 = 0x0800;

const PACKET_HOST: u32 = 0;
const PACKET_MULTICAST: u32 = 2;

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

// struct ethhdr (linux/if_ether.h) — packed, matches the kernel layout used
// by bpf_skb_load_bytes/bpf_skb_store_bytes below.
#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// Minimal local CO-RE views of the kernel's real `struct sk_buff` /
// `struct net_device`, matching the C source's own local re-declaration
// (only the fields tc8 needs; matched against target BTF by name).
#[btf]
struct sk_buff {
    dev: *mut net_device,
}

#[btf]
struct net_device {
    needed_headroom: u16,
    needed_tailroom: u16,
}

#[no_mangle]
static mut seen_tc1: bool = false;
#[no_mangle]
static mut seen_tc2: bool = false;
#[no_mangle]
static mut seen_tc3: bool = false;
#[no_mangle]
static mut seen_tc4: bool = false;
#[no_mangle]
static mut seen_tc5: bool = false;
#[no_mangle]
static mut seen_tc6: bool = false;
#[no_mangle]
static mut seen_tc7: bool = false;
#[no_mangle]
static mut seen_tc8: bool = false;

#[no_mangle]
static mut set_type: bool = false;

#[no_mangle]
static mut seen_eth: bool = false;
#[no_mangle]
static mut seen_host: bool = false;
#[no_mangle]
static mut seen_mcast: bool = false;

#[no_mangle]
static mut mark: i32 = 0;
#[no_mangle]
static mut prio: i32 = 0;
#[no_mangle]
static mut headroom: u16 = 0;
#[no_mangle]
static mut tailroom: u16 = 0;

#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tc1(skb: *const __sk_buff) -> i32 {
    let mut eth = ethhdr {
        h_dest: [0; 6],
        h_source: [0; 6],
        h_proto: 0,
    };

    if vload!((*skb).protocol) == htons(ETH_P_IP) as u32
        && bpf_skb_load_bytes(
            skb as *const c_void,
            0,
            &mut eth as *mut ethhdr as *mut c_void,
            core::mem::size_of::<ethhdr>() as u32,
        ) == 0
    {
        let host = vload!((*skb).pkt_type) == PACKET_HOST;
        unsafe {
            seen_eth = eth.h_proto == htons(ETH_P_IP);
            seen_host = host;
        }
        if host && unsafe { set_type } {
            eth.h_dest[0] = 4;
            if bpf_skb_store_bytes(
                skb as *const c_void,
                0,
                &eth as *const ethhdr as *const c_void,
                core::mem::size_of::<ethhdr>() as u32,
                0,
            ) != 0
            {
                return TCX_NEXT;
            }
            bpf_skb_change_type(skb as *const c_void, PACKET_MULTICAST);
        }
    }
    unsafe { seen_tc1 = true };
    TCX_NEXT
}

#[link_section = "tc/egress"]
#[no_mangle]
extern "C" fn tc2(_skb: *const __sk_buff) -> i32 {
    unsafe { seen_tc2 = true };
    TCX_NEXT
}

#[link_section = "tc/egress"]
#[no_mangle]
extern "C" fn tc3(_skb: *const __sk_buff) -> i32 {
    unsafe { seen_tc3 = true };
    TCX_NEXT
}

#[link_section = "tc/egress"]
#[no_mangle]
extern "C" fn tc4(_skb: *const __sk_buff) -> i32 {
    unsafe { seen_tc4 = true };
    TCX_NEXT
}

#[link_section = "tc/egress"]
#[no_mangle]
extern "C" fn tc5(_skb: *const __sk_buff) -> i32 {
    unsafe { seen_tc5 = true };
    TCX_PASS
}

#[link_section = "tc/egress"]
#[no_mangle]
extern "C" fn tc6(_skb: *const __sk_buff) -> i32 {
    unsafe { seen_tc6 = true };
    TCX_PASS
}

#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tc7(skb: *const __sk_buff) -> i32 {
    let mut eth = ethhdr {
        h_dest: [0; 6],
        h_source: [0; 6],
        h_proto: 0,
    };

    if vload!((*skb).protocol) == htons(ETH_P_IP) as u32
        && bpf_skb_load_bytes(
            skb as *const c_void,
            0,
            &mut eth as *mut ethhdr as *mut c_void,
            core::mem::size_of::<ethhdr>() as u32,
        ) == 0
        && eth.h_dest[0] == 4
        && unsafe { set_type }
    {
        unsafe { seen_mcast = vload!((*skb).pkt_type) == PACKET_MULTICAST };
        bpf_skb_change_type(skb as *const c_void, PACKET_HOST);
    }
    unsafe { seen_tc7 = true };
    TCX_PASS
}

#[link_section = "tc/egress"]
#[no_mangle]
extern "C" fn tc8(skb: *const __sk_buff) -> i32 {
    let sk = skb as *const sk_buff;
    let mut dev: *mut net_device = core::ptr::null_mut();
    bpf_probe_read_kernel(
        &mut dev,
        core::mem::size_of::<*mut net_device>() as u32,
        unsafe { &*sk }.dev().as_ptr() as *const c_void,
    );

    unsafe { seen_tc8 = true };
    unsafe {
        mark = vload!((*skb).mark) as i32;
        prio = vload!((*skb).priority) as i32;
    }

    let ndev = dev as *const net_device;
    let mut hr: u16 = 0;
    let mut tr: u16 = 0;
    bpf_probe_read_kernel(
        &mut hr,
        core::mem::size_of::<u16>() as u32,
        unsafe { &*ndev }.needed_headroom().as_ptr() as *const c_void,
    );
    bpf_probe_read_kernel(
        &mut tr,
        core::mem::size_of::<u16>() as u32,
        unsafe { &*ndev }.needed_tailroom().as_ptr() as *const c_void,
    );
    unsafe {
        headroom = hr;
        tailroom = tr;
    }

    TCX_PASS
}

// The C source names its license global `LICENSE` (not the crate macro's
// default `_license`); the internalize keep-list is derived from the C
// object's global symbol names, so without a matching symbol here the
// license section is silently DCE'd away and every GPL-only helper call
// (bpf_probe_read_kernel in tc8) is rejected as non-GPL.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
