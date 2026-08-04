#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/icmp_send.c
// (bpf-rs-core idiom).

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, sync_fetch_and_add_u32};
use bpf_rs_core::vload;

/* 127.0.0.1 in host byte order */
const SERVER_IP: u32 = 0x7F000001;
/* ::1 in host byte order (last 32-bit word) */
const SERVER_IP6_LO: u32 = 0x00000001;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;

const SK_DROP: i32 = 0;
const SK_PASS: i32 = 1;

#[no_mangle]
static mut server_port: u16 = 0;
#[no_mangle]
static mut unreach_type: i32 = 0;
#[no_mangle]
static mut unreach_code: i32 = 0;
#[no_mangle]
static mut kfunc_ret: i32 = -1;
#[no_mangle]
static mut target_pid: i32 = -1;

#[no_mangle]
static mut rec_count: u32 = 0;
#[no_mangle]
static mut rec_kfunc_rets: [i32; 2] = [-1, -1];

// struct iphdr (linux/ip.h): ihl/version packed into the first byte on
// little-endian; the rest is kept as raw fields for the correct struct
// size (this is what C's `iph + 1` pointer arithmetic steps by).
#[repr(C)]
struct IpHdr {
    ihl_version: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

// struct ipv6hdr (linux/ipv6.h): daddr kept as the in6_u.u6_addr32 view,
// the only one the C source reads.
#[repr(C)]
struct Ipv6Hdr {
    version_priority: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u32; 4],
    daddr: [u32; 4],
}

// struct tcphdr (linux/tcp.h): only `dest` is read; the rest is kept as
// raw fields for the correct struct size.
#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    flags: u16,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

// struct icmphdr (linux/icmp.h): only type/code are read; `un` is kept as
// a raw 4-byte field for the correct struct size.
#[repr(C)]
struct IcmpHdr {
    type_: u8,
    code: u8,
    checksum: u16,
    un: u32,
}

extern "C" {
    fn bpf_icmp_send(skb_ctx: *mut __sk_buff, type_: i32, code: i32) -> i32;
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn egress(skb: *mut __sk_buff) -> i32 {
    let data = vload!((*skb).data) as usize as *const u8;
    let data_end = vload!((*skb).data_end) as usize as *const u8;

    if unsafe { data.add(1) } > data_end {
        return SK_PASS;
    }

    let version = unsafe { *data } >> 4;

    if version == 4 {
        if unsafe { data.add(core::mem::size_of::<IpHdr>()) } > data_end {
            return SK_PASS;
        }
        let iph = data as *const IpHdr;
        let ihl_version = unsafe { (*iph).ihl_version };
        let protocol = unsafe { (*iph).protocol };
        let daddr = unsafe { (*iph).daddr };
        if protocol != IPPROTO_TCP || daddr != SERVER_IP.to_be() {
            return SK_PASS;
        }

        let ihl = (ihl_version & 0xF) as usize;
        let tcph_addr = unsafe { data.add(ihl * 4) };
        if unsafe { tcph_addr.add(core::mem::size_of::<TcpHdr>()) } > data_end {
            return SK_PASS;
        }
        let tcph = tcph_addr as *const TcpHdr;
        let dest = unsafe { (*tcph).dest };
        let port = unsafe { server_port };
        if dest != port.to_be() {
            return SK_PASS;
        }
    } else if version == 6 {
        if unsafe { data.add(core::mem::size_of::<Ipv6Hdr>()) } > data_end {
            return SK_PASS;
        }
        let ip6h = data as *const Ipv6Hdr;
        let nexthdr = unsafe { (*ip6h).nexthdr };
        let daddr = unsafe { (*ip6h).daddr };
        if nexthdr != IPPROTO_TCP {
            return SK_PASS;
        }
        if daddr[0] != 0 || daddr[1] != 0 || daddr[2] != 0 || daddr[3] != SERVER_IP6_LO.to_be() {
            return SK_PASS;
        }

        let tcph_addr = unsafe { data.add(core::mem::size_of::<Ipv6Hdr>()) };
        if unsafe { tcph_addr.add(core::mem::size_of::<TcpHdr>()) } > data_end {
            return SK_PASS;
        }
        let tcph = tcph_addr as *const TcpHdr;
        let dest = unsafe { (*tcph).dest };
        let port = unsafe { server_port };
        if dest != port.to_be() {
            return SK_PASS;
        }
    } else {
        return SK_PASS;
    }

    let ret = unsafe {
        bpf_icmp_send(
            skb,
            unreach_type,
            unreach_code,
        )
    };
    unsafe { kfunc_ret = ret };

    SK_DROP
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn recursion(skb: *mut __sk_buff) -> i32 {
    let data = vload!((*skb).data) as usize as *const u8;
    let data_end = vload!((*skb).data_end) as usize as *const u8;

    if unsafe { target_pid } as u64 != (bpf_get_current_pid_tgid() >> 32) {
        return SK_PASS;
    }

    if unsafe { data.add(core::mem::size_of::<IpHdr>()) } > data_end {
        return SK_PASS;
    }
    let iph = data as *const IpHdr;
    let ihl_version = unsafe { (*iph).ihl_version };
    let version = ihl_version >> 4;
    if version != 4 {
        return SK_PASS;
    }

    let daddr = unsafe { (*iph).daddr };
    if daddr != SERVER_IP.to_be() {
        return SK_PASS;
    }

    let protocol = unsafe { (*iph).protocol };
    let ihl = (ihl_version & 0xF) as usize;
    let hdr_addr = unsafe { data.add(ihl * 4) };

    if protocol == IPPROTO_TCP {
        if unsafe { hdr_addr.add(core::mem::size_of::<TcpHdr>()) } > data_end {
            return SK_PASS;
        }
        let tcph = hdr_addr as *const TcpHdr;
        let dest = unsafe { (*tcph).dest };
        let port = unsafe { server_port };
        if dest != port.to_be() {
            return SK_PASS;
        }
    } else if protocol == IPPROTO_ICMP {
        if unsafe { hdr_addr.add(core::mem::size_of::<IcmpHdr>()) } > data_end {
            return SK_PASS;
        }
        let icmph = hdr_addr as *const IcmpHdr;
        let icmp_type = unsafe { (*icmph).type_ };
        let icmp_code = unsafe { (*icmph).code };
        if icmp_type as i32 != unsafe { unreach_type } || icmp_code as i32 != unsafe { unreach_code } {
            return SK_PASS;
        }
    } else {
        return SK_PASS;
    }

    let ret = unsafe {
        bpf_icmp_send(
            skb,
            unreach_type,
            unreach_code,
        )
    };

    let idx = (unsafe { rec_count } & 1) as usize;
    if idx < 2 {
        unsafe { rec_kfunc_rets[idx] = ret };
    }
    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(rec_count), 1);

    if protocol == IPPROTO_ICMP {
        return SK_PASS;
    }

    SK_DROP
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual BSD/GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
