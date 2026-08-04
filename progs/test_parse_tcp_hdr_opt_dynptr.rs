#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_parse_tcp_hdr_opt_dynptr.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;

const TCPOPT_EOL: u8 = 0;
const TCPOPT_NOP: u8 = 1;

const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

const ETHHDR_LEN: usize = 14; // sizeof(struct ethhdr)
const IPV6HDR_LEN: usize = 40; // sizeof(struct ipv6hdr)
const TCPHDR_LEN: usize = 20; // sizeof(struct tcphdr)

/// Kind number used for experiments.
#[link_section = ".rodata"]
#[no_mangle]
static tcp_hdr_opt_kind_tpr: u32 = 0xFD;
/// Length of the tcp header option.
#[link_section = ".rodata"]
#[no_mangle]
static tcp_hdr_opt_len_tpr: u32 = 6;
/// Maximum number of header options to check to lookup server_id.
#[link_section = ".rodata"]
#[no_mangle]
static tcp_hdr_opt_max_opt_checks: u32 = 15;

#[no_mangle]
static mut server_id: u32 = 0;

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

/// UAPI struct bpf_dynptr (linux/bpf.h): two opaque u64 slots.
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

extern "C" {
    fn bpf_dynptr_from_xdp(xdp: *mut xdp_md, flags: u64, ptr: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_slice(
        ptr: *const bpf_dynptr,
        offset: u64,
        buffer: *mut c_void,
        buffer_sz: u64,
    ) -> *mut c_void;
}

fn parse_hdr_opt(
    ptr: *const bpf_dynptr,
    off: &mut u32,
    hdr_bytes_remaining: &mut u8,
    server_id_out: *mut u32,
) -> i32 {
    let mut buffer: [u8; 6] = [0; 6]; // sizeof(kind) + sizeof(hdr_len) + sizeof(*server_id)

    let data = unsafe {
        bpf_dynptr_slice(
            ptr,
            *off as u64,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u64,
        )
    };
    if data.is_null() {
        return -1;
    }
    let data = data as *const u8;

    let kind = unsafe { *data };

    if kind == TCPOPT_EOL {
        return -1;
    }

    if kind == TCPOPT_NOP {
        *off += 1;
        *hdr_bytes_remaining = hdr_bytes_remaining.wrapping_sub(1);
        return 0;
    }

    if *hdr_bytes_remaining < 2 {
        return -1;
    }

    let hdr_len = unsafe { *data.add(1) };
    if hdr_len > *hdr_bytes_remaining {
        return -1;
    }

    if kind as u32 == tcp_hdr_opt_kind_tpr {
        if hdr_len as u32 != tcp_hdr_opt_len_tpr {
            return -1;
        }

        let mut sid: u32 = 0;
        let sid_bytes = &mut sid as *mut u32 as *mut u8;
        for i in 0..4usize {
            unsafe {
                core::ptr::write_volatile(
                    sid_bytes.add(i),
                    core::ptr::read_volatile(data.add(2 + i)),
                );
            }
        }
        unsafe { *server_id_out = sid };
        return 1;
    }

    *off += hdr_len as u32;
    *hdr_bytes_remaining = hdr_bytes_remaining.wrapping_sub(hdr_len);
    0
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_ingress_v6(xdp: *const xdp_md) -> i32 {
    let mut buffer: [u8; TCPHDR_LEN] = [0; TCPHDR_LEN];

    let mut ptr = bpf_dynptr { __opaque: [0; 2] };
    unsafe { bpf_dynptr_from_xdp(xdp as *mut xdp_md, 0, &mut ptr) };

    let mut off: u32 = (ETHHDR_LEN + IPV6HDR_LEN) as u32;

    let tcp_hdr = unsafe {
        bpf_dynptr_slice(
            &ptr,
            off as u64,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u64,
        )
    };
    if tcp_hdr.is_null() {
        return XDP_DROP;
    }
    let tcp_hdr = tcp_hdr as *const u8;

    // struct tcphdr: source(2) dest(2) seq(4) ack_seq(4) = 12 bytes, then a
    // little-endian bitfield byte holding res1:4, doff:4 at offset 12.
    let doff_byte = unsafe { *tcp_hdr.add(12) };
    let doff = (doff_byte >> 4) & 0x0F;
    let tcp_hdr_opt_len = doff.wrapping_mul(4).wrapping_sub(TCPHDR_LEN as u8);

    if (tcp_hdr_opt_len as u32) < tcp_hdr_opt_len_tpr {
        return XDP_DROP;
    }

    let mut hdr_bytes_remaining: u8 = tcp_hdr_opt_len;

    off += TCPHDR_LEN as u32;

    // max number of bytes of options in tcp header is 40 bytes
    for _ in 0..tcp_hdr_opt_max_opt_checks {
        let err = parse_hdr_opt(
            &ptr,
            &mut off,
            &mut hdr_bytes_remaining,
            core::ptr::addr_of_mut!(server_id),
        );

        if err != 0 || hdr_bytes_remaining == 0 {
            break;
        }
    }

    if unsafe { server_id } == 0 {
        return XDP_DROP;
    }

    XDP_PASS
}

bpf_object!("GPL");
