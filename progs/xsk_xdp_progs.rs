#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/xsk_xdp_progs.c
// (bpf-rs-core idiom).
//
// The file-scope `static unsigned int idx;` in the C source is written then
// immediately read within the same call to xsk_xdp_shared_umem and read
// nowhere else, so the reference compiler proves it dead-as-a-global and
// drops its .bss backing store entirely (confirmed via `bpftool btf dump`
// on the clang-built object: .bss holds only `adjust_value`, `count` and
// `xsk_xdp_drop.drop_idx`, offsets 0/4/8). Mirrored here as a plain local
// instead of a persistent static so our .bss layout matches byte-for-byte:
// test_xsk.c's is_adjust_tail_supported() looks up the whole .bss blob
// (key 0) into a bare 4-byte `int`, relying on `adjust_value` being the
// very first (offset 0) member.

use bpf_rs_core::bpf_map;
use bpf_rs_core::helpers::{
    bpf_redirect_map, bpf_xdp_adjust_meta, bpf_xdp_adjust_tail, bpf_xdp_get_buff_len,
    bpf_xdp_store_bytes,
};
use bpf_rs_core::{bpf_object, vload};

const XDP_DROP: i32 = 1;

const MAX_SOCKETS: u32 = 2;
const EOPNOTSUPP: i32 = 95;

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

// struct ethhdr (linux/if_ether.h). Read only via raw-pointer loads: the
// XDP data pointer carries no alignment guarantee.
#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// xsk_xdp_common.h: struct xdp_info { __u64 count; } __attribute__((aligned(32)));
#[repr(C, align(32))]
struct xdp_info {
    count: u64,
}

// xsk_xdp_common.h: #define PKT_HDR_ALIGN (sizeof(struct ethhdr) + 2)
const PKT_HDR_ALIGN: u32 = core::mem::size_of::<ethhdr>() as u32 + 2;

bpf_map! {
    xsk {
        r#type: *const [i32; 17], // BPF_MAP_TYPE_XSKMAP
        max_entries: *const [i32; 2],
        key_size: *const [i32; 4],   // sizeof(int)
        value_size: *const [i32; 4], // sizeof(int)
    }
}

#[no_mangle]
static mut adjust_value: i32 = 0;
#[no_mangle]
static mut count: i32 = 0;

#[link_section = "xdp.frags"]
#[no_mangle]
extern "C" fn xsk_def_prog(_xdp: *const xdp_md) -> i32 {
    bpf_redirect_map(&xsk, 0, XDP_DROP as u64) as i32
}

#[link_section = "xdp.frags"]
#[no_mangle]
extern "C" fn xsk_xdp_drop(_xdp: *const xdp_md) -> i32 {
    // #[no_mangle] (rather than rustc's v0-mangled name, which starts with
    // "_R" and sorts before every plain lowercase identifier) so this local
    // static lands after `adjust_value`/`count` in .bss, matching the
    // reference object's layout byte-for-byte; not in the C object's
    // GLOBAL-symbol keep-list, so the internalize pass still demotes it
    // back to a local/static symbol, same as the clang build.
    #[no_mangle]
    static mut drop_idx: u32 = 0;

    let d = unsafe { drop_idx };
    unsafe { drop_idx = d.wrapping_add(1) };

    // Drop every other packet.
    if d % 2 != 0 {
        return XDP_DROP;
    }

    bpf_redirect_map(&xsk, 0, XDP_DROP as u64) as i32
}

#[link_section = "xdp.frags"]
#[no_mangle]
extern "C" fn xsk_xdp_populate_metadata(xdp: *const xdp_md) -> i32 {
    // Reserve enough for all custom metadata.
    let err = bpf_xdp_adjust_meta(
        xdp as *mut xdp_md,
        -(core::mem::size_of::<xdp_info>() as i32),
    );
    if err != 0 {
        return XDP_DROP;
    }

    let data = vload!((*xdp).data) as usize;
    let data_meta = vload!((*xdp).data_meta) as usize;

    if data_meta + core::mem::size_of::<xdp_info>() > data {
        return XDP_DROP;
    }

    let c = unsafe { count };
    unsafe { count = c.wrapping_add(1) };
    unsafe { (*(data_meta as *mut xdp_info)).count = c as u64 };

    bpf_redirect_map(&xsk, 0, XDP_DROP as u64) as i32
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xsk_xdp_shared_umem(xdp: *const xdp_md) -> i32 {
    let data = vload!((*xdp).data) as usize;
    let data_end = vload!((*xdp).data_end) as usize;

    if data + core::mem::size_of::<ethhdr>() > data_end {
        return XDP_DROP;
    }

    // Redirecting packets based on the destination MAC address.
    let h_dest5 = unsafe { core::ptr::read_volatile((data as *const u8).add(5)) };
    let idx = (h_dest5 as u32) / 2;
    if idx > MAX_SOCKETS {
        return XDP_DROP;
    }

    bpf_redirect_map(&xsk, idx as u64, XDP_DROP as u64) as i32
}

#[link_section = "xdp.frags"]
#[no_mangle]
extern "C" fn xsk_xdp_adjust_tail(xdp: *const xdp_md) -> i32 {
    let xdp_mut = xdp as *mut xdp_md;

    let buff_len = bpf_xdp_get_buff_len(xdp_mut) as u32;
    if buff_len == 0 {
        return XDP_DROP;
    }

    let av = unsafe { adjust_value };
    let ret = bpf_xdp_adjust_tail(xdp_mut, av) as i32;
    if ret < 0 {
        // Handle unsupported cases.
        if ret == -EOPNOTSUPP {
            // Set adjust_value to -EOPNOTSUPP to indicate to userspace that
            // this case is unsupported.
            unsafe { adjust_value = -EOPNOTSUPP };
            return bpf_redirect_map(&xsk, 0, XDP_DROP as u64) as i32;
        }

        return XDP_DROP;
    }

    let curr_buff_len = bpf_xdp_get_buff_len(xdp_mut) as u32;
    if curr_buff_len != buff_len.wrapping_add(av as u32) {
        return XDP_DROP;
    }

    if curr_buff_len > buff_len {
        // Convert sequence number to network byte order. Store this in the
        // last 4 bytes of the packet. Use 'adjust_value' to determine the
        // position at the end of the packet for storing the sequence
        // number.
        let len = curr_buff_len.wrapping_sub(PKT_HDR_ALIGN);
        let words_to_end = len / core::mem::size_of::<u32>() as u32 - 1;
        let seq_num: u32 = words_to_end.to_be();

        bpf_xdp_store_bytes(
            xdp_mut,
            curr_buff_len.wrapping_sub(core::mem::size_of::<u32>() as u32),
            &seq_num as *const u32 as *const core::ffi::c_void,
            core::mem::size_of::<u32>() as u32,
        );
    }

    bpf_redirect_map(&xsk, 0, XDP_DROP as u64) as i32
}

bpf_object!("GPL");
