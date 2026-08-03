#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/fib_lookup.c
// (bpf-rs-core idiom).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::{__sk_buff, TC_ACT_SHOT};
use bpf_rs_core::helpers::bpf_fib_lookup;

// struct bpf_fib_lookup (linux/bpf.h): 64-byte layout, unions represented
// with matching Rust unions. `fib_params` is a real global here (the
// userspace test reads/writes it through skel->bss->fib_params using the
// kernel uapi struct directly), but since the test never goes through a
// bpftool-generated typed field accessor for it (it just casts the mmap'd
// bss region to `struct bpf_fib_lookup *`), only the raw byte layout needs
// to match the uapi struct — field/union type names here are not
// load-bearing. Same layout as progs/test_tc_neigh_fib.rs's local copy.
#[repr(C)]
union TotLenOrMtu {
    tot_len: u16,
    #[allow(dead_code)]
    mtu_result: u16,
}

#[repr(C)]
union TosOrFlowinfo {
    #[allow(dead_code)]
    tos: u8,
    #[allow(dead_code)]
    flowinfo: u32,
    #[allow(dead_code)]
    rt_metric: u32,
}

#[repr(C)]
union AddrSrc {
    #[allow(dead_code)]
    ipv4_src: u32,
    #[allow(dead_code)]
    ipv6_src: [u32; 4],
}

#[repr(C)]
union AddrDst {
    #[allow(dead_code)]
    ipv4_dst: u32,
    #[allow(dead_code)]
    ipv6_dst: [u32; 4],
}

#[repr(C)]
union VlanOrTbid {
    #[allow(dead_code)]
    h_vlan: [u16; 2],
    #[allow(dead_code)]
    tbid: u32,
}

#[repr(C)]
union MarkOrMac {
    #[allow(dead_code)]
    mark: u32,
    #[allow(dead_code)]
    mac: MacPair,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct MacPair {
    #[allow(dead_code)]
    smac: [u8; 6],
    #[allow(dead_code)]
    dmac: [u8; 6],
}

#[repr(C)]
struct bpf_fib_lookup {
    family: u8,
    l4_protocol: u8,
    sport: u16,
    dport: u16,
    tot_len: TotLenOrMtu,
    ifindex: u32,
    tos_flowinfo: TosOrFlowinfo,
    addr_src: AddrSrc,
    addr_dst: AddrDst,
    vlan_tbid: VlanOrTbid,
    mark_mac: MarkOrMac,
}

const _: () = assert!(core::mem::size_of::<bpf_fib_lookup>() == 64);

#[no_mangle]
static mut fib_params: bpf_fib_lookup = bpf_fib_lookup {
    family: 0,
    l4_protocol: 0,
    sport: 0,
    dport: 0,
    tot_len: TotLenOrMtu { tot_len: 0 },
    ifindex: 0,
    tos_flowinfo: TosOrFlowinfo { tos: 0 },
    addr_src: AddrSrc { ipv4_src: 0 },
    addr_dst: AddrDst { ipv4_dst: 0 },
    vlan_tbid: VlanOrTbid { tbid: 0 },
    mark_mac: MarkOrMac { mark: 0 },
};

#[no_mangle]
static mut fib_lookup_ret: i32 = 0;

#[no_mangle]
static mut lookup_flags: i32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn fib_lookup(skb: *const __sk_buff) -> i32 {
    let flags = unsafe { lookup_flags } as u32;
    let ret = bpf_fib_lookup(
        skb as *const c_void,
        core::ptr::addr_of_mut!(fib_params),
        core::mem::size_of::<bpf_fib_lookup>() as i32,
        flags,
    );
    unsafe {
        fib_lookup_ret = ret as i32;
    }

    TC_ACT_SHOT
}

bpf_object!("GPL");
