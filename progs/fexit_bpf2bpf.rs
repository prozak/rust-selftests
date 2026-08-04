#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/fexit_bpf2bpf.c
// (bpf-rs-core idiom).
//
// fexit/... programs attach to test_pkt_access() and its noinline
// subprograms (target: test_pkt_access.bpf.o, a tc/SCHED_CLS program); the
// trampoline's real arg0 for those is the kernel `struct sk_buff *` (not
// the `struct __sk_buff *` the tc source sees), matched via CO-RE against
// the real kernel struct, same idiom as test_trace_ext_tracing.rs.
//
// test_pkt_access_subprog2's `val` parameter gets constant-propagated away
// by the target's LLVM (see test_pkt_access.c's comment): the compiler
// building test_pkt_access.bpf.o here is clang 22 (< 23), so its BTF still
// declares 2 params but the real ABI has collapsed to 1, and the kernel
// falls back to a conservative 5-slot ctx array with `ret` at index 5 (C's
// `struct args_subprog2 { __u64 args[5]; __u64 ret; }` branch). ctx here
// is untyped, so skb's address is a plain scalar -- read through it with
// bpf_probe_read_kernel, not a direct dereference.
//
// prog_tests/fexit_bpf2bpf.c's check_data_map() reads the internal .bss
// map as a raw `result[prog_cnt]` array, assuming the 8 globals below sit
// in the exact C declaration order (test_result group first, then the
// freplace group). rustc's mono-item collector always emits same-crate
// #[no_mangle] statics in ascending ABI-symbol-name order regardless of
// source order (confirmed separately for functions; the same alphabetical
// layout is confirmed here too), which would scatter the two groups and
// break test_target_yes_callees (prog_cnt=4, first group only). Since
// nothing in this file's own prog_tests consumes a compile-time skeleton
// field for these globals (check_data_map is a raw byte read), hand-lay
// them out in a `global_asm!` block instead of as Rust `static`s, which
// keeps their ELF symbol names (needed by the keep-list) and .bss layout
// order (needed by check_data_map) both correct; only the BTF VAR
// description for each (unused here) is lost.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_probe_read_kernel, bpf_skb_load_bytes};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_object, vload};
use btf_macros::btf;
use core::ffi::c_void;

#[btf]
struct sk_buff {
    len: u32,
}

// struct ethhdr (linux/if_ether.h): only used for its size.
#[repr(C)]
struct EthHdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

// struct ipv6hdr (linux/ipv6.h): only nexthdr/payload_len are read; the
// rest is kept as raw fields so the struct's size (and the following
// tcphdr's offset) matches the real header exactly.
#[repr(C)]
struct Ipv6Hdr {
    priority_version: u8,
    flow_lbl: [u8; 3],
    payload_len: u16,
    nexthdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

// struct tcphdr (linux/tcp.h): res1/doff/flags is one little-endian
// bitfield u16 split byte-wise here -- the low byte holds res1:4|doff:4,
// the high byte holds fin,syn,rst,psh,ack,urg,ece,cwr from bit0 up, so
// `syn` is bit 1 (0x02) of `tcp_flags`.
#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    res1_doff: u8,
    tcp_flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

const TCP_FLAG_SYN: u8 = 0x02;

core::arch::global_asm!(
    r#"
    .section .bss,"aw",@nobits
    .global test_result
    .p2align 3
    .type test_result,@object
    .size test_result,8
test_result:
    .zero 8
    .global test_result_subprog1
    .p2align 3
    .type test_result_subprog1,@object
    .size test_result_subprog1,8
test_result_subprog1:
    .zero 8
    .global test_result_subprog2
    .p2align 3
    .type test_result_subprog2,@object
    .size test_result_subprog2,8
test_result_subprog2:
    .zero 8
    .global test_result_subprog3
    .p2align 3
    .type test_result_subprog3,@object
    .size test_result_subprog3,8
test_result_subprog3:
    .zero 8
    .global test_get_skb_len
    .p2align 3
    .type test_get_skb_len,@object
    .size test_get_skb_len,8
test_get_skb_len:
    .zero 8
    .global test_get_skb_ifindex
    .p2align 3
    .type test_get_skb_ifindex,@object
    .size test_get_skb_ifindex,8
test_get_skb_ifindex:
    .zero 8
    .global test_get_constant
    .p2align 3
    .type test_get_constant,@object
    .size test_get_constant,8
test_get_constant:
    .zero 8
    .global test_pkt_write_access_subprog
    .p2align 3
    .type test_pkt_write_access_subprog,@object
    .size test_pkt_write_access_subprog,8
test_pkt_write_access_subprog:
    .zero 8
    "#
);

extern "C" {
    static mut test_result: u64;
    static mut test_result_subprog1: u64;
    static mut test_result_subprog2: u64;
    static mut test_result_subprog3: u64;
    static mut test_get_skb_len: u64;
    static mut test_get_skb_ifindex: u64;
    static mut test_get_constant: u64;
    static mut test_pkt_write_access_subprog: u64;
}

#[link_section = "fexit/test_pkt_access"]
#[no_mangle]
extern "C" fn test_main(ctx: *const u64) -> i32 {
    let skb = arg(ctx, 0) as *const sk_buff;
    let ret = arg(ctx, 1) as i32;
    let len = *unsafe { &*skb }.len().get().unwrap() as i32;
    if len != 74 || ret != 0 {
        return 0;
    }
    unsafe {
        test_result = 1;
    }
    0
}

#[link_section = "fexit/test_pkt_access_subprog1"]
#[no_mangle]
extern "C" fn test_subprog1(ctx: *const u64) -> i32 {
    let skb = arg(ctx, 0) as *const sk_buff;
    let ret = arg(ctx, 1) as i32;
    let len = *unsafe { &*skb }.len().get().unwrap() as i32;
    if len != 74 || ret != 148 {
        return 0;
    }
    unsafe {
        test_result_subprog1 = 1;
    }
    0
}

#[link_section = "fexit/test_pkt_access_subprog2"]
#[no_mangle]
extern "C" fn test_subprog2(ctx: *const u64) -> i32 {
    let skb = arg(ctx, 0) as *const sk_buff;
    let len_ptr = unsafe { &*skb }.len().as_ptr();
    let mut len: u32 = 0;
    bpf_probe_read_kernel(&mut len, 4, len_ptr as *const c_void);

    // bpf_prog_test_load() loads test_pkt_access.bpf.o with
    // BPF_F_TEST_RND_HI32, which randomizes upper 32 bits after BPF_ALU32
    // insns; trim to the low 32 bits like the C original.
    let ret = arg(ctx, 5) as u32;
    if len != 74 || ret != 148 {
        return 0;
    }
    unsafe {
        test_result_subprog2 = 1;
    }
    0
}

#[link_section = "fexit/test_pkt_access_subprog3"]
#[no_mangle]
extern "C" fn test_subprog3(ctx: *const u64) -> i32 {
    let val = arg(ctx, 0) as i32;
    let skb = arg(ctx, 1) as *const sk_buff;
    let ret = arg(ctx, 2) as i32;
    let len = *unsafe { &*skb }.len().get().unwrap() as i32;
    if len != 74 || ret != 74 * val || val != 3 {
        return 0;
    }
    unsafe {
        test_result_subprog3 = 1;
    }
    0
}

#[link_section = "freplace/get_skb_len"]
#[no_mangle]
extern "C" fn new_get_skb_len(skb: *const __sk_buff) -> i32 {
    let len = vload!((*skb).len) as i32;
    if len != 74 {
        return 0;
    }
    unsafe {
        test_get_skb_len = 1;
    }
    74
}

#[link_section = "freplace/get_skb_ifindex"]
#[no_mangle]
extern "C" fn new_get_skb_ifindex(val: i32, skb: *const __sk_buff, var: i32) -> i32 {
    let data_end = vload!((*skb).data_end) as usize;
    let data = vload!((*skb).data) as usize;
    let ifindex = vload!((*skb).ifindex) as i32;

    // check that BPF extension can read packet via direct packet access
    if data
        .wrapping_add(14)
        .wrapping_add(core::mem::size_of::<Ipv6Hdr>())
        > data_end
    {
        return 0;
    }
    let ip6p = data.wrapping_add(14) as *const Ipv6Hdr;

    if unsafe { (*ip6p).nexthdr } != 6 || unsafe { (*ip6p).payload_len } != 123u16.to_be() {
        return 0;
    }

    // check that legacy packet access helper works too
    let mut ip6: Ipv6Hdr = unsafe { core::mem::zeroed() };
    let n = bpf_skb_load_bytes(
        skb as *const c_void,
        14,
        &mut ip6 as *mut Ipv6Hdr as *mut c_void,
        core::mem::size_of::<Ipv6Hdr>() as u32,
    );
    if n < 0 {
        return 0;
    }
    if ip6.nexthdr != 6 || ip6.payload_len != 123u16.to_be() {
        return 0;
    }

    if ifindex != 1 || val != 3 || var != 1 {
        return 0;
    }
    unsafe {
        test_get_skb_ifindex = 1;
    }
    3
}

#[link_section = "freplace/get_constant"]
#[no_mangle]
extern "C" fn new_get_constant(val: i64) -> i32 {
    if val != 123 {
        return 0;
    }
    unsafe {
        test_get_constant = 1;
    }
    unsafe { test_get_constant as i32 }
}

#[link_section = "freplace/test_pkt_write_access_subprog"]
#[no_mangle]
extern "C" fn new_test_pkt_write_access_subprog(skb: *const __sk_buff, off: u32) -> i32 {
    let data = vload!((*skb).data) as usize;
    let data_end = vload!((*skb).data_end) as usize;

    if off as usize > core::mem::size_of::<EthHdr>() + core::mem::size_of::<Ipv6Hdr>() {
        return -1;
    }

    let tcp = data.wrapping_add(off as usize) as *mut TcpHdr;
    if (tcp as usize).wrapping_add(core::mem::size_of::<TcpHdr>()) > data_end {
        return -1;
    }

    // make modifications to the packet data
    unsafe {
        (*tcp).check = (*tcp).check.wrapping_add(1);
        (*tcp).tcp_flags &= !TCP_FLAG_SYN;
    }

    unsafe {
        test_pkt_write_access_subprog = 1;
    }
    0
}

bpf_object!("GPL");
