#![no_std]
#![no_main]
#![feature(linkage, used_with_arg)]

// Direct translation of
// tools/testing/selftests/bpf/progs/uprobe_multi_usdt.c (bpf-rs-core
// idiom).

#![allow(non_upper_case_globals)]

use bpf_rs_core::bpf_object;
use bpf_rs_core::maps::{self, BpfMap};

// Pinned usdt.bpf.h ABI: twelve 24-byte argument specifications,
// followed by a cookie and argument count (304 bytes including padding).
// Clang aligns the 12+4-bit u16 fields at byte 10, leaving padding after
// arg_type; reg_off is at byte 14 and the final two bytes at 16 and 17.
#[repr(C)]
struct UsdtArgSpec {
    val_off: u64,
    arg_type: u8,
    _pad_arg_type: u8,
    idx_reg_off_scale_bitshift: u16,
    reserved: u8,
    _pad_reserved: u8,
    reg_off: i16,
    arg_signed: bool,
    arg_bitshift: i8,
    _pad_tail: [u8; 6],
}

#[repr(C)]
struct UsdtSpec {
    args: [UsdtArgSpec; 12],
    usdt_cookie: u64,
    arg_cnt: i16,
    _pad_tail: [u8; 6],
}

// Compiler retention keeps both definitions in a shared .maps section.
// Required even for a zero-argument handler: libbpf populates these maps
// while attaching USDT probes. Weak linkage matches usdt.bpf.h.
#[used(compiler)]
#[linkage = "weak"]
#[link_section = ".maps"]
#[no_mangle]
static mut __bpf_usdt_specs: BpfMap<i32, UsdtSpec, { maps::ARRAY }, 256> = BpfMap::new();

#[used(compiler)]
#[linkage = "weak"]
#[link_section = ".maps"]
#[no_mangle]
static mut __bpf_usdt_ip_to_spec_id: BpfMap<i64, u32, { maps::HASH }, 1024> = BpfMap::new();

#[no_mangle]
static mut count: i32 = 0;

#[link_section = "usdt"]
#[no_mangle]
extern "C" fn usdt0(_ctx: *const u64) -> i32 {
    unsafe { count += 1 };
    0
}

bpf_object!("GPL");
