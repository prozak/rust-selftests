// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(linkage, used_with_arg)]

// Direct translation of tools/testing/selftests/bpf/progs/uprobe_syscall_executed.c
// (bpf-rs-core idiom).
//
// All six programs are the identical body (check current pid == `pid`,
// bump `executed`); none of them ever dereference `ctx` (uprobe.multi/
// uretprobe.multi/uprobe.session/usdt take `struct pt_regs *ctx` directly
// with no field access, uprobe/uretprobe are BPF_UPROBE/BPF_URETPROBE
// macros with no extracted args -- same shape as kprobe_multi_override.rs),
// so ctx is carried opaque here.
//
// `struct pt_regs regs;` is a plain (non-CORE) global declared but never
// read/written by any program body in this file (unlike the sibling
// uprobe_syscall.c, whose *userspace* test reads `skel->bss->regs` -- no
// prog_tests subtest here does that for this skeleton). It only needs to
// exist as a matching bss symbol; layout follows test_uprobe.rs's
// already-established `pt_regs` (x86_64 kernel struct, 21 `unsigned long`
// slots), since this repo's uprobe/uretprobe/uprobe.multi tests are run
// under FLAVOR=qemu (real x86_64 kernel BTF) -- UML wraps pt_regs around
// `uml_pt_regs` instead and doesn't support uprobe attach at all.
//
// The uprobe_usdt subtest attaches through bpf_program__attach_usdt(), which
// needs usdt.bpf.h's two `SEC(".maps") __weak` maps, `__bpf_usdt_specs` and
// `__bpf_usdt_ip_to_spec_id`, by name with global linkage; they are declared
// here as in uprobe_multi_usdt.rs (weak, as in C; the keep list keeps a C
// object's weak symbols too).

use bpf_rs_core::bpf_object;
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use core::ffi::c_void;

#[allow(non_camel_case_types)]
#[repr(C)]
struct pt_regs {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    bp: u64,
    bx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    ax: u64,
    cx: u64,
    dx: u64,
    si: u64,
    di: u64,
    orig_ax: u64,
    ip: u64,
    cs: u64,
    flags: u64,
    sp: u64,
    ss: u64,
}

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
static mut regs: pt_regs = pt_regs {
    r15: 0,
    r14: 0,
    r13: 0,
    r12: 0,
    bp: 0,
    bx: 0,
    r11: 0,
    r10: 0,
    r9: 0,
    r8: 0,
    ax: 0,
    cx: 0,
    dx: 0,
    si: 0,
    di: 0,
    orig_ax: 0,
    ip: 0,
    cs: 0,
    flags: 0,
    sp: 0,
    ss: 0,
};

#[no_mangle]
static mut executed: i32 = 0;

#[no_mangle]
static mut pid: i32 = 0;

#[inline(never)]
fn record(_ctx: *const c_void) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) as i32 != unsafe { pid } {
        return 0;
    }

    unsafe {
        executed += 1;
    }
    0
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn test_uprobe(ctx: *const c_void) -> i32 {
    record(ctx)
}

#[link_section = "uretprobe"]
#[no_mangle]
extern "C" fn test_uretprobe(ctx: *const c_void) -> i32 {
    record(ctx)
}

#[link_section = "uprobe.multi"]
#[no_mangle]
extern "C" fn test_uprobe_multi(ctx: *const c_void) -> i32 {
    record(ctx)
}

#[link_section = "uretprobe.multi"]
#[no_mangle]
extern "C" fn test_uretprobe_multi(ctx: *const c_void) -> i32 {
    record(ctx)
}

#[link_section = "uprobe.session"]
#[no_mangle]
extern "C" fn test_uprobe_session(ctx: *const c_void) -> i32 {
    record(ctx)
}

#[link_section = "usdt"]
#[no_mangle]
extern "C" fn test_usdt(ctx: *const c_void) -> i32 {
    record(ctx)
}

bpf_object!("GPL");
