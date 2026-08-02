#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_uprobe.c
// (bpf-rs-core idiom).
//
// All six programs are BPF_UPROBE/BPF_URETPROBE (kprobe-family macros): ctx
// is `struct pt_regs *`, the same raw register-slot layout documented in
// test_probe_user.rs (x86_64 kernel-internal struct pt_regs, 21
// `unsigned long` slots: r15,r14,r13,r12,bp,bx,r11,r10,r9,r8,ax,cx,dx,si,di,
// orig_ax,ip,cs,flags,sp,ss). test_regs_change(_ip) *write* through ctx, so
// it is carried as `*mut u64` here instead of the usual `*const u64`.
//
// `regs`/`ip` are only compiled `#[cfg(target_arch = "x86")]` upstream
// (`#if defined(__TARGET_ARCH_x86)`); this build only ever targets x86_64,
// so they are unconditional here, same as the C source's effective object.
//
// `struct pt_regs regs;` is a plain (non-CORE) global: the regenerated
// skeleton just emits `struct pt_regs regs;` by name, resolved against the
// systemwide <asm/ptrace.h> struct already visible in prog_tests/uprobe.c,
// so the BTF struct here must be named exactly `pt_regs` with an identical
// byte layout (all fields plain u64 keeps the two 8-byte `cs`/`ss` unions
// byte-compatible).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;

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

// Register-slot indices into the ctx `*mut u64` (same ordering as `pt_regs`
// above), matching kprobe_multi_override.rs/test_probe_user.rs's idiom.
const SLOT_R11: usize = 6;
const SLOT_R10: usize = 7;
const SLOT_R9: usize = 8;
const SLOT_R8: usize = 9;
const SLOT_AX: usize = 10;
const SLOT_CX: usize = 11;
const SLOT_DX: usize = 12;
const SLOT_SI: usize = 13;
const SLOT_DI: usize = 14;
const SLOT_IP: usize = 16;

#[no_mangle]
static mut my_pid: i32 = 0;

#[no_mangle]
static mut test1_result: i32 = 0;
#[no_mangle]
static mut test2_result: i32 = 0;
#[no_mangle]
static mut test3_result: i32 = 0;
#[no_mangle]
static mut test4_result: i32 = 0;

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
static mut ip: u64 = 0;

fn current_pid() -> i32 {
    (bpf_get_current_pid_tgid() >> 32) as i32
}

#[link_section = "uprobe/./liburandom_read.so:urandlib_api_sameoffset"]
#[no_mangle]
extern "C" fn test1(_ctx: *const u64) -> i32 {
    if current_pid() != unsafe { my_pid } {
        return 0;
    }

    unsafe {
        test1_result = 1;
    }
    0
}

#[link_section = "uprobe/./liburandom_read.so:urandlib_api_sameoffset@LIBURANDOM_READ_1.0.0"]
#[no_mangle]
extern "C" fn test2(_ctx: *const u64) -> i32 {
    if current_pid() != unsafe { my_pid } {
        return 0;
    }

    unsafe {
        test2_result = 1;
    }
    0
}

#[link_section = "uretprobe/./liburandom_read.so:urandlib_api_sameoffset@@LIBURANDOM_READ_2.0.0"]
#[no_mangle]
extern "C" fn test3(ctx: *const u64) -> i32 {
    if current_pid() != unsafe { my_pid } {
        return 0;
    }

    let ret = unsafe { *ctx.add(SLOT_AX) } as i32;
    unsafe {
        test3_result = ret;
    }
    0
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn test4(_ctx: *const u64) -> i32 {
    if current_pid() != unsafe { my_pid } {
        return 0;
    }

    unsafe {
        test4_result = 1;
    }
    0
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn test_regs_change(ctx: *mut u64) -> i32 {
    if current_pid() != unsafe { my_pid } {
        return 0;
    }

    unsafe {
        *ctx.add(SLOT_AX) = regs.ax;
        *ctx.add(SLOT_CX) = regs.cx;
        *ctx.add(SLOT_DX) = regs.dx;
        *ctx.add(SLOT_R8) = regs.r8;
        *ctx.add(SLOT_R9) = regs.r9;
        *ctx.add(SLOT_R10) = regs.r10;
        *ctx.add(SLOT_R11) = regs.r11;
        *ctx.add(SLOT_DI) = regs.di;
        *ctx.add(SLOT_SI) = regs.si;
    }
    0
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn test_regs_change_ip(ctx: *mut u64) -> i32 {
    if current_pid() != unsafe { my_pid } {
        return 0;
    }

    unsafe {
        *ctx.add(SLOT_IP) = ip;
    }
    0
}

bpf_object!("GPL");
