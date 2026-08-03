#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/uprobe_syscall.c
// (bpf-rs-core idiom).
//
// `probe` is SEC("uprobe") with `struct pt_regs *ctx`; the C body is a plain
// `__builtin_memcpy(&regs, ctx, sizeof(regs))`. ctx here is carried as the
// raw `*const u64` register-slot array (same x86_64 kernel pt_regs slot
// ordering as test_uprobe.rs/test_probe_user.rs: r15,r14,r13,r12,bp,bx,r11,
// r10,r9,r8,ax,cx,dx,si,di,orig_ax,ip,cs,flags,sp,ss) and copied field by
// field instead of via a bulk memcpy: even a small fixed-size
// copy_nonoverlapping here gets MemCpyOpt-recognized and rewritten into an
// unresolvable bpf_arena_memcpy kfunc call, so each slot is read/stored
// individually instead.
//
// `struct pt_regs regs;` is a plain (non-CORE) global: the regenerated
// skeleton emits `struct pt_regs regs;` by name, resolved against the
// systemwide <asm/ptrace.h> struct used directly by prog_tests/uprobe_syscall.c
// (`skel->bss->regs`), so the BTF struct here must be named exactly
// `pt_regs` with an identical byte layout.

use bpf_rs_core::bpf_object;

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

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn probe(ctx: *const u64) -> i32 {
    unsafe {
        regs.r15 = *ctx.add(0);
        regs.r14 = *ctx.add(1);
        regs.r13 = *ctx.add(2);
        regs.r12 = *ctx.add(3);
        regs.bp = *ctx.add(4);
        regs.bx = *ctx.add(5);
        regs.r11 = *ctx.add(6);
        regs.r10 = *ctx.add(7);
        regs.r9 = *ctx.add(8);
        regs.r8 = *ctx.add(9);
        regs.ax = *ctx.add(10);
        regs.cx = *ctx.add(11);
        regs.dx = *ctx.add(12);
        regs.si = *ctx.add(13);
        regs.di = *ctx.add(14);
        regs.orig_ax = *ctx.add(15);
        regs.ip = *ctx.add(16);
        regs.cs = *ctx.add(17);
        regs.flags = *ctx.add(18);
        regs.sp = *ctx.add(19);
        regs.ss = *ctx.add(20);
    }
    0
}

bpf_object!("GPL");
