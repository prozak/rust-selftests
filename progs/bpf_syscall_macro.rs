#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_syscall_macro.c
// (bpf-rs-core idiom).
//
// Both `handle_sys_prctl` (BPF_KPROBE on the raw `__x64_sys_prctl` entry) and
// the two BPF_KSYSCALL programs read syscall arguments off the *inner*
// `struct pt_regs` reached through the ARCH_HAS_SYSCALL_WRAPPER indirection:
// `ctx` is the kprobe's own pt_regs, whose `di` slot (PT_REGS_PARM1(ctx))
// holds a pointer to the real syscall pt_regs -- same double-indirection
// idiom as test_probe_user.rs's `handle_sys_connect` and test_vmlinux.rs.
// rustc can't emit the `__kconfig` BTF VAR BPF_KSYSCALL branches on, so the
// wrapper-present branch is hardcoded to match this build's x86_64 kernel
// (CONFIG_ARCH_HAS_SYSCALL_WRAPPER=y).
//
// x86_64 `struct pt_regs` is 21 `long`-sized fields in order: r15,r14,r13,
// r12,bp,bx,r11,r10,r9,r8,ax,cx,dx,si,di,orig_ax,ip,cs,flags,sp,ss. Register
// -> syscall-arg mapping (tools/lib/bpf/bpf_tracing.h):
//   PARM1/PARM1_SYSCALL = di     PARM4          = cx  (clobbered by SYSCALL)
//   PARM2/PARM2_SYSCALL = si     PARM4_SYSCALL  = r10 (real 4th syscall arg)
//   PARM3/PARM3_SYSCALL = dx     PARM5/PARM5_SYSCALL = r8
//                                PARM6_SYSCALL  = r9
// `arg4_cx`/`arg4_core_cx` deliberately read the wrong (cx) register, same
// as the C source -- the userspace test asserts they DIFFER from the real
// arg4 on x86_64.

use core::ffi::c_void;
use core::ptr::{addr_of, read_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel};

const DI: u64 = 14 * 8;
const SI: u64 = 13 * 8;
const DX: u64 = 12 * 8;
const CX: u64 = 11 * 8;
const R10: u64 = 7 * 8;
const R9: u64 = 8 * 8;
const R8: u64 = 9 * 8;

#[link_section = ".rodata"]
#[no_mangle]
static filter_pid: i32 = 0;

#[no_mangle]
static mut arg1: i32 = 0;
#[no_mangle]
static mut arg2: u64 = 0;
#[no_mangle]
static mut arg3: u64 = 0;
#[no_mangle]
static mut arg4_cx: u64 = 0;
#[no_mangle]
static mut arg4: u64 = 0;
#[no_mangle]
static mut arg5: u64 = 0;

#[no_mangle]
static mut arg1_core: i32 = 0;
#[no_mangle]
static mut arg2_core: u64 = 0;
#[no_mangle]
static mut arg3_core: u64 = 0;
#[no_mangle]
static mut arg4_core_cx: u64 = 0;
#[no_mangle]
static mut arg4_core: u64 = 0;
#[no_mangle]
static mut arg5_core: u64 = 0;

#[no_mangle]
static mut option_syscall: i32 = 0;
#[no_mangle]
static mut arg2_syscall: u64 = 0;
#[no_mangle]
static mut arg3_syscall: u64 = 0;
#[no_mangle]
static mut arg4_syscall: u64 = 0;
#[no_mangle]
static mut arg5_syscall: u64 = 0;

#[no_mangle]
static mut splice_fd_in: u64 = 0;
#[no_mangle]
static mut splice_off_in: u64 = 0;
#[no_mangle]
static mut splice_fd_out: u64 = 0;
#[no_mangle]
static mut splice_off_out: u64 = 0;
#[no_mangle]
static mut splice_len: u64 = 0;
#[no_mangle]
static mut splice_flags: u64 = 0;

fn cur_pid() -> i32 {
    (bpf_get_current_pid_tgid() >> 32) as i32
}

fn wanted_pid() -> i32 {
    unsafe { read_volatile(addr_of!(filter_pid)) }
}

fn probe_read_u64(addr: u64) -> u64 {
    let mut v: u64 = 0;
    bpf_probe_read_kernel(&mut v, 8, addr as *const c_void);
    v
}

#[link_section = "kprobe/__x64_sys_prctl"]
#[no_mangle]
extern "C" fn handle_sys_prctl(ctx: *const u64) -> i32 {
    if cur_pid() != wanted_pid() {
        return 0;
    }

    // PT_REGS_SYSCALL_REGS(ctx) == PT_REGS_PARM1(ctx) == ctx->di.
    let real_regs = unsafe { *ctx.add(14) };

    unsafe {
        arg1 = probe_read_u64(real_regs + DI) as i32;
        arg2 = probe_read_u64(real_regs + SI);
        arg3 = probe_read_u64(real_regs + DX);
        arg4_cx = probe_read_u64(real_regs + CX);
        arg4 = probe_read_u64(real_regs + R10);
        arg5 = probe_read_u64(real_regs + R8);

        arg1_core = probe_read_u64(real_regs + DI) as i32;
        arg2_core = probe_read_u64(real_regs + SI);
        arg3_core = probe_read_u64(real_regs + DX);
        arg4_core_cx = probe_read_u64(real_regs + CX);
        arg4_core = probe_read_u64(real_regs + R10);
        arg5_core = probe_read_u64(real_regs + R8);
    }

    0
}

#[link_section = "ksyscall/prctl"]
#[no_mangle]
extern "C" fn prctl_enter(ctx: *const u64) -> i32 {
    if cur_pid() != wanted_pid() {
        return 0;
    }

    let regs = unsafe { *ctx.add(14) };

    unsafe {
        option_syscall = probe_read_u64(regs + DI) as i32;
        arg2_syscall = probe_read_u64(regs + SI);
        arg3_syscall = probe_read_u64(regs + DX);
        arg4_syscall = probe_read_u64(regs + R10);
        arg5_syscall = probe_read_u64(regs + R8);
    }

    0
}

#[link_section = "ksyscall/splice"]
#[no_mangle]
extern "C" fn splice_enter(ctx: *const u64) -> i32 {
    if cur_pid() != wanted_pid() {
        return 0;
    }

    let regs = unsafe { *ctx.add(14) };

    unsafe {
        let fd_in = probe_read_u64(regs + DI) as i32;
        splice_fd_in = fd_in as i64 as u64;
        splice_off_in = probe_read_u64(regs + SI);
        let fd_out = probe_read_u64(regs + DX) as i32;
        splice_fd_out = fd_out as i64 as u64;
        splice_off_out = probe_read_u64(regs + R10);
        splice_len = probe_read_u64(regs + R8);
        let flags = probe_read_u64(regs + R9) as u32;
        splice_flags = flags as u64;
    }

    0
}

bpf_object!("GPL");
