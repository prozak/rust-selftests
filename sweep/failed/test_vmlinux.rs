#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_vmlinux.c
// bpf-rs-core idiom.
//
// prog_tests/vmlinux.c triggers a nanosleep(tv_nsec=1337) syscall and
// asserts every *_called bool went true. handle__fentry/handle__kprobe
// attach (userspace-side, via set_attach_target/attach_kprobe) to
// hrtimer_start_range_ns(_user), whose 2nd arg (`ktime_t tim`) carries the
// timer's expiration, which for nanosleep equals the requested tv_nsec.
//
// handle__raw_tp/handle__tp_btf read the syscall's first arg (the user
// `struct __kernel_timespec *rqtp`) off `struct pt_regs *regs` via
// PT_REGS_PARM1_CORE_SYSCALL, which macro-expands to BPF_CORE_READ i.e. a
// bpf_probe_read_kernel of regs->regs.gp[14] (x86-64 UML's `di`, see
// tools/lib/bpf/bpf_tracing.h's __UML_PT_REGS__ block: struct pt_regs
// wraps struct uml_pt_regs, whose `gp` register-slot array starts at
// offset 0 — same layout test_probe_user.rs relies on for ksyscall ctx).
// handle__tp reads the same struct syscall_trace_enter fields (`nr` at
// offset 8, `args[0]` at offset 16 per trace_entry(8)+int nr(4)+pad(4))
// that the classic tracepoint ctx is laid out as, matching the C source's
// direct (non-CORE) field access there. handle__kprobe reads PT_REGS_PARM2
// (gp[13] / `si`) directly, matching BPF_KPROBE's non-CORE PT_REGS_PARMn.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_probe_read_kernel, bpf_probe_read_user};
use bpf_rs_core::progs::fentry_arg as arg;

const NR_NANOSLEEP: i32 = 35;
const MY_TV_NSEC: i64 = 1337;

// x86-64 UML: struct pt_regs { struct uml_pt_regs regs; }, `gp` is the
// first field of uml_pt_regs, so pt_regs doubles as a `u64[]` register
// array; offsets below are register-slot indices * 8.
const GP_DI: u64 = 14 * 8; // PARM1 (also PARM1_SYSCALL)
const GP_SI: usize = 13; // PARM2 (also PARM2_SYSCALL)

// offsetof(struct __kernel_timespec, tv_nsec): tv_sec is __kernel_time64_t
// (8 bytes) followed by `long long tv_nsec`.
const TV_NSEC_OFF: u64 = 8;

#[no_mangle]
static mut tp_called: bool = false;
#[no_mangle]
static mut raw_tp_called: bool = false;
#[no_mangle]
static mut tp_btf_called: bool = false;
#[no_mangle]
static mut kprobe_called: bool = false;
#[no_mangle]
static mut fentry_called: bool = false;

fn nsleep_tv_nsec_matches(rqtp: u64) -> bool {
    let mut tv_nsec: i64 = 0;
    let ret = bpf_probe_read_user(
        &mut tv_nsec as *mut i64 as *mut c_void,
        8,
        (rqtp + TV_NSEC_OFF) as *const c_void,
    );
    ret == 0 && tv_nsec == MY_TV_NSEC
}

#[link_section = "tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn handle__tp(ctx: *const u8) -> i32 {
    let nr = unsafe { core::ptr::read_unaligned(ctx.add(8) as *const i32) };
    if nr != NR_NANOSLEEP {
        return 0;
    }

    let rqtp = unsafe { core::ptr::read_unaligned(ctx.add(16) as *const u64) };
    if !nsleep_tv_nsec_matches(rqtp) {
        return 0;
    }

    unsafe {
        tp_called = true;
    }
    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handle__raw_tp(ctx: *const u64) -> i32 {
    let regs = arg(ctx, 0);
    let id = arg(ctx, 1) as i64;
    if id != NR_NANOSLEEP as i64 {
        return 0;
    }

    let mut rqtp: u64 = 0;
    bpf_probe_read_kernel(&mut rqtp, 8, (regs + GP_DI) as *const c_void);
    if !nsleep_tv_nsec_matches(rqtp) {
        return 0;
    }

    unsafe {
        raw_tp_called = true;
    }
    0
}

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn handle__tp_btf(ctx: *const u64) -> i32 {
    let regs = arg(ctx, 0);
    let id = arg(ctx, 1) as i64;
    if id != NR_NANOSLEEP as i64 {
        return 0;
    }

    let mut rqtp: u64 = 0;
    bpf_probe_read_kernel(&mut rqtp, 8, (regs + GP_DI) as *const c_void);
    if !nsleep_tv_nsec_matches(rqtp) {
        return 0;
    }

    unsafe {
        tp_btf_called = true;
    }
    0
}

#[link_section = "kprobe"]
#[no_mangle]
extern "C" fn handle__kprobe(ctx: *const u64) -> i32 {
    let tim = unsafe { *ctx.add(GP_SI) } as i64;
    if tim == MY_TV_NSEC {
        unsafe {
            kprobe_called = true;
        }
    }
    0
}

#[link_section = "fentry"]
#[no_mangle]
extern "C" fn handle__fentry(ctx: *const u64) -> i32 {
    let tim = arg(ctx, 1) as i64;
    if tim == MY_TV_NSEC {
        unsafe {
            fentry_called = true;
        }
    }
    0
}

bpf_object!("GPL");
