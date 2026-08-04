#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_sleepable_tracepoints.c
// (bpf-rs-core idiom).
//
// All four "getcwd" handlers resolve the syscall's first arg (the user
// `char *buf` pointer) off `struct pt_regs *regs`. Following the
// already-verified pt_regs idiom from test_vmlinux.rs (this repo's UML
// build wraps `struct pt_regs` around `struct uml_pt_regs`, whose `gp`
// register-slot array happens to line up with the native x86-64 field
// order too), every regs read here goes through a plain
// `bpf_probe_read_kernel` at a fixed offset (GP_DI = 14*8, the `di` slot /
// PARM1 / PARM1_SYSCALL) rather than a direct pointer dereference --
// avoids re-deriving trust-level distinctions the C source's
// PT_REGS_PARM1_SYSCALL (tp_btf, direct) vs PT_REGS_PARM1_CORE_SYSCALL
// (raw_tp/sys_exit, CORE) macros encode, since the probe-read form already
// works uniformly for both in this environment.
//
// The classic tracepoint handler (`handle_sys_enter_tp`) reads
// `struct syscall_trace_enter`'s `args[0]` at a fixed byte offset (16 =
// trace_entry(8) + int nr(4) + pad(4)), same layout test_vmlinux.rs's
// handle__tp uses.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_copy_from_user, bpf_get_current_pid_tgid, bpf_get_current_task_btf, bpf_probe_read_kernel,
    bpf_task_pt_regs,
};
use bpf_rs_core::progs::fentry_arg as arg;

const NR_GETCWD: i64 = 79;
const GP_DI: u64 = 14 * 8; // PARM1 (also PARM1_SYSCALL)

#[no_mangle]
static mut target_pid: i32 = 0;
#[no_mangle]
static mut prog_triggered: i32 = 0;
#[no_mangle]
static mut err: isize = 0;
#[no_mangle]
static mut copied_byte: i8 = 0;

#[inline(never)]
fn copy_getcwd_arg(ubuf: *const c_void) -> i32 {
    let ret = bpf_copy_from_user(
        core::ptr::addr_of_mut!(copied_byte) as *mut c_void,
        1,
        ubuf,
    );
    unsafe { err = ret as isize };
    if ret != 0 {
        return ret as i32;
    }

    unsafe { prog_triggered = 1 };
    0
}

#[inline(always)]
fn read_di(regs: u64) -> u64 {
    let mut v: u64 = 0;
    bpf_probe_read_kernel(&mut v, 8, (regs + GP_DI) as *const c_void);
    v
}

#[link_section = "tp_btf.s/sys_enter"]
#[no_mangle]
extern "C" fn handle_sys_enter_tp_btf(ctx: *const u64) -> i32 {
    let regs = arg(ctx, 0);
    let id = arg(ctx, 1) as i64;

    if (bpf_get_current_pid_tgid() >> 32) != unsafe { target_pid } as u64 || id != NR_GETCWD {
        return 0;
    }

    copy_getcwd_arg(read_di(regs) as *const c_void)
}

#[link_section = "raw_tp.s/sys_enter"]
#[no_mangle]
extern "C" fn handle_sys_enter_raw_tp(ctx: *const u64) -> i32 {
    let regs = arg(ctx, 0);
    let id = arg(ctx, 1) as i64;

    if (bpf_get_current_pid_tgid() >> 32) != unsafe { target_pid } as u64 || id != NR_GETCWD {
        return 0;
    }

    copy_getcwd_arg(read_di(regs) as *const c_void)
}

#[link_section = "tp.s/syscalls/sys_enter_getcwd"]
#[no_mangle]
extern "C" fn handle_sys_enter_tp(ctx: *const u8) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) != unsafe { target_pid } as u64 {
        return 0;
    }

    let arg0 = unsafe { core::ptr::read_unaligned(ctx.add(16) as *const u64) };
    copy_getcwd_arg(arg0 as *const c_void)
}

#[link_section = "tp.s/syscalls/sys_exit_getcwd"]
#[no_mangle]
extern "C" fn handle_sys_exit_tp(_ctx: *const c_void) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) != unsafe { target_pid } as u64 {
        return 0;
    }

    let cur_task: *mut c_void = bpf_get_current_task_btf();
    let regs = bpf_task_pt_regs(cur_task) as u64;
    copy_getcwd_arg(read_di(regs) as *const c_void)
}

#[link_section = "raw_tp.s"]
#[no_mangle]
extern "C" fn handle_raw_tp_bare(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "tp.s"]
#[no_mangle]
extern "C" fn handle_tp_bare(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "tracepoint.s/syscalls/sys_enter_getcwd"]
#[no_mangle]
extern "C" fn handle_sys_enter_tp_alias(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "raw_tracepoint.s/sys_enter"]
#[no_mangle]
extern "C" fn handle_sys_enter_raw_tp_alias(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "raw_tp.s/sys_enter"]
#[no_mangle]
extern "C" fn handle_test_run(ctx: *const u64) -> i32 {
    let regs = arg(ctx, 0);
    let id = arg(ctx, 1);

    if regs == 0x1234 && id == 0x5678 {
        return (regs + id) as i32;
    }

    0
}

#[link_section = "raw_tp.s/sched_switch"]
#[no_mangle]
extern "C" fn handle_raw_tp_non_faultable(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "tp.s/sched/sched_switch"]
#[no_mangle]
extern "C" fn handle_tp_non_syscall(_ctx: *const c_void) -> i32 {
    0
}

bpf_object!("GPL");
