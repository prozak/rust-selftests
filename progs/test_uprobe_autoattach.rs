#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_uprobe_autoattach.c
// (bpf-rs-core idiom).
//
// BPF_UPROBE/BPF_URETPROBE ctx is `struct pt_regs *`, the raw register-slot
// array documented in test_uprobe.rs/test_probe_user.rs (x86_64 kernel
// `struct pt_regs`, 21 `unsigned long` slots: r15,r14,r13,r12,bp,bx,r11,r10,
// r9,r8,ax,cx,dx,si,di,orig_ax,ip,cs,flags,sp,ss). PT_REGS_PARMn_CORE on
// x86_64 maps arg1..arg6 to di,si,dx,cx,r8,r9 respectively; PT_REGS_RC_CORE
// is ax. FUNC_REG_ARG_CNT is 6 on x86_64, so the C source's arg7/arg8 (and
// a[6]/a[7]) are compiled out and not translated here.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use core::ffi::c_void;

const SLOT_R9: usize = 8;
const SLOT_R8: usize = 9;
const SLOT_AX: usize = 10;
const SLOT_CX: usize = 11;
const SLOT_DX: usize = 12;
const SLOT_SI: usize = 13;
const SLOT_DI: usize = 14;

#[no_mangle]
static mut uprobe_byname_parm1: i32 = 0;
#[no_mangle]
static mut uprobe_byname_ran: i32 = 0;
#[no_mangle]
static mut uretprobe_byname_rc: i32 = 0;
#[no_mangle]
static mut uretprobe_byname_ret: i32 = 0;
#[no_mangle]
static mut uretprobe_byname_ran: i32 = 0;
#[no_mangle]
static mut uprobe_byname2_parm1: u64 = 0;
#[no_mangle]
static mut uprobe_byname2_ran: i32 = 0;
#[no_mangle]
static mut uretprobe_byname2_rc: u64 = 0;
#[no_mangle]
static mut uretprobe_byname2_ran: i32 = 0;

#[no_mangle]
static mut test_pid: i32 = 0;

#[no_mangle]
static mut a: [i32; 8] = [0; 8];

fn current_pid() -> i32 {
    (bpf_get_current_pid_tgid() >> 32) as i32
}

/* This program cannot auto-attach, but that should not stop other
 * programs from attaching.
 */
#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn handle_uprobe_noautoattach(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "uprobe//proc/self/exe:autoattach_trigger_func"]
#[no_mangle]
extern "C" fn handle_uprobe_byname(ctx: *const u64) -> i32 {
    let di = unsafe { *ctx.add(SLOT_DI) };
    let si = unsafe { *ctx.add(SLOT_SI) };
    let dx = unsafe { *ctx.add(SLOT_DX) };
    let cx = unsafe { *ctx.add(SLOT_CX) };
    let r8 = unsafe { *ctx.add(SLOT_R8) };
    let r9 = unsafe { *ctx.add(SLOT_R9) };

    unsafe {
        uprobe_byname_parm1 = di as i32;
        uprobe_byname_ran = 1;

        a[0] = di as i32;
        a[1] = si as i32;
        a[2] = dx as i32;
        a[3] = cx as i32;
        a[4] = r8 as i32;
        a[5] = r9 as i32;
    }

    0
}

#[link_section = "uretprobe//proc/self/exe:autoattach_trigger_func"]
#[no_mangle]
extern "C" fn handle_uretprobe_byname(ctx: *const u64) -> i32 {
    let rc = unsafe { *ctx.add(SLOT_AX) } as i32;

    unsafe {
        uretprobe_byname_rc = rc;
        uretprobe_byname_ret = rc;
        uretprobe_byname_ran = 2;
    }

    0
}

#[link_section = "uprobe/libc.so.6:fopen"]
#[no_mangle]
extern "C" fn handle_uprobe_byname2(ctx: *const u64) -> i32 {
    let pid = current_pid();

    /* ignore irrelevant invocations */
    if unsafe { test_pid } != pid {
        return 0;
    }

    let pathname = unsafe { *ctx.add(SLOT_DI) };
    unsafe {
        uprobe_byname2_parm1 = pathname;
        uprobe_byname2_ran = 3;
    }
    0
}

#[link_section = "uretprobe/libc.so.6:fopen"]
#[no_mangle]
extern "C" fn handle_uretprobe_byname2(ctx: *const u64) -> i32 {
    let pid = current_pid();

    /* ignore irrelevant invocations */
    if unsafe { test_pid } != pid {
        return 0;
    }

    let ret = unsafe { *ctx.add(SLOT_AX) };
    unsafe {
        uretprobe_byname2_rc = ret;
        uretprobe_byname2_ran = 4;
    }
    0
}

bpf_object!("GPL");
