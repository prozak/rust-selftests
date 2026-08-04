#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_attach_cookie, bpf_get_current_pid_tgid};
use core::ffi::c_void;
use core::ptr::addr_of_mut;

const EPERM: i32 = 1;

#[no_mangle]
static mut my_tid: i32 = 0;

#[no_mangle]
static mut kprobe_res: u64 = 0;
#[no_mangle]
static mut kprobe_multi_res: u64 = 0;
#[no_mangle]
static mut kretprobe_res: u64 = 0;
#[no_mangle]
static mut uprobe_res: u64 = 0;
#[no_mangle]
static mut uretprobe_res: u64 = 0;
#[no_mangle]
static mut tp_res: u64 = 0;
#[no_mangle]
static mut pe_res: u64 = 0;
#[no_mangle]
static mut raw_tp_res: u64 = 0;
#[no_mangle]
static mut tp_btf_res: u64 = 0;
#[no_mangle]
static mut fentry_res: u64 = 0;
#[no_mangle]
static mut fexit_res: u64 = 0;
#[no_mangle]
static mut fmod_ret_res: u64 = 0;
#[no_mangle]
static mut lsm_res: u64 = 0;

#[inline(always)]
fn update(ctx: *const c_void, res: *mut u64) {
    let tid = bpf_get_current_pid_tgid() as u32;
    if unsafe { my_tid as u32 } != tid {
        return;
    }
    let cookie = bpf_get_attach_cookie(ctx);
    unsafe { *res |= cookie };
}

#[link_section = "kprobe"]
#[no_mangle]
extern "C" fn handle_kprobe(ctx: *const c_void) -> i32 {
    update(ctx, addr_of_mut!(kprobe_res));
    0
}

#[link_section = "kretprobe"]
#[no_mangle]
extern "C" fn handle_kretprobe(ctx: *const c_void) -> i32 {
    update(ctx, addr_of_mut!(kretprobe_res));
    0
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn handle_uprobe(ctx: *const c_void) -> i32 {
    update(ctx, addr_of_mut!(uprobe_res));
    0
}

#[link_section = "uretprobe"]
#[no_mangle]
extern "C" fn handle_uretprobe(ctx: *const c_void) -> i32 {
    update(ctx, addr_of_mut!(uretprobe_res));
    0
}

#[link_section = "tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn handle_tp1(ctx: *const c_void) -> i32 {
    update(ctx, addr_of_mut!(tp_res));
    0
}

#[link_section = "tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn handle_tp2(ctx: *const c_void) -> i32 {
    update(ctx, addr_of_mut!(tp_res));
    0
}

#[link_section = "tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn handle_tp3(ctx: *const c_void) -> i32 {
    update(ctx, addr_of_mut!(tp_res));
    1
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn handle_pe(ctx: *const c_void) -> i32 {
    update(ctx, addr_of_mut!(pe_res));
    0
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handle_raw_tp(ctx: *const c_void) -> i32 {
    update(ctx, addr_of_mut!(raw_tp_res));
    0
}

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn handle_tp_btf(ctx: *const u64) -> i32 {
    update(ctx as *const c_void, addr_of_mut!(tp_btf_res));
    0
}

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn fentry_test1(ctx: *const u64) -> i32 {
    update(ctx as *const c_void, addr_of_mut!(fentry_res));
    0
}

#[link_section = "fexit/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn fexit_test1(ctx: *const u64) -> i32 {
    update(ctx as *const c_void, addr_of_mut!(fexit_res));
    0
}

#[link_section = "fmod_ret/bpf_modify_return_test"]
#[no_mangle]
extern "C" fn fmod_ret_test(ctx: *const u64) -> i32 {
    update(ctx as *const c_void, addr_of_mut!(fmod_ret_res));
    1234
}

#[link_section = "lsm/file_mprotect"]
#[no_mangle]
extern "C" fn test_int_hook(ctx: *const u64) -> i32 {
    let ret = unsafe { *ctx.add(3) } as i32;

    let tid = bpf_get_current_pid_tgid() as u32;
    if unsafe { my_tid as u32 } != tid {
        return ret;
    }
    update(ctx as *const c_void, addr_of_mut!(lsm_res));
    -EPERM
}

bpf_object!("GPL");
