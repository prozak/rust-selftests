// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// translint allow(kconfig): the C object's LINUX_HAS_BPF_COOKIE .kconfig
// extern is read only by usdt.bpf.h's library functions (bpf_usdt_arg & co.)
// in .text, which none of its programs call; the translation has no such dead
// code to read it from
// translint: allow(kconfig)
#![feature(linkage, used_with_arg)]
#![allow(non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/uprobe_multi.c
// (bpf-rs-core idiom). prog_tests/uprobe_multi_test.c and bpf_cookie.c
// attach the uprobe.multi programs to uprobe_multi_func_1..3 of the test
// binary, store the functions' addresses in the *_addr globals, and count
// in the *_result globals how often each probe fired at the right address
// (with the right cookie when test_cookie is set); the sleepable variants
// also copy a user string through user_ptr. The usdt programs record the
// pid filter's effect. The two usdt.bpf.h maps are the ones libbpf fills
// when it attaches a "usdt" program (uprobe_multi_usdt.rs). `user_ptr` is
// the C's `void *`.
// BTF_C_VOID: c_void

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_copy_from_user, bpf_get_attach_cookie, bpf_get_current_pid_tgid, bpf_get_func_ip,
    bpf_strncmp,
};
use bpf_rs_core::maps::{self, BpfMap};

// Pinned usdt.bpf.h ABI (see uprobe_multi_usdt.rs).
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
static mut uprobe_multi_func_1_addr: u64 = 0;
#[no_mangle]
static mut uprobe_multi_func_2_addr: u64 = 0;
#[no_mangle]
static mut uprobe_multi_func_3_addr: u64 = 0;

#[no_mangle]
static mut uprobe_multi_func_1_result: u64 = 0;
#[no_mangle]
static mut uprobe_multi_func_2_result: u64 = 0;
#[no_mangle]
static mut uprobe_multi_func_3_result: u64 = 0;

#[no_mangle]
static mut uretprobe_multi_func_1_result: u64 = 0;
#[no_mangle]
static mut uretprobe_multi_func_2_result: u64 = 0;
#[no_mangle]
static mut uretprobe_multi_func_3_result: u64 = 0;

#[no_mangle]
static mut uprobe_multi_sleep_result: u64 = 0;

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut child_pid: i32 = 0;
#[no_mangle]
static mut child_tid: i32 = 0;
#[no_mangle]
static mut child_pid_usdt: i32 = 0;
#[no_mangle]
static mut child_tid_usdt: i32 = 0;

#[no_mangle]
static mut expect_pid: i32 = 0;
// write-only C bools
#[no_mangle]
static mut bad_pid_seen: bool = false;
#[no_mangle]
static mut bad_pid_seen_usdt: bool = false;

// C bool, branched on: u8, and every site of the C object tests it with
// `!= 1` (translint bool-global), so `test_cookie` is `== 1` here and
// `!test_cookie` is `!= 1`
#[no_mangle]
static mut test_cookie: u8 = 0;
#[no_mangle]
static mut user_ptr: *mut c_void = core::ptr::null_mut();

/* the literal is in a map */
#[link_section = ".rodata.str1.1"]
static TEST_DATA: [u8; 10] = *b"test_data\0";

#[inline(always)]
fn verify_sleepable_user_copy() -> bool {
    let mut data = [0u8; 9];

    bpf_copy_from_user(data.as_mut_ptr() as *mut c_void, 9, unsafe { user_ptr });
    bpf_strncmp(data.as_ptr() as *const c_void, 9, TEST_DATA.as_ptr() as *const c_void) == 0
}

// the C object keeps uprobe_multi_check as a local subprogram
#[inline(never)]
#[export_name = "uprobe_multi_check"]
extern "C" fn uprobe_multi_check(ctx: *const c_void, is_return: bool, is_sleep: bool) {
    unsafe {
        let cur_pid_tgid = bpf_get_current_pid_tgid();

        let cur_pid = (cur_pid_tgid >> 32) as u32;
        if pid != 0 && cur_pid != pid as u32 {
            return;
        }

        if expect_pid != 0 && cur_pid != expect_pid as u32 {
            bad_pid_seen = true;
        }

        child_pid = (cur_pid_tgid >> 32) as i32;
        child_tid = cur_pid_tgid as i32;

        let cookie: u64 = if test_cookie == 1 { bpf_get_attach_cookie(ctx) } else { 0 };
        let addr: u64 = bpf_get_func_ip(ctx);

        // SET(__var, __addr, __cookie)
        macro_rules! set {
            ($var:ident, $addr:ident, $cookie:expr) => {
                if addr == $addr && (test_cookie != 1 || cookie == $cookie) {
                    *addr_of_mut!($var) += 1;
                }
            };
        }

        if is_return {
            set!(uretprobe_multi_func_1_result, uprobe_multi_func_1_addr, 2);
            set!(uretprobe_multi_func_2_result, uprobe_multi_func_2_addr, 3);
            set!(uretprobe_multi_func_3_result, uprobe_multi_func_3_addr, 1);
        } else {
            set!(uprobe_multi_func_1_result, uprobe_multi_func_1_addr, 3);
            set!(uprobe_multi_func_2_result, uprobe_multi_func_2_addr, 1);
            set!(uprobe_multi_func_3_result, uprobe_multi_func_3_addr, 2);
        }

        if is_sleep && verify_sleepable_user_copy() {
            uprobe_multi_sleep_result += 1;
        }
    }
}

#[link_section = "uprobe.multi//proc/self/exe:uprobe_multi_func_*"]
#[no_mangle]
extern "C" fn uprobe(ctx: *const c_void) -> i32 {
    uprobe_multi_check(ctx, false, false);
    0
}

#[link_section = "uretprobe.multi//proc/self/exe:uprobe_multi_func_*"]
#[no_mangle]
extern "C" fn uretprobe(ctx: *const c_void) -> i32 {
    uprobe_multi_check(ctx, true, false);
    0
}

#[link_section = "uprobe.multi.s//proc/self/exe:uprobe_multi_func_*"]
#[no_mangle]
extern "C" fn uprobe_sleep(ctx: *const c_void) -> i32 {
    uprobe_multi_check(ctx, false, true);
    0
}

#[link_section = "uretprobe.multi.s//proc/self/exe:uprobe_multi_func_*"]
#[no_mangle]
extern "C" fn uretprobe_sleep(ctx: *const c_void) -> i32 {
    uprobe_multi_check(ctx, true, true);
    0
}

#[link_section = "uprobe.multi//proc/self/exe:uprobe_multi_func_*"]
#[no_mangle]
extern "C" fn uprobe_extra(_ctx: *const c_void) -> i32 {
    /* we need this one just to mix PID-filtered and global uprobes */
    0
}

#[link_section = "usdt"]
#[no_mangle]
extern "C" fn usdt_pid(_ctx: *const c_void) -> i32 {
    unsafe {
        let cur_pid_tgid = bpf_get_current_pid_tgid();

        let cur_pid = (cur_pid_tgid >> 32) as u32;
        if pid != 0 && cur_pid != pid as u32 {
            return 0;
        }

        if expect_pid != 0 && cur_pid != expect_pid as u32 {
            bad_pid_seen_usdt = true;
        }

        child_pid_usdt = (cur_pid_tgid >> 32) as i32;
        child_tid_usdt = cur_pid_tgid as i32;
    }

    0
}

#[link_section = "usdt"]
#[no_mangle]
extern "C" fn usdt_extra(_ctx: *const c_void) -> i32 {
    /* we need this one just to mix PID-filtered and global USDT probes */
    0
}

bpf_object!("GPL");
