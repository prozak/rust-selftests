// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// translint allow(kconfig): the C object's LINUX_HAS_BPF_COOKIE .kconfig
// extern is read only by usdt.bpf.h's library functions (bpf_usdt_arg & co.)
// in .text; BPF_USDT(usdt_probe) takes no usdt args and calls none of them
// translint: allow(kconfig)

// Direct translation of tools/testing/selftests/bpf/progs/uretprobe_stack.c
// (bpf-rs-core idiom). Each uprobe/uretprobe/USDT program captures the user
// stack into its own bss array and records the length; prog_tests/
// uretprobe_stack.c validates the frames against its target_1..4 chain.
//
// bpf_program__attach_usdt() needs usdt.bpf.h's two `SEC(".maps") __weak`
// maps, `__bpf_usdt_specs` and `__bpf_usdt_ip_to_spec_id`, by name
// (test_urandom_usdt.rs); the program itself reads no USDT argument, so
// none of the header's helpers (or its LINUX_HAS_BPF_COOKIE __kconfig) is
// needed. The `static bool recur` locals of the C are the object's
// `____uprobe_1.recur`/`____uretprobe_1.recur` bss symbols (u8 here: the
// object compares the byte with 0, as the C object does).

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_stack;
use bpf_rs_core::maps::{self, BpfMap};

const BPF_F_USER_STACK: u64 = 1 << 8;

// Mirror of usdt.bpf.h's `struct __bpf_usdt_arg_spec` (24 bytes) and
// `struct __bpf_usdt_spec` (304 bytes), as test_urandom_usdt.rs lays them out.
#[repr(C)]
#[derive(Clone, Copy)]
struct UsdtArgSpec {
    val_off: u64,
    arg_type: u8,
    _pad0: u8,
    idx_reg_off_lo: u8,
    idx_hi_scale: u8,
    reserved: u8,
    _pad1: u8,
    reg_off: i16,
    arg_signed: bool,
    arg_bitshift: i8,
    _pad2: [u8; 6],
}

#[repr(C)]
struct UsdtSpec {
    args: [UsdtArgSpec; 12],
    usdt_cookie: u64,
    arg_cnt: i16,
}

const BPF_USDT_MAX_SPEC_CNT: usize = 256;
const BPF_USDT_MAX_IP_CNT: usize = 4 * BPF_USDT_MAX_SPEC_CNT;

#[link_section = ".maps"]
#[no_mangle]
static __bpf_usdt_specs: BpfMap<i32, UsdtSpec, { maps::ARRAY }, BPF_USDT_MAX_SPEC_CNT> =
    BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static __bpf_usdt_ip_to_spec_id: BpfMap<i64, u32, { maps::HASH }, BPF_USDT_MAX_IP_CNT> =
    BpfMap::new();

#[no_mangle]
static mut entry_stack1: [u64; 32] = [0; 32];
#[no_mangle]
static mut exit_stack1: [u64; 32] = [0; 32];
#[no_mangle]
static mut entry_stack1_recur: [u64; 32] = [0; 32];
#[no_mangle]
static mut exit_stack1_recur: [u64; 32] = [0; 32];
#[no_mangle]
static mut entry_stack2: [u64; 32] = [0; 32];
#[no_mangle]
static mut entry_stack3: [u64; 32] = [0; 32];
#[no_mangle]
static mut entry_stack4: [u64; 32] = [0; 32];
#[no_mangle]
static mut exit_stack4: [u64; 32] = [0; 32];
#[no_mangle]
static mut usdt_stack: [u64; 32] = [0; 32];

#[no_mangle]
static mut entry1_len: i32 = 0;
#[no_mangle]
static mut exit1_len: i32 = 0;
#[no_mangle]
static mut entry1_recur_len: i32 = 0;
#[no_mangle]
static mut exit1_recur_len: i32 = 0;
#[no_mangle]
static mut entry2_len: i32 = 0;
#[no_mangle]
static mut exit2_len: i32 = 0;
#[no_mangle]
static mut entry3_len: i32 = 0;
#[no_mangle]
static mut exit3_len: i32 = 0;
#[no_mangle]
static mut entry4_len: i32 = 0;
#[no_mangle]
static mut exit4_len: i32 = 0;
#[no_mangle]
static mut usdt_len: i32 = 0;

const SZ: u32 = 32 * 8; // sizeof(usdt_stack)

#[inline(always)]
fn user_stack(ctx: *const c_void, buf: *mut [u64; 32]) -> i32 {
    bpf_get_stack(ctx, buf as *mut c_void, SZ, BPF_F_USER_STACK) as i32
}

/* target_1 is recursive with depth of 2, so we capture two separate
 * stack traces, depending on which occurrence it is
 */
#[export_name = "____uprobe_1.recur"]
static mut uprobe_1_recur: u8 = 0;

#[link_section = "uprobe//proc/self/exe:target_1"]
#[no_mangle]
extern "C" fn uprobe_1(ctx: *const c_void) -> i32 {
    unsafe {
        if uprobe_1_recur == 0 {
            entry1_len = user_stack(ctx, core::ptr::addr_of_mut!(entry_stack1));
        } else {
            entry1_recur_len = user_stack(ctx, core::ptr::addr_of_mut!(entry_stack1_recur));
        }

        uprobe_1_recur = 1;
    }
    0
}

/* see above, target_1 is recursive */
#[export_name = "____uretprobe_1.recur"]
static mut uretprobe_1_recur: u8 = 0;

#[link_section = "uretprobe//proc/self/exe:target_1"]
#[no_mangle]
extern "C" fn uretprobe_1(ctx: *const c_void) -> i32 {
    unsafe {
        /* NOTE: order of returns is reversed to order of entries */
        if uretprobe_1_recur == 0 {
            exit1_recur_len = user_stack(ctx, core::ptr::addr_of_mut!(exit_stack1_recur));
        } else {
            exit1_len = user_stack(ctx, core::ptr::addr_of_mut!(exit_stack1));
        }

        uretprobe_1_recur = 1;
    }
    0
}

#[link_section = "uprobe//proc/self/exe:target_2"]
#[no_mangle]
extern "C" fn uprobe_2(ctx: *const c_void) -> i32 {
    unsafe { entry2_len = user_stack(ctx, core::ptr::addr_of_mut!(entry_stack2)) };
    0
}

/* no uretprobe for target_2 */

#[link_section = "uprobe//proc/self/exe:target_3"]
#[no_mangle]
extern "C" fn uprobe_3(ctx: *const c_void) -> i32 {
    unsafe { entry3_len = user_stack(ctx, core::ptr::addr_of_mut!(entry_stack3)) };
    0
}

/* no uretprobe for target_3 */

#[link_section = "uprobe//proc/self/exe:target_4"]
#[no_mangle]
extern "C" fn uprobe_4(ctx: *const c_void) -> i32 {
    unsafe { entry4_len = user_stack(ctx, core::ptr::addr_of_mut!(entry_stack4)) };
    0
}

#[link_section = "uretprobe//proc/self/exe:target_4"]
#[no_mangle]
extern "C" fn uretprobe_4(ctx: *const c_void) -> i32 {
    unsafe { exit4_len = user_stack(ctx, core::ptr::addr_of_mut!(exit_stack4)) };
    0
}

#[link_section = "usdt//proc/self/exe:uretprobe_stack:target"]
#[no_mangle]
extern "C" fn usdt_probe(ctx: *const c_void) -> i32 {
    unsafe { usdt_len = user_stack(ctx, core::ptr::addr_of_mut!(usdt_stack)) };
    0
}

bpf_object!("GPL");
