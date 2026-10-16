// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_urandom_usdt.c
// (bpf-rs-core idiom).
//
// Each program is a `BPF_USDT(name, iter_num, iter_cnt, buf_sz)` handler from
// <bpf/usdt.bpf.h>: the real entry point takes `struct pt_regs *ctx` (same
// raw register-slot array other kprobe/uprobe-family translations use, see
// test_attach_probe.rs/test_uprobe.rs), and the macro-generated wrapper reads
// each declared argument via `bpf_usdt_arg(ctx, i, &_x)` before calling into
// the body. The body here only ever reads `buf_sz` (arg index 2) -- iter_num
// and iter_cnt are unused in the C source too -- so only that one argument
// is fetched.
//
// `bpf_usdt_arg()` and its `__bpf_usdt_spec_id()` helper are libbpf-internal
// (tools/lib/bpf/usdt.bpf.h): they resolve which `struct __bpf_usdt_spec` a
// given attach site is using (via `bpf_get_attach_cookie()`, assuming the
// running kernel supports BPF cookies -- true for any kernel modern enough to
// run this selftest suite's own test_usdt.c basic-cookie assertions in the
// first place) and then decode the argument's location descriptor. That
// decode logic is reimplemented here directly (`usdt_arg`) against a
// byte-exact re-derivation of libbpf's `struct __bpf_usdt_arg_spec`/
// `struct __bpf_usdt_spec` layout (empirically measured via a host-clang
// probe of the real header: 24-byte arg spec, 304-byte spec, see
// UsdtArgSpec/UsdtSpec below) rather than calling the C helper by name.
//
// bpf_program__attach_usdt() needs usdt.bpf.h's two `SEC(".maps") __weak`
// maps, `__bpf_usdt_specs` and `__bpf_usdt_ip_to_spec_id`, by name with
// global linkage; they are declared below (the keep list keeps a C object's
// weak symbols too, as uprobe_multi_usdt.rs relies on).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_attach_cookie, bpf_get_current_pid_tgid, bpf_map_lookup_elem, bpf_probe_read_kernel,
    bpf_probe_read_user, sync_fetch_and_add_u32,
};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

// Byte-exact mirror of usdt.bpf.h's `struct __bpf_usdt_arg_spec` (24 bytes),
// offsets re-derived via a host-clang probe of the real header (bitfields
// have no Rust equivalent, so the arg_type/idx_reg_off/scale_bitshift/
// reserved bitfield group is decomposed into its measured byte positions):
// val_off@0(u64), arg_type@8, pad@9, idx_reg_off_lo@10, idx_hi|scale@11,
// reserved@12, pad@13, reg_off@14(i16), arg_signed@16, arg_bitshift@17,
// tail pad to 24.
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
    arg_signed: u8,
    arg_bitshift: i8,
}

// Mirror of `struct __bpf_usdt_spec` (304 bytes: 12 * 24-byte args + 8-byte
// cookie + 2-byte arg_cnt, tail-padded to the 8-byte alignment of the array).
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
static mut urand_pid: i32 = 0;

#[no_mangle]
static mut urand_read_without_sema_call_cnt: i32 = 0;
#[no_mangle]
static mut urand_read_without_sema_buf_sz_sum: i32 = 0;

#[no_mangle]
static mut urand_read_with_sema_call_cnt: i32 = 0;
#[no_mangle]
static mut urand_read_with_sema_buf_sz_sum: i32 = 0;

#[no_mangle]
static mut urandlib_read_without_sema_call_cnt: i32 = 0;
#[no_mangle]
static mut urandlib_read_without_sema_buf_sz_sum: i32 = 0;

#[no_mangle]
static mut urandlib_read_with_sema_call_cnt: i32 = 0;
#[no_mangle]
static mut urandlib_read_with_sema_buf_sz_sum: i32 = 0;

fn current_pid() -> i32 {
    (bpf_get_current_pid_tgid() >> 32) as i32
}

fn read_pt_regs_u64(ctx: *const u8, byte_off: i16) -> u64 {
    let mut val: u64 = 0;
    let src = unsafe { ctx.offset(byte_off as isize) } as *const c_void;
    bpf_probe_read_kernel(&mut val, 8, src);
    val
}

// Reimplementation of usdt.bpf.h's `bpf_usdt_arg(ctx, arg_num, &res)` for a
// single caller-chosen arg index, returning 0 on any error (matching the
// `*res = 0` on error, C-side caller here never checks bpf_usdt_arg's return
// code either).
fn usdt_arg(ctx: *const u8, arg_num: usize) -> i64 {
    let spec_id = bpf_get_attach_cookie(ctx as *const c_void) as i32;
    let spec_ptr = bpf_map_lookup_elem(&__bpf_usdt_specs, &spec_id) as *const UsdtSpec;
    if spec_ptr.is_null() {
        return 0;
    }

    let arg_cnt = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*spec_ptr).arg_cnt)) };
    if arg_num >= 12 || (arg_num as i16) >= arg_cnt {
        return 0;
    }
    // Read the fields straight from the map value, as usdt.bpf.h does: a copy
    // of the 24-byte spec on the stack would make reg_off an unbounded
    // scalar to the verifier, which then rejects `ctx + reg_off`.
    let arg_spec = unsafe { &*core::ptr::addr_of!((*spec_ptr).args[arg_num]) };

    let mut val: u64 = match arg_spec.arg_type {
        0 => arg_spec.val_off, // BPF_USDT_ARG_CONST
        1 => read_pt_regs_u64(ctx, arg_spec.reg_off), // BPF_USDT_ARG_REG
        2 => {
            // BPF_USDT_ARG_REG_DEREF
            let base = read_pt_regs_u64(ctx, arg_spec.reg_off);
            let mut v: u64 = 0;
            let src = base.wrapping_add(arg_spec.val_off) as *const c_void;
            bpf_probe_read_user(&mut v as *mut u64 as *mut c_void, 8, src);
            v
        }
        3 => {
            // BPF_USDT_ARG_SIB
            let base = read_pt_regs_u64(ctx, arg_spec.reg_off);
            let idx_reg_off = (arg_spec.idx_reg_off_lo as i16)
                | (((arg_spec.idx_hi_scale & 0x0F) as i16) << 8);
            let idx = read_pt_regs_u64(ctx, idx_reg_off);
            let scale = ((arg_spec.idx_hi_scale >> 4) & 0x0F) as u32;
            let addr = base.wrapping_add(idx << scale).wrapping_add(arg_spec.val_off);
            let mut v: u64 = 0;
            bpf_probe_read_user(&mut v as *mut u64 as *mut c_void, 8, addr as *const c_void);
            v
        }
        _ => return 0,
    };

    let shift = (arg_spec.arg_bitshift as u32) & 63;
    val <<= shift;
    val = if arg_spec.arg_signed != 0 {
        ((val as i64) >> shift) as u64
    } else {
        val >> shift
    };
    val as i64
}

#[link_section = "usdt/./urandom_read:urand:read_without_sema"]
#[no_mangle]
extern "C" fn urand_read_without_sema(ctx: *const u64) -> i32 {
    if unsafe { urand_pid } != current_pid() {
        return 0;
    }

    let buf_sz = usdt_arg(ctx as *const u8, 2) as i32;
    sync_fetch_and_add_u32(
        core::ptr::addr_of_mut!(urand_read_without_sema_call_cnt) as *mut u32,
        1,
    );
    sync_fetch_and_add_u32(
        core::ptr::addr_of_mut!(urand_read_without_sema_buf_sz_sum) as *mut u32,
        buf_sz as u32,
    );
    0
}

#[link_section = "usdt/./urandom_read:urand:read_with_sema"]
#[no_mangle]
extern "C" fn urand_read_with_sema(ctx: *const u64) -> i32 {
    if unsafe { urand_pid } != current_pid() {
        return 0;
    }

    let buf_sz = usdt_arg(ctx as *const u8, 2) as i32;
    sync_fetch_and_add_u32(
        core::ptr::addr_of_mut!(urand_read_with_sema_call_cnt) as *mut u32,
        1,
    );
    sync_fetch_and_add_u32(
        core::ptr::addr_of_mut!(urand_read_with_sema_buf_sz_sum) as *mut u32,
        buf_sz as u32,
    );
    0
}

#[link_section = "usdt/./liburandom_read.so:urandlib:read_without_sema"]
#[no_mangle]
extern "C" fn urandlib_read_without_sema(ctx: *const u64) -> i32 {
    if unsafe { urand_pid } != current_pid() {
        return 0;
    }

    let buf_sz = usdt_arg(ctx as *const u8, 2) as i32;
    sync_fetch_and_add_u32(
        core::ptr::addr_of_mut!(urandlib_read_without_sema_call_cnt) as *mut u32,
        1,
    );
    sync_fetch_and_add_u32(
        core::ptr::addr_of_mut!(urandlib_read_without_sema_buf_sz_sum) as *mut u32,
        buf_sz as u32,
    );
    0
}

#[link_section = "usdt/./liburandom_read.so:urandlib:read_with_sema"]
#[no_mangle]
extern "C" fn urandlib_read_with_sema(ctx: *const u64) -> i32 {
    if unsafe { urand_pid } != current_pid() {
        return 0;
    }

    let buf_sz = usdt_arg(ctx as *const u8, 2) as i32;
    sync_fetch_and_add_u32(
        core::ptr::addr_of_mut!(urandlib_read_with_sema_call_cnt) as *mut u32,
        1,
    );
    sync_fetch_and_add_u32(
        core::ptr::addr_of_mut!(urandlib_read_with_sema_buf_sz_sum) as *mut u32,
        buf_sz as u32,
    );
    0
}

bpf_object!("GPL");
