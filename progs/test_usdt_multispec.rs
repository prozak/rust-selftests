// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(linkage, used_with_arg)]
#![allow(non_upper_case_globals)]

// translint allow(padding): __bpf_usdt_arg_spec is only ever read out of the
// map value, never built as a literal; its members are the C's for
// `// BTF_C_MEMBERS:`, so no padding members can be added
// translint: allow(padding)

// Direct translation of
// tools/testing/selftests/bpf/progs/test_usdt_multispec.c (bpf-rs-core
// idiom). The C is linked together with test_usdt.c into test_usdt.skel.h
// (Makefile.skel: `test_usdt.skel.h-deps := test_usdt.bpf.o
// test_usdt_multispec.bpf.o`) to validate that usdt.bpf.h can be included
// in several files forming one object: `my_pid` is test_usdt.c's global,
// an extern here (`// BTF_EXTERN:`, scripts/ksym_vars.py mirrors the C
// object's declaration for the static linker). prog_tests/usdt.c's
// multispec subtest fires the 100 inlined usdt_100 call sites and reads
// `usdt_100_called` / `usdt_100_sum` back. NO-ORACLE on its own: the gate
// swaps one object at a time and test_usdt's linked skeleton takes the C
// half.
//
// `BPF_USDT(usdt_100, int x)` fetches its argument with usdt.bpf.h's
// bpf_usdt_arg() before the body runs; that library function is the
// test_usdt.rs reimplementation (a subprogram, as the C's `__weak
// __hidden` one), with __bpf_usdt_spec_id()'s LINUX_HAS_BPF_COOKIE
// `.kconfig` fallback (`// BTF_KCONFIG:`). The two usdt.bpf.h maps are
// the ones libbpf fills when it attaches the program (uprobe_multi_usdt.rs).

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_attach_cookie, bpf_get_current_pid_tgid, bpf_map_lookup_elem, bpf_probe_read_kernel,
    bpf_probe_read_user, sync_fetch_and_add_i32,
};
use bpf_rs_core::maps::{self, BpfMap};

const ESRCH: i32 = 3;
const ENOENT: i32 = 2;
const EINVAL: i32 = 22;

const BPF_USDT_ARG_CONST: u8 = 0;
const BPF_USDT_ARG_REG: u8 = 1;
const BPF_USDT_ARG_REG_DEREF: u8 = 2;
const BPF_USDT_ARG_SIB: u8 = 3;

const BPF_USDT_MAX_ARG_CNT: u64 = 12;
const BPF_USDT_MAX_SPEC_CNT: usize = 256;
const BPF_USDT_MAX_IP_CNT: usize = 4 * BPF_USDT_MAX_SPEC_CNT;

// usdt.bpf.h's `struct __bpf_usdt_arg_spec` (24 bytes, see test_usdt.rs:
// the C's members, the bitfields read out of the u16 at byte 10,
// `// BTF_C_MEMBERS:` for the static linker).
#[allow(non_camel_case_types)]
#[repr(C)]
struct __bpf_usdt_arg_spec {
    val_off: u64,
    arg_type: u8,
    idx_reg_off: u16, // bytes 10-11: idx_reg_off:12 | scale_bitshift:4 << 12
    scale_bitshift: u8, // byte 12 in this layout (the C's __reserved): never read
    __reserved: u8,
    reg_off: i16,
    arg_signed: u8,
    arg_bitshift: i8,
}

// Mirror of `struct __bpf_usdt_spec` (304 bytes).
#[allow(non_camel_case_types)]
#[repr(C)]
struct __bpf_usdt_spec {
    args: [__bpf_usdt_arg_spec; BPF_USDT_MAX_ARG_CNT as usize],
    usdt_cookie: u64,
    arg_cnt: i16,
}

#[used(compiler)]
#[linkage = "weak"]
#[link_section = ".maps"]
#[no_mangle]
static __bpf_usdt_specs: BpfMap<i32, __bpf_usdt_spec, { maps::ARRAY }, BPF_USDT_MAX_SPEC_CNT> =
    BpfMap::new();

#[used(compiler)]
#[linkage = "weak"]
#[link_section = ".maps"]
#[no_mangle]
static __bpf_usdt_ip_to_spec_id: BpfMap<i64, u32, { maps::HASH }, BPF_USDT_MAX_IP_CNT> =
    BpfMap::new();

// BTF_C_MEMBERS: __bpf_usdt_arg_spec
// BTF_KCONFIG: LINUX_HAS_BPF_COOKIE
extern "C" {
    static LINUX_HAS_BPF_COOKIE: u8;
}

/// usdt.bpf.h `__bpf_usdt_spec_id()`
#[inline(always)]
fn bpf_usdt_spec_id(ctx: *const c_void) -> i32 {
    if unsafe { LINUX_HAS_BPF_COOKIE } == 0 {
        // PT_REGS_IP(ctx) = ctx->ip, pt_regs slot 16
        let ip: i64 = unsafe { *((ctx as *const u64).add(16) as *const i64) };
        let spec_id_ptr = bpf_map_lookup_elem(&__bpf_usdt_ip_to_spec_id, &ip) as *const i32;
        return if spec_id_ptr.is_null() { -ESRCH } else { unsafe { *spec_id_ptr } };
    }
    bpf_get_attach_cookie(ctx) as i32
}

/// C's `barrier_var(var)`: `asm volatile("" : "+r"(var))`. Rust rejects an
/// empty asm template with an operand, and a non-empty one makes LLVM's
/// BTF emitter record a line for an instruction that is never emitted (the
/// kernel then rejects the duplicate line_info offset); black_box is the
/// same opaque identity, through a stack slot.
#[inline(always)]
fn barrier_var(var: &mut u64) {
    *var = core::hint::black_box(*var);
}

#[inline(always)]
fn read_pt_regs_u64(ctx: *const c_void, byte_off: i64, val: &mut u64) -> i64 {
    bpf_probe_read_kernel(val, 8, unsafe { (ctx as *const u8).offset(byte_off as isize) } as *const c_void)
}

/// usdt.bpf.h `bpf_usdt_arg()` (test_usdt.rs)
#[inline(never)]
fn bpf_usdt_arg(ctx: *const c_void, mut arg_num: u64, res: &mut i64) -> i32 {
    let mut val: u64 = 0;
    let mut idx: u64 = 0;

    *res = 0;

    let spec_id = bpf_usdt_spec_id(ctx);
    if spec_id < 0 {
        return -ESRCH;
    }
    let spec = bpf_map_lookup_elem(&__bpf_usdt_specs, &spec_id) as *const __bpf_usdt_spec;
    if spec.is_null() {
        return -ESRCH;
    }
    if arg_num >= BPF_USDT_MAX_ARG_CNT {
        return -ENOENT;
    }
    barrier_var(&mut arg_num);
    if arg_num >= unsafe { (*spec).arg_cnt } as i64 as u64 {
        return -ENOENT;
    }
    let arg_spec = unsafe { &*core::ptr::addr_of!((*spec).args).cast::<__bpf_usdt_arg_spec>().add(arg_num as usize) };

    match arg_spec.arg_type {
        BPF_USDT_ARG_CONST => {
            val = arg_spec.val_off;
        }
        BPF_USDT_ARG_REG => {
            let err = read_pt_regs_u64(ctx, arg_spec.reg_off as i64, &mut val);
            if err != 0 {
                return err as i32;
            }
        }
        BPF_USDT_ARG_REG_DEREF => {
            let err = read_pt_regs_u64(ctx, arg_spec.reg_off as i64, &mut val);
            if err != 0 {
                return err as i32;
            }
            let err = bpf_probe_read_user(
                &mut val as *mut u64 as *mut c_void,
                8,
                val.wrapping_add(arg_spec.val_off) as *const c_void,
            );
            if err != 0 {
                return err as i32;
            }
        }
        BPF_USDT_ARG_SIB => {
            let err = read_pt_regs_u64(ctx, arg_spec.reg_off as i64, &mut val);
            if err != 0 {
                return err as i32;
            }
            let idx_reg_off = (arg_spec.idx_reg_off & 0x0FFF) as u64;
            let err = read_pt_regs_u64(ctx, idx_reg_off as i64, &mut idx);
            if err != 0 {
                return err as i32;
            }
            let scale_bitshift = (arg_spec.idx_reg_off >> 12) as u32;
            let err = bpf_probe_read_user(
                &mut val as *mut u64 as *mut c_void,
                8,
                val.wrapping_add(idx << scale_bitshift).wrapping_add(arg_spec.val_off) as *const c_void,
            );
            if err != 0 {
                return err as i32;
            }
        }
        _ => return -EINVAL,
    }

    let shift = (arg_spec.arg_bitshift as u32) & 63;
    val <<= shift;
    val = if arg_spec.arg_signed != 0 { ((val as i64) >> shift) as u64 } else { val >> shift };
    *res = val as i64;
    0
}

// BTF_EXTERN: my_pid
extern "C" {
    static my_pid: i32;
}

#[no_mangle]
static mut usdt_100_called: i32 = 0;
#[no_mangle]
static mut usdt_100_sum: i32 = 0;

/// BPF_USDT(usdt_100, int x)
#[link_section = "usdt//proc/self/exe:test:usdt_100"]
#[no_mangle]
extern "C" fn usdt_100(ctx: *const c_void) -> i32 {
    let mut tmp: i64 = 0;
    bpf_usdt_arg(ctx, 0, &mut tmp);
    let x = tmp as i32;

    if unsafe { my_pid } as i64 as u64 != bpf_get_current_pid_tgid() >> 32 {
        return 0;
    }

    sync_fetch_and_add_i32(addr_of_mut!(usdt_100_called), 1);
    sync_fetch_and_add_i32(addr_of_mut!(usdt_100_sum), x);

    0
}

bpf_object!("GPL");
