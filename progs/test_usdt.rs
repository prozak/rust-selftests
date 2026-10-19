// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(linkage, used_with_arg)]
#![allow(non_upper_case_globals)]

// translint allow(padding): __bpf_usdt_arg_spec is only ever read out of the
// map value, never built as a literal; its members are the C's for
// `// BTF_C_MEMBERS:`, so no padding members can be added
// translint: allow(padding)

// Direct translation of tools/testing/selftests/bpf/progs/test_usdt.c
// (bpf-rs-core idiom). prog_tests/usdt.c attaches the programs to its own
// USDT probes (test:usdt0/usdt3/usdt12/usdt_sib and the optimized_attach
// ones), fires them and reads the `*_called`, `*_cookie`, `*_arg_cnt`,
// `*_args`/`*_arg_rets`/`*_arg_sizes` globals back. The x86-only
// `usdt_executed` and `usdt_check_arg` programs are in the C object (built
// for x86_64), so they are here too.
//
// usdt.bpf.h's library (bpf_usdt_arg, bpf_usdt_arg_cnt, bpf_usdt_cookie,
// bpf_usdt_arg_size) is reimplemented below against the byte-exact
// `struct __bpf_usdt_arg_spec` / `struct __bpf_usdt_spec` layout
// (test_urandom_usdt.rs), with the C's return codes: the programs store
// them; the three `__weak __hidden` ones are subprograms as in the C
// object (`#[inline(never)]`), bpf_usdt_arg_size and __bpf_usdt_spec_id
// are `static __always_inline`. `__bpf_usdt_spec_id()` reads
// LINUX_HAS_BPF_COOKIE, the header's
// `__kconfig` extern (`// BTF_KCONFIG:` below, scripts/ksym_vars.py
// mirrors the C object's declaration): without BPF cookies the spec id is
// looked up by the probe's ip (pt_regs slot 16) in
// `__bpf_usdt_ip_to_spec_id`. The C's `barrier_var(arg_num)` between the
// two bound checks is a black_box pass of the value (an empty inline asm
// with an operand is not expressible in Rust). The two usdt.bpf.h maps are the ones libbpf fills when it
// attaches a "usdt" program (uprobe_multi_usdt.rs).
//
// BPF_USDT(name, args...) fetches every declared argument with
// bpf_usdt_arg() before the body runs (the macro passes them as call
// arguments), so usdt12 and usdt_check_arg fetch first and test the pid
// after, as the C object does. The `long _x` temporaries narrow to each
// parameter's declared type (int, unsigned, short, signed char) and widen
// again into the u64 arrays.

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_attach_cookie, bpf_get_current_pid_tgid, bpf_get_prandom_u32, bpf_map_lookup_elem,
    bpf_probe_read_kernel, bpf_probe_read_user, sync_fetch_and_add_i32,
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

// usdt.bpf.h's `struct __bpf_usdt_arg_spec` (24 bytes): val_off@0,
// arg_type@8 (an 8-bit enum bitfield), idx_reg_off@10 (12 bits) with
// scale_bitshift in the high nibble of byte 11, __reserved@12, reg_off@14,
// arg_signed@16, arg_bitshift@17, tail pad. Rust has no bitfields: the
// members are the C's, in the C's order, and the code reads the two
// bitfields out of the u16 at byte 10; `// BTF_C_MEMBERS:` gives the
// struct the C object's member BTF (the bitfield offsets and the enum), so
// the static linker matches the weak map definitions of the two objects.
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

/// usdt.bpf.h `bpf_usdt_arg_cnt()`: number of USDT arguments defined for
/// the currently traced USDT
#[inline(never)]
fn bpf_usdt_arg_cnt(ctx: *const c_void) -> i32 {
    let spec_id = bpf_usdt_spec_id(ctx);
    if spec_id < 0 {
        return -ESRCH;
    }
    let spec = bpf_map_lookup_elem(&__bpf_usdt_specs, &spec_id) as *const __bpf_usdt_spec;
    if spec.is_null() {
        return -ESRCH;
    }
    unsafe { (*spec).arg_cnt as i32 }
}

/// usdt.bpf.h `bpf_usdt_arg_size()`: size in bytes of the #arg_num
/// (zero-indexed) USDT argument, negative error if not found
#[inline(always)]
fn bpf_usdt_arg_size(ctx: *const c_void, mut arg_num: u64) -> i32 {
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
    /* arg_spec->arg_bitshift = 64 - arg_sz * 8
     * so: arg_sz = (64 - arg_spec->arg_bitshift) / 8
     */
    ((64 - arg_spec.arg_bitshift as i32) as u32 / 8) as i32
}

#[inline(always)]
fn read_pt_regs_u64(ctx: *const c_void, byte_off: i64, val: &mut u64) -> i64 {
    bpf_probe_read_kernel(val, 8, unsafe { (ctx as *const u8).offset(byte_off as isize) } as *const c_void)
}

/// usdt.bpf.h `bpf_usdt_arg()`: fetch USDT argument #arg_num (zero-indexed)
/// into *res; 0 on success, negative error otherwise, *res zero on error
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
    // Read the fields straight from the map value, as usdt.bpf.h does (a
    // stack copy would make reg_off an unbounded scalar to the verifier).
    let arg_spec = unsafe { &*core::ptr::addr_of!((*spec).args).cast::<__bpf_usdt_arg_spec>().add(arg_num as usize) };

    match arg_spec.arg_type {
        BPF_USDT_ARG_CONST => {
            /* Arg is just a constant ("-4@$-9" in USDT arg spec).
             * value is recorded in arg_spec->val_off directly.
             */
            val = arg_spec.val_off;
        }
        BPF_USDT_ARG_REG => {
            /* Arg is in a register (e.g, "8@%rax" in USDT arg spec),
             * so we read the contents of that register directly from
             * struct pt_regs. To keep things simple user-space parts
             * record offsetof(struct pt_regs, <regname>) in arg_spec->reg_off.
             */
            let err = read_pt_regs_u64(ctx, arg_spec.reg_off as i64, &mut val);
            if err != 0 {
                return err as i32;
            }
        }
        BPF_USDT_ARG_REG_DEREF => {
            /* Arg is in memory addressed by register, plus some offset
             * (e.g., "-4@-1204(%rbp)" in USDT arg spec). Register is
             * identified like with BPF_USDT_ARG_REG case, and the offset
             * is in arg_spec->val_off. We first fetch register contents
             * from pt_regs, then do another user-space probe read to
             * fetch argument value itself.
             */
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
            /* Arg is in memory addressed by SIB (Scale-Index-Base) mode
             * (e.g., "-1@-96(%rbp,%rax,8)" in USDT arg spec). We first
             * fetch the base register contents and the index register
             * contents from pt_regs. Then we calculate the final address
             * as base + (index * scale) + offset, and do a user-space
             * probe read to fetch the argument value.
             */
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

    /* cast arg from 1, 2, or 4 bytes to final 8 byte size clearing
     * necessary upper arg_bitshift bits, with sign extension if argument
     * is signed
     */
    let shift = (arg_spec.arg_bitshift as u32) & 63;
    val <<= shift;
    val = if arg_spec.arg_signed != 0 { ((val as i64) >> shift) as u64 } else { val >> shift };
    *res = val as i64;
    0
}

/// usdt.bpf.h `bpf_usdt_cookie()`: the user-specified cookie provided
/// during attach
#[inline(never)]
fn bpf_usdt_cookie(ctx: *const c_void) -> i64 {
    let spec_id = bpf_usdt_spec_id(ctx);
    if spec_id < 0 {
        return 0;
    }
    let spec = bpf_map_lookup_elem(&__bpf_usdt_specs, &spec_id) as *const __bpf_usdt_spec;
    if spec.is_null() {
        return 0;
    }
    unsafe { (*spec).usdt_cookie as i64 }
}

#[inline(always)]
fn current_tgid() -> u64 {
    bpf_get_current_pid_tgid() >> 32
}

#[no_mangle]
static mut my_pid: i32 = 0;

#[no_mangle]
static mut usdt0_called: i32 = 0;
#[no_mangle]
static mut usdt0_cookie: u64 = 0;
#[no_mangle]
static mut usdt0_arg_cnt: i32 = 0;
#[no_mangle]
static mut usdt0_arg_ret: i32 = 0;
#[no_mangle]
static mut usdt0_arg_size: i32 = 0;

#[link_section = "usdt"]
#[no_mangle]
extern "C" fn usdt0(ctx: *const c_void) -> i32 {
    let mut tmp: i64 = 0;

    if unsafe { my_pid } as i64 as u64 != current_tgid() {
        return 0;
    }

    sync_fetch_and_add_i32(addr_of_mut!(usdt0_called), 1);

    unsafe {
        usdt0_cookie = bpf_usdt_cookie(ctx) as u64;
        usdt0_arg_cnt = bpf_usdt_arg_cnt(ctx);
        /* should return -ENOENT for any arg_num */
        usdt0_arg_ret = bpf_usdt_arg(ctx, bpf_get_prandom_u32() as u64, &mut tmp);
        usdt0_arg_size = bpf_usdt_arg_size(ctx, bpf_get_prandom_u32() as u64);
    }
    0
}

#[no_mangle]
static mut usdt3_called: i32 = 0;
#[no_mangle]
static mut usdt3_cookie: u64 = 0;
#[no_mangle]
static mut usdt3_arg_cnt: i32 = 0;
#[no_mangle]
static mut usdt3_arg_rets: [i32; 3] = [0; 3];
#[no_mangle]
static mut usdt3_args: [u64; 3] = [0; 3];
#[no_mangle]
static mut usdt3_arg_sizes: [i32; 3] = [0; 3];

#[link_section = "usdt//proc/self/exe:test:usdt3"]
#[no_mangle]
extern "C" fn usdt3(ctx: *const c_void) -> i32 {
    let mut tmp: i64 = 0;

    if unsafe { my_pid } as i64 as u64 != current_tgid() {
        return 0;
    }

    sync_fetch_and_add_i32(addr_of_mut!(usdt3_called), 1);

    unsafe {
        usdt3_cookie = bpf_usdt_cookie(ctx) as u64;
        usdt3_arg_cnt = bpf_usdt_arg_cnt(ctx);

        usdt3_arg_rets[0] = bpf_usdt_arg(ctx, 0, &mut tmp);
        usdt3_args[0] = tmp as i32 as i64 as u64;
        usdt3_arg_sizes[0] = bpf_usdt_arg_size(ctx, 0);

        usdt3_arg_rets[1] = bpf_usdt_arg(ctx, 1, &mut tmp);
        usdt3_args[1] = tmp as u64;
        usdt3_arg_sizes[1] = bpf_usdt_arg_size(ctx, 1);

        usdt3_arg_rets[2] = bpf_usdt_arg(ctx, 2, &mut tmp);
        usdt3_args[2] = tmp as u64;
        usdt3_arg_sizes[2] = bpf_usdt_arg_size(ctx, 2);
    }

    0
}

#[no_mangle]
static mut usdt12_called: i32 = 0;
#[no_mangle]
static mut usdt12_cookie: u64 = 0;
#[no_mangle]
static mut usdt12_arg_cnt: i32 = 0;
#[no_mangle]
static mut usdt12_args: [u64; 12] = [0; 12];
#[no_mangle]
static mut usdt12_arg_sizes: [i32; 12] = [0; 12];

#[repr(C)]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

extern "C" {
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
}

/// BPF_USDT(usdt12, int a1, int a2, long a3, long a4, unsigned a5, long a6,
/// __u64 a7, uintptr_t a8, int a9, short a10, short a11, signed char a12)
#[link_section = "usdt//proc/self/exe:test:usdt12"]
#[no_mangle]
extern "C" fn usdt12(ctx: *const c_void) -> i32 {
    let mut x: [i64; 12] = [0; 12];
    let mut n = 0usize;
    while n < 12 {
        bpf_usdt_arg(ctx, n as u64, &mut x[n]);
        n += 1;
    }
    let a1 = x[0] as i32;
    let a2 = x[1] as i32;
    let a3 = x[2];
    let a4 = x[3];
    let a5 = x[4] as u32;
    let a6 = x[5];
    let a7 = x[6] as u64;
    let a8 = x[7] as usize;
    let a9 = x[8] as i32;
    let a10 = x[9] as i16;
    let a11 = x[10] as i16;
    let a12 = x[11] as i8;

    if unsafe { my_pid } as i64 as u64 != current_tgid() {
        return 0;
    }

    sync_fetch_and_add_i32(addr_of_mut!(usdt12_called), 1);

    unsafe {
        usdt12_cookie = bpf_usdt_cookie(ctx) as u64;
        usdt12_arg_cnt = bpf_usdt_arg_cnt(ctx);

        usdt12_args[0] = a1 as i64 as u64;
        usdt12_args[1] = a2 as i64 as u64;
        usdt12_args[2] = a3 as u64;
        usdt12_args[3] = a4 as u64;
        usdt12_args[4] = a5 as u64;
        usdt12_args[5] = a6 as u64;
        usdt12_args[6] = a7;
        usdt12_args[7] = a8 as u64;
        usdt12_args[8] = a9 as i64 as u64;
        usdt12_args[9] = a10 as i64 as u64;
        usdt12_args[10] = a11 as i64 as u64;
        usdt12_args[11] = a12 as i64 as u64;

        // C: bpf_for(i, 0, 12)
        let mut it = bpf_iter_num { __opaque: [0; 1] };
        bpf_iter_num_new(&mut it, 0, 12);
        loop {
            let t = bpf_iter_num_next(&mut it);
            if t.is_null() {
                break;
            }
            let i = *t;
            if !(i >= 0 && i < 12) {
                break;
            }
            usdt12_arg_sizes[i as usize] = bpf_usdt_arg_size(ctx, i as u64);
        }
        bpf_iter_num_destroy(&mut it);
    }

    0
}

#[no_mangle]
static mut usdt_sib_called: i32 = 0;
#[no_mangle]
static mut usdt_sib_cookie: u64 = 0;
#[no_mangle]
static mut usdt_sib_arg_cnt: i32 = 0;
#[no_mangle]
static mut usdt_sib_arg_ret: i32 = 0;
#[no_mangle]
static mut usdt_sib_arg: i16 = 0;
#[no_mangle]
static mut usdt_sib_arg_size: i32 = 0;

/*
 * usdt_sib is only tested on x86-related architectures, so it requires
 * manual attach since auto-attach will panic tests under other architectures
 */
#[link_section = "usdt"]
#[no_mangle]
extern "C" fn usdt_sib(ctx: *const c_void) -> i32 {
    let mut tmp: i64 = 0;

    if unsafe { my_pid } as i64 as u64 != current_tgid() {
        return 0;
    }

    sync_fetch_and_add_i32(addr_of_mut!(usdt_sib_called), 1);

    unsafe {
        usdt_sib_cookie = bpf_usdt_cookie(ctx) as u64;
        usdt_sib_arg_cnt = bpf_usdt_arg_cnt(ctx);

        usdt_sib_arg_ret = bpf_usdt_arg(ctx, 0, &mut tmp);
        usdt_sib_arg = tmp as i16;
        usdt_sib_arg_size = bpf_usdt_arg_size(ctx, 0);
    }

    0
}

// #ifdef __TARGET_ARCH_x86
#[no_mangle]
static mut executed: i32 = 0;
#[no_mangle]
static mut expected_ip: usize = 0;

#[link_section = "usdt"]
#[no_mangle]
extern "C" fn usdt_executed(ctx: *const c_void) -> i32 {
    // ctx->ip, pt_regs slot 16
    let ip = unsafe { *(ctx as *const usize).add(16) };
    if unsafe { expected_ip } == ip {
        unsafe { executed += 1 };
    }
    0
}

#[no_mangle]
static mut arg_total: i32 = 0;
#[no_mangle]
static mut arg_bad: i32 = 0;
#[no_mangle]
static mut arg_last: [isize; 3] = [0; 3];
#[no_mangle]
static mut expected_arg: [isize; 3] = [0; 3];
#[no_mangle]
static mut expected_pid: i32 = 0;

/// BPF_USDT(usdt_check_arg, long arg1, long arg2, long arg3)
#[link_section = "usdt"]
#[no_mangle]
extern "C" fn usdt_check_arg(ctx: *const c_void) -> i32 {
    let mut arg1: i64 = 0;
    let mut arg2: i64 = 0;
    let mut arg3: i64 = 0;
    bpf_usdt_arg(ctx, 0, &mut arg1);
    bpf_usdt_arg(ctx, 1, &mut arg2);
    bpf_usdt_arg(ctx, 2, &mut arg3);

    if unsafe { expected_pid } as i64 as u64 != current_tgid() {
        return 0;
    }

    sync_fetch_and_add_i32(addr_of_mut!(arg_total), 1);
    unsafe {
        arg_last[0] = arg1 as isize;
        arg_last[1] = arg2 as isize;
        arg_last[2] = arg3 as isize;

        if arg1 != expected_arg[0] as i64 || arg2 != expected_arg[1] as i64 || arg3 != expected_arg[2] as i64 {
            sync_fetch_and_add_i32(addr_of_mut!(arg_bad), 1);
        }
    }

    0
}
// #endif

bpf_object!("GPL");
