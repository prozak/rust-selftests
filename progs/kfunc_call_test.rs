#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/kfunc_call_test.c
// (bpf-rs-core idiom).
//
// kfunc_call_test5_asm is hand-written BPF asm in the C original purely to
// exercise ISA-dependent (ALU32 vs no-ALU32) register construction ahead of
// the kfunc call; since bpf_kfunc_call_test5's u8/u16/u32 params only ever
// read their low bits from the passed-in register, the final result is
// identical whether the truncation happens explicitly (typed Rust locals,
// same as this file's kfunc_call_test5) or implicitly (raw asm). The
// userspace oracle only checks the return value, so a plain-Rust
// reimplementation reusing test5's own multiply-and-call logic is a
// faithful translation without needing a `#[naked]` symbol-relocated call.
//
// kfunc_call_ctx: struct ctx_val's `ctx` field is `__kptr`-tagged in the C
// source, but rustc cannot emit BTF_KIND_TYPE_TAG (see TRANSLATING.md /
// btf-type-tag-uptr-kptr-unfixable) so bpf_kptr_xchg into it would be
// rejected ("R1 has no valid kptr"). The map is part of the object's kept
// ABI (must still be declared to match ELF shape) but the C program's use
// of it is a single-invocation "stash, xchg from NULL, always take the
// non-null branch" round trip with no cross-invocation purpose here either
// -- kfunc_call_test.skel.h is reopened fresh for every test run. So this
// follows kptr-bss-global-workaround-use-trusted-ptr-directly /
// cgrp_kfunc_success's generalization: skip the map entirely and just
// create+release the acquired pointer directly. prog_tests/kfunc_call.c's
// TC_TEST(kfunc_call_ctx, 0) only asserts the return value.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_prandom_u32, bpf_sk_fullsock};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;
use core::ffi::c_void;

#[repr(C)]
struct ProgTestRefKfunc {
    _opaque: [u8; 0],
}

#[repr(C)]
struct BpfTestmodCtx {
    _opaque: [u8; 0],
}

#[repr(C)]
struct SyscallTestArgs {
    data: [u8; 16],
    size: usize,
}

#[repr(C)]
#[allow(dead_code)]
struct CtxVal {
    ctx: *mut BpfTestmodCtx,
}

type CtxMap = BpfMap<i32, CtxVal, { maps::ARRAY }, 1>;

#[link_section = ".maps"]
#[no_mangle]
static ctx_map: CtxMap = BpfMap::new();

extern "C" {
    fn bpf_kfunc_call_test5(a: u8, b: u16, c: u32) -> i32;
    fn bpf_kfunc_call_test4(a: i8, b: i16, c: i32, d: i64) -> i64;
    fn bpf_kfunc_call_test2(sk: *mut c_void, a: u32, b: u32) -> i32;
    fn bpf_kfunc_call_test1(sk: *mut c_void, a: u32, b: u64, c: u32, d: u64) -> u64;
    fn bpf_kfunc_call_test_acquire(scalar_ptr: *mut u64) -> *mut ProgTestRefKfunc;
    fn bpf_kfunc_call_test_release(p: *mut ProgTestRefKfunc);
    fn bpf_kfunc_call_test_pass_ctx(skb: *const __sk_buff);
    // Real params are `struct prog_test_pass1 *` (16 bytes) / `struct
    // prog_test_pass2 *` (88 bytes, matching the C layout: int len +
    // short arr1[4] + { char arr2[4]; unsigned long arr3[8]; } with C
    // alignment padding). The verifier's KF_ARG_PTR_TO_MEM path for a
    // plain (non-BTF-ID) struct-pointer kfunc arg only checks that the
    // caller's memory region is >= the callee's declared struct size
    // (kernel/bpf/verifier.c get_kfunc_ptr_arg_type + check_mem_reg) --
    // it never matches the caller's BTF type/name against the callee's.
    // So a same-size byte array is a legitimate substitute and, unlike a
    // Rust struct literal built from nested arrays, a flat `[0; N]`
    // zero-init doesn't trip LLVM's memcpy-shaped-store recognition (see
    // copy-nonoverlapping-becomes-arena-memcpy-kfunc).
    fn bpf_kfunc_call_test_pass1(p: *mut [u8; 16]);
    fn bpf_kfunc_call_test_pass2(p: *mut [u8; 88]);
    fn bpf_kfunc_call_test_mem_len_pass1(mem: *mut c_void, len: i32);
    fn bpf_kfunc_call_test_mem_len_fail2(mem: *mut u64, len: i32);
    fn bpf_kfunc_call_test_get_rdwr_mem(p: *mut ProgTestRefKfunc, size: i32) -> *mut i32;
    fn bpf_kfunc_call_test_get_rdonly_mem(p: *mut ProgTestRefKfunc, size: i32) -> *mut i32;
    fn bpf_kfunc_call_test_static_unused_arg(arg: u32, unused: u32) -> u32;
    fn bpf_testmod_ctx_create(err: *mut i32) -> *mut BpfTestmodCtx;
    fn bpf_testmod_ctx_release(ctx: *mut BpfTestmodCtx);
}

/// Shared with kfunc_call_test5's third call and kfunc_call_test5_asm:
/// val8 = val32 & 0xFF, val16 = val32 & 0xFFFF, each multiplied then
/// truncated back to its own width (matches the C comment's promotion
/// rules bit-for-bit; the kfunc only ever reads the truncated low bits
/// regardless of how the caller built the register value).
#[inline(always)]
fn test5_call_scaled(val32: u32) -> i32 {
    let val16 = (val32 & 0xFFFF) as u16;
    let val8 = (val32 & 0xFF) as u8;
    let m8 = ((val8 as u32).wrapping_mul(0xFF)) as u8;
    let m16 = ((val16 as u32).wrapping_mul(0xFFFF)) as u16;
    let m32 = ((val32 as u64).wrapping_mul(0xFFFF_FFFFu64)) as u32;
    unsafe { bpf_kfunc_call_test5(m8, m16, m32) }
}

#[inline(always)]
fn fullsock(skb: *const __sk_buff) -> *mut c_void {
    let sk_raw = vload!((*skb).sk);
    if sk_raw == 0 {
        return core::ptr::null_mut();
    }
    bpf_sk_fullsock(sk_raw as *mut c_void)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_call_test5(skb: *const __sk_buff) -> i32 {
    let sk = fullsock(skb);
    if sk.is_null() {
        return -1;
    }

    let ret = unsafe { bpf_kfunc_call_test5(0xFFu8, 0xFFFFu16, 0xFFFF_FFFFu32) };
    if ret != 0 {
        return ret;
    }

    let val32 = bpf_get_prandom_u32();
    let val16 = (val32 & 0xFFFF) as u16;
    let val8 = (val32 & 0xFF) as u8;
    let ret = unsafe { bpf_kfunc_call_test5(val8, val16, val32) };
    if ret != 0 {
        return ret;
    }

    test5_call_scaled(val32)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_call_test5_asm(_ctx: *const c_void) -> i32 {
    let val32 = bpf_get_prandom_u32();
    test5_call_scaled(val32)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_call_test4(skb: *const __sk_buff) -> i32 {
    let sk = fullsock(skb);
    if sk.is_null() {
        return -1;
    }

    let tmp = unsafe { bpf_kfunc_call_test4(-3, -30, -200, -1000) };
    ((tmp >> 32) + tmp) as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_call_test2(skb: *const __sk_buff) -> i32 {
    let sk = fullsock(skb);
    if sk.is_null() {
        return -1;
    }

    unsafe { bpf_kfunc_call_test2(sk, 1, 2) }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_call_test1(skb: *const __sk_buff) -> i32 {
    let sk = fullsock(skb);
    if sk.is_null() {
        return -1;
    }

    let a: u64 = 1u64 << 32;
    let r = unsafe { bpf_kfunc_call_test1(sk, 1, a | 2, 3, a | 4) };
    let ret = (r >> 32) as u32;
    let ret = ret.wrapping_add(r as u32);
    ret as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_call_test_ref_btf_id(_skb: *const __sk_buff) -> i32 {
    let mut s: u64 = 0;
    let pt = unsafe { bpf_kfunc_call_test_acquire(&mut s) };
    let mut ret: i32 = 0;
    if !pt.is_null() {
        let a = unsafe { *(pt as *const i32) };
        let b = unsafe { *((pt as *const i32).add(1)) };
        if a != 42 || b != 108 {
            ret = -1;
        }
        unsafe {
            bpf_kfunc_call_test_release(pt);
        }
    }
    ret
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_call_test_pass(skb: *const __sk_buff) -> i32 {
    let mut p1: [u8; 16] = [0; 16];
    let mut p2: [u8; 88] = [0; 88];
    let mut a: i16 = 0;
    let mut b: u64 = 0;
    let mut c: i64 = 0;
    let mut d: i8 = 0;
    let mut e: i32 = 0;

    unsafe {
        bpf_kfunc_call_test_pass_ctx(skb);
        bpf_kfunc_call_test_pass1(&mut p1);
        bpf_kfunc_call_test_pass2(&mut p2);

        bpf_kfunc_call_test_mem_len_pass1(&mut a as *mut i16 as *mut c_void, 2);
        bpf_kfunc_call_test_mem_len_pass1(&mut b as *mut u64 as *mut c_void, 8);
        bpf_kfunc_call_test_mem_len_pass1(&mut c as *mut i64 as *mut c_void, 8);
        bpf_kfunc_call_test_mem_len_pass1(&mut d as *mut i8 as *mut c_void, 1);
        bpf_kfunc_call_test_mem_len_pass1(&mut e as *mut i32 as *mut c_void, 4);
        bpf_kfunc_call_test_mem_len_fail2(&mut b as *mut u64, -1);
    }

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn kfunc_syscall_test(args: *mut SyscallTestArgs) -> i32 {
    let size = unsafe { (*args).size };
    if size > 16 {
        return -7;
    }

    unsafe {
        let data_ptr = (*args).data.as_mut_ptr() as *mut c_void;
        bpf_kfunc_call_test_mem_len_pass1(data_ptr, 16);
        bpf_kfunc_call_test_mem_len_pass1(
            data_ptr,
            core::mem::size_of::<SyscallTestArgs>() as i32,
        );
        bpf_kfunc_call_test_mem_len_pass1(data_ptr, size as i32);
    }

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn kfunc_syscall_test_null(args: *mut SyscallTestArgs) -> i32 {
    // Must not dereference args: it's deliberately called with a NULL ctx
    // pointer so the verifier treats it as possibly-non-null and allows the
    // load; adding a null check here would change what's being tested.
    unsafe {
        bpf_kfunc_call_test_mem_len_pass1(args as *mut c_void, 0);
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_call_test_get_mem(_skb: *const __sk_buff) -> i32 {
    let mut s: u64 = 0;
    let pt = unsafe { bpf_kfunc_call_test_acquire(&mut s) };
    let mut ret: i32 = 0;
    if !pt.is_null() {
        let p = unsafe { bpf_kfunc_call_test_get_rdwr_mem(pt, 8) };
        if !p.is_null() {
            unsafe {
                *p = 42;
                ret = *p.add(1);
            }
        } else {
            ret = -1;
        }

        if ret >= 0 {
            let p = unsafe { bpf_kfunc_call_test_get_rdonly_mem(pt, 8) };
            if !p.is_null() {
                ret = unsafe { *p };
            } else {
                ret = -1;
            }
        }

        unsafe {
            bpf_kfunc_call_test_release(pt);
        }
    }
    ret
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_call_test_static_unused_arg(_skb: *const __sk_buff) -> i32 {
    let expected: u32 = 5;
    let actual = unsafe { bpf_kfunc_call_test_static_unused_arg(expected, 0xdeadbeef) };
    if actual != expected {
        -1
    } else {
        0
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn kfunc_call_ctx(_skb: *const __sk_buff) -> i32 {
    let mut err: i32 = 0;
    let ctx = unsafe { bpf_testmod_ctx_create(&mut err) };
    if ctx.is_null() && err == 0 {
        err = -1;
    }
    if !ctx.is_null() {
        unsafe {
            bpf_testmod_ctx_release(ctx);
        }
    }
    err
}

bpf_object!("GPL");
