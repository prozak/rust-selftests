// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/crypto_bench.c
// (bpf-rs-core idiom, crypto_common.h inlined as in crypto_sanity.rs).
// benchs/bench_bpf_crypto.c writes the cipher name and key into the
// globals, runs crypto_setup with bpf_prog_test_run (it builds the
// bpf_crypto_params, creates a crypto context and stashes it as a kptr in
// the one element of __crypto_ctx_map), then runs crypto_encrypt or
// crypto_decrypt on a packet and reads `hits` and `status`. The 128- and
// 256-byte copies into `params` are word loops (an array copy would become
// a bpf_arena_memcpy kfunc call); `len` is `const volatile` .rodata; the C
// names its license global `__license` (bpftool_ringbuf.rs); the .bss is
// laid out as the C object has it (`// C_LAYOUT:`). The strings are C
// `char` arrays. The two dynptr locals are declared pdst first so that
// psrc takes the higher frame slot (fp-16) as in clang's object: the
// prover pins a dynptr's contents by frame address (lesson 25).
// BTF_C_CHAR: u8
// C_LAYOUT: .bss

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use bpf_rs_core::btf_type_tags;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_dynptr_from_mem, bpf_kptr_xchg, bpf_map_lookup_elem, bpf_map_update_elem, sync_fetch_and_add,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::bpf_object;

const EINVAL: i32 = 22;
const ENOENT: i32 = 2;
const EEXIST: i32 = 17;

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_crypto_params {
    r#type: [u8; 14],
    reserved: [u8; 2],
    algo: [u8; 128],
    key: [u8; 256],
    key_len: u32,
    authsize: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_crypto_ctx {
    _priv: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct __crypto_ctx_value {
    ctx: *mut bpf_crypto_ctx,
}

btf_type_tags! {
    __crypto_ctx_value.ctx: kptr;
}

#[link_section = ".maps"]
#[no_mangle]
static __crypto_ctx_map: BpfMap<i32, __crypto_ctx_value, { maps::ARRAY }, 1> = BpfMap::new();

extern "C" {
    fn bpf_crypto_ctx_create(params: *const bpf_crypto_params, params__sz: u32, err: *mut i32) -> *mut bpf_crypto_ctx;
    fn bpf_crypto_ctx_release(ctx: *mut bpf_crypto_ctx);
    fn bpf_crypto_encrypt(
        ctx: *mut bpf_crypto_ctx,
        src: *const bpf_dynptr,
        dst: *const bpf_dynptr,
        iv: *const bpf_dynptr,
    ) -> i32;
    fn bpf_crypto_decrypt(
        ctx: *mut bpf_crypto_ctx,
        src: *const bpf_dynptr,
        dst: *const bpf_dynptr,
        iv: *const bpf_dynptr,
    ) -> i32;
    fn bpf_dynptr_from_skb(skb: *mut __sk_buff, flags: u64, ptr__uninit: *mut bpf_dynptr) -> i32;
}

#[link_section = ".rodata"]
#[no_mangle]
static len: u32 = 16;

/*
 * cipher[] and key[] are 8-byte aligned and 'params' is kept off the stack to
 * work around an LLVM code generation bug. clang lowers the memcpy() of these
 * byte-aligned globals into a per-byte load/store sequence staged on the stack,
 * and additionally materializes the on-stack 'struct bpf_crypto_params' twice.
 * Both blow the 512-byte BPF stack limit. Aligning the sources lets clang copy
 * word-wise, and a global 'params' removes the large object from the stack.
 */
#[no_mangle]
static mut cipher: [u8; 128] = [0; 128];
#[no_mangle]
static mut key_len: u32 = 0;
#[no_mangle]
static mut authsize: u32 = 0;
#[no_mangle]
static mut dst: [u8; 256] = [0; 256];
#[no_mangle]
static mut key: [u8; 256] = [0; 256];
// static struct bpf_crypto_params params; (the C object's local .bss symbol)
#[export_name = "params"]
static mut params: bpf_crypto_params = bpf_crypto_params {
    r#type: [0; 14],
    reserved: [0; 2],
    algo: [0; 128],
    key: [0; 256],
    key_len: 0,
    authsize: 0,
};
#[no_mangle]
static mut hits: isize = 0;
#[no_mangle]
static mut status: i32 = 0;

/// crypto_common.h: crypto_ctx_value_lookup()
#[inline(always)]
fn crypto_ctx_value_lookup() -> *mut __crypto_ctx_value {
    let key0: u32 = 0;

    bpf_map_lookup_elem(&__crypto_ctx_map, &key0) as *mut __crypto_ctx_value
}

/// crypto_common.h: crypto_ctx_insert()
#[inline(always)]
unsafe fn crypto_ctx_insert(ctx: *mut bpf_crypto_ctx) -> i32 {
    let local = __crypto_ctx_value { ctx: core::ptr::null_mut() };
    let key0: u32 = 0;

    let err = bpf_map_update_elem(&__crypto_ctx_map, &key0, &local, 0) as i32;
    if err != 0 {
        bpf_crypto_ctx_release(ctx);
        return err;
    }

    let v = bpf_map_lookup_elem(&__crypto_ctx_map, &key0) as *mut __crypto_ctx_value;
    if v.is_null() {
        bpf_crypto_ctx_release(ctx);
        return -ENOENT;
    }

    let old = bpf_kptr_xchg(addr_of_mut!((*v).ctx).cast(), ctx.cast()) as *mut bpf_crypto_ctx;
    if !old.is_null() {
        bpf_crypto_ctx_release(old);
        return -EEXIST;
    }

    0
}

/// `__builtin_memcpy(dst, src, 8 * words)` as 8-byte moves (both sides are
/// 8-byte aligned globals)
#[inline(always)]
unsafe fn copy_words(to: *mut u64, src: *const u64, words: usize) {
    let mut i = 0;
    while i < words {
        write_volatile(to.add(i), read_volatile(src.add(i)));
        i += 1;
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn crypto_setup(_args: *mut c_void) -> i32 {
    let mut err: i32 = 0;

    unsafe {
        status = 0;

        if cipher[0] == 0 || key_len == 0 || key_len > 256 {
            status = -EINVAL;
            return 0;
        }

        // __builtin_memcpy(&params.type, "skcipher", sizeof("skcipher"))
        write_volatile(addr_of_mut!(params.r#type) as *mut u64, u64::from_le_bytes(*b"skcipher"));
        write_volatile((addr_of_mut!(params.r#type) as *mut u8).add(8), 0);
        params.key_len = key_len;
        params.authsize = authsize;
        copy_words(addr_of_mut!(params.algo) as *mut u64, addr_of!(cipher) as *const u64, 128 / 8);
        copy_words(addr_of_mut!(params.key) as *mut u64, addr_of!(key) as *const u64, 256 / 8);

        let cctx = bpf_crypto_ctx_create(addr_of!(params), core::mem::size_of::<bpf_crypto_params>() as u32, &mut err);
        if cctx.is_null() {
            status = err;
            return 0;
        }

        let err = crypto_ctx_insert(cctx);
        if err != 0 && err != -EEXIST {
            status = err;
        }
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn crypto_encrypt(skb: *mut __sk_buff) -> i32 {
    let mut pdst = MaybeUninit::<bpf_dynptr>::uninit();
    let mut psrc = MaybeUninit::<bpf_dynptr>::uninit();

    let v = crypto_ctx_value_lookup();
    if v.is_null() {
        unsafe { status = -ENOENT };
        return 0;
    }

    let ctx = unsafe { (*v).ctx };
    if ctx.is_null() {
        unsafe { status = -ENOENT };
        return 0;
    }

    unsafe {
        bpf_dynptr_from_skb(skb, 0, psrc.as_mut_ptr());
        bpf_dynptr_from_mem(addr_of_mut!(dst) as *mut c_void, read_volatile(addr_of!(len)) as u64, 0, pdst.as_mut_ptr() as *mut c_void);
        status = bpf_crypto_encrypt(ctx, psrc.as_ptr(), pdst.as_ptr(), core::ptr::null());
        sync_fetch_and_add(addr_of_mut!(hits), 1);
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn crypto_decrypt(skb: *mut __sk_buff) -> i32 {
    let mut pdst = MaybeUninit::<bpf_dynptr>::uninit();
    let mut psrc = MaybeUninit::<bpf_dynptr>::uninit();

    let v = crypto_ctx_value_lookup();
    if v.is_null() {
        return -ENOENT;
    }

    let ctx = unsafe { (*v).ctx };
    if ctx.is_null() {
        return -ENOENT;
    }

    unsafe {
        bpf_dynptr_from_skb(skb, 0, psrc.as_mut_ptr());
        bpf_dynptr_from_mem(addr_of_mut!(dst) as *mut c_void, read_volatile(addr_of!(len)) as u64, 0, pdst.as_mut_ptr() as *mut c_void);
        status = bpf_crypto_decrypt(ctx, psrc.as_ptr(), pdst.as_ptr(), core::ptr::null());
        sync_fetch_and_add(addr_of_mut!(hits), 1);
    }
    0
}

#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
