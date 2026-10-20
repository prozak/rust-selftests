// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/crypto_basic.c,
// bpf-rs-core idiom (crypto_sanity.rs carries the same crypto_common.h
// map, value type and kfunc prototypes).
//
// crypto_release creates and releases a crypto context (it loads;
// prog_tests/crypto_sanity.c runs it); crypto_acquire is a NEGATIVE
// verifier test: it acquires a second reference and releases only one, so
// the verifier rejects the leak with the message declared below. The
// unused crypto_common.h map is still a global of the C object, so it is
// defined here too. The license symbol is `__license`, as in the C.

use bpf_rs_core::btf_type_tags;
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::test_tags;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{addr_of_mut, write_volatile};

test_tags! {
    crypto_acquire: __failure, __msg("Unreleased reference");
}

const EINVAL: i32 = 22;

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
    fn bpf_crypto_ctx_acquire(ctx: *mut bpf_crypto_ctx) -> *mut bpf_crypto_ctx;
    fn bpf_crypto_ctx_release(ctx: *mut bpf_crypto_ctx);
}

#[no_mangle]
static mut status: i32 = 0;

// C: struct bpf_crypto_params params = { .type = "skcipher", .algo =
// "ecb(aes)", .key_len = 16 }; -- a zero-filled stack local with three
// fields set. Built with a memset plus three scalar stores: an aggregate
// copy would be an llvm.memcpy, which add_ksyms.py rewrites into the
// bpf_arena_memcpy kfunc (not in this kernel's BTF), while a constant-length
// memset is expanded inline by llc as clang's struct init is.
#[inline(always)]
fn make_params() -> bpf_crypto_params {
    let mut params = MaybeUninit::<bpf_crypto_params>::zeroed();
    let p = params.as_mut_ptr();
    unsafe {
        write_volatile(addr_of_mut!((*p).r#type) as *mut u64, u64::from_ne_bytes(*b"skcipher"));
        write_volatile(addr_of_mut!((*p).algo) as *mut u64, u64::from_ne_bytes(*b"ecb(aes)"));
        write_volatile(addr_of_mut!((*p).key_len), 16);
        params.assume_init()
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn crypto_release(_ctx: *mut c_void) -> i32 {
    let params = make_params();
    let mut err: i32 = 0;

    unsafe { status = 0 };

    let cctx = unsafe { bpf_crypto_ctx_create(&params, core::mem::size_of::<bpf_crypto_params>() as u32, &mut err) };

    if cctx.is_null() {
        unsafe { status = err };
        return 0;
    }

    unsafe { bpf_crypto_ctx_release(cctx) };

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn crypto_acquire(_ctx: *mut c_void) -> i32 {
    let params = make_params();
    let mut err: i32 = 0;

    unsafe { status = 0 };

    let cctx = unsafe { bpf_crypto_ctx_create(&params, core::mem::size_of::<bpf_crypto_params>() as u32, &mut err) };

    if cctx.is_null() {
        unsafe { status = err };
        return 0;
    }

    let cctx = unsafe { bpf_crypto_ctx_acquire(cctx) };
    if cctx.is_null() {
        return -EINVAL;
    }

    unsafe { bpf_crypto_ctx_release(cctx) };

    0
}

#[no_mangle]
#[link_section = "license"]
static __license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
