// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/crypto_sanity.c
// (bpf-rs-core idiom, crypto_common.h inlined). skb_crypto_setup builds the
// bpf_crypto_params from the key and algorithm the test writes into the
// globals, creates a crypto context and stashes it as a kptr in the one
// element of __crypto_ctx_map; the two tc programs find the UDP payload of
// a test packet as a dynptr and decrypt/encrypt it into dst, after a
// deliberately too-small dst_bad that must fail with -EINVAL.
// prog_tests/crypto_sanity.c reads status and dst. The 128- and 256-byte
// copies into params are word loops (an array copy would become a
// bpf_arena_memcpy kfunc call); .bss is laid out as the C object has it,
// which gives key and algo the C's 8-byte alignment. The byte arrays are
// C `char` (the test snprintf()s algo and compares dst as a string).
// BTF_C_CHAR: u8
// C_LAYOUT: .bss

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_dynptr_from_mem, bpf_kptr_xchg, bpf_map_lookup_elem, bpf_map_update_elem,
    bpf_skb_load_bytes, bpf_skb_pull_data,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, btf_type_tags, vload};

const TC_ACT_SHOT: i32 = 2;
const ETH_HLEN: u32 = 14;
const ETH_P_IPV6_BE: u32 = 0xDD86; // __bpf_constant_htons(ETH_P_IPV6)
const IPPROTO_UDP: u8 = 17;
const EINVAL: i32 = 22;
const ENOENT: i32 = 2;
const EIO: i32 = 5;
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
    fn bpf_dynptr_adjust(ptr: *mut bpf_dynptr, start: u64, end: u64) -> i32;
}

#[no_mangle]
static mut key: [u8; 256] = [0; 256];
#[no_mangle]
static mut udp_test_port: u16 = 7777;
#[no_mangle]
static mut authsize: u32 = 0;
#[no_mangle]
static mut key_len: u32 = 0;
#[no_mangle]
static mut algo: [u8; 128] = [0; 128];
#[no_mangle]
static mut dst: [u8; 16] = [0; 16];
#[no_mangle]
static mut dst_bad: [u8; 8] = [0; 8];
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

#[inline(never)]
#[export_name = "skb_dynptr_validate"]
extern "C" fn skb_dynptr_validate(skb: *mut __sk_buff, psrc: *mut bpf_dynptr) -> i32 {
    let mut ip6h = MaybeUninit::<[u8; 40]>::uninit();
    let mut udph = MaybeUninit::<[u8; 8]>::uninit();

    unsafe {
        if vload!((*skb).protocol) != ETH_P_IPV6_BE {
            return -1;
        }

        if bpf_skb_load_bytes(skb as *const c_void, ETH_HLEN, ip6h.as_mut_ptr() as *mut c_void, 40) != 0 {
            return -1;
        }

        // ip6h.nexthdr
        if *(ip6h.as_ptr() as *const u8).add(6) != IPPROTO_UDP {
            return -1;
        }

        if bpf_skb_load_bytes(skb as *const c_void, ETH_HLEN + 40, udph.as_mut_ptr() as *mut c_void, 8) != 0 {
            return -1;
        }

        // udph.dest != __bpf_htons(udp_test_port)
        if core::ptr::read_unaligned((udph.as_ptr() as *const u8).add(2) as *const u16) != udp_test_port.swap_bytes() {
            return -1;
        }

        let offset: u32 = ETH_HLEN + 40 + 8;
        if vload!((*skb).len) < offset + 16 {
            return -1;
        }

        /* let's make sure that 16 bytes of payload are in the linear part of skb */
        bpf_skb_pull_data(skb as *const c_void, offset + 16);
        bpf_dynptr_from_skb(skb, 0, psrc);
        bpf_dynptr_adjust(psrc, offset as u64, (offset + 16) as u64);
    }

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn skb_crypto_setup(_ctx: *mut c_void) -> i32 {
    let mut err: i32 = 0;

    unsafe {
        status = 0;
        if key_len > 256 {
            status = -EINVAL;
            return 0;
        }

        // __builtin_memcpy(&params.type, "skcipher", sizeof("skcipher"))
        write_volatile(addr_of_mut!(params.r#type) as *mut u64, u64::from_le_bytes(*b"skcipher"));
        write_volatile((addr_of_mut!(params.r#type) as *mut u8).add(8), 0);
        params.key_len = key_len;
        params.authsize = authsize;
        copy_words(addr_of_mut!(params.algo) as *mut u64, addr_of!(algo) as *const u64, 128 / 8);
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

/// decrypt_sanity / encrypt_sanity differ only in the kfunc they call
#[inline(always)]
unsafe fn crypto_sanity(
    skb: *mut __sk_buff,
    op: unsafe extern "C" fn(*mut bpf_crypto_ctx, *const bpf_dynptr, *const bpf_dynptr, *const bpf_dynptr) -> i32,
) -> i32 {
    let mut psrc = MaybeUninit::<bpf_dynptr>::uninit();
    let mut pdst = MaybeUninit::<bpf_dynptr>::uninit();

    status = 0;
    let err = skb_dynptr_validate(skb, psrc.as_mut_ptr());
    if err < 0 {
        status = err;
        return TC_ACT_SHOT;
    }

    let v = crypto_ctx_value_lookup();
    if v.is_null() {
        status = -ENOENT;
        return TC_ACT_SHOT;
    }

    let ctx = (*v).ctx;
    if ctx.is_null() {
        status = -ENOENT;
        return TC_ACT_SHOT;
    }

    /* Check also bad case where the dst buffer is smaller than the
     * skb's linear section.
     */
    bpf_dynptr_from_mem(addr_of_mut!(dst_bad) as *mut c_void, 8, 0, pdst.as_mut_ptr() as *mut c_void);
    status = op(ctx, psrc.as_ptr(), pdst.as_ptr(), core::ptr::null());
    if status == 0 {
        status = -EIO;
    }
    if status != -EINVAL {
        return TC_ACT_SHOT;
    }

    /* dst is a global variable to make testing part easier to check.
     * In real production code, a percpu map should be used to store
     * the result.
     */
    bpf_dynptr_from_mem(addr_of_mut!(dst) as *mut c_void, 16, 0, pdst.as_mut_ptr() as *mut c_void);
    status = op(ctx, psrc.as_ptr(), pdst.as_ptr(), core::ptr::null());
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn decrypt_sanity(skb: *mut __sk_buff) -> i32 {
    unsafe { crypto_sanity(skb, bpf_crypto_decrypt) }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn encrypt_sanity(skb: *mut __sk_buff) -> i32 {
    unsafe { crypto_sanity(skb, bpf_crypto_encrypt) }
}

// char __license[] SEC("license") = "GPL";
#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
