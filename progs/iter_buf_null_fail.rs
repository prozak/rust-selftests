// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/iter_buf_null_fail.c
// (bpf-rs-core idiom). ctx->key of an iter/bpf_map_elem program is
// PTR_TO_BUF | PTR_MAYBE_NULL | MEM_RDONLY: a direct read is rejected, a
// read after a NULL check is accepted. The test_loader decl tags are
// declared with test_tags! and appended to the object's BTF by
// scripts/btf_test_tags.py.

use bpf_rs_core::bpf_object;
use bpf_rs_core::test_tags;
use core::ffi::c_void;
use core::ptr::write_volatile;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__bpf_map_elem {
    meta: *mut bpf_iter_meta,
    map: *mut c_void,
    key: *mut c_void,
    value: *mut c_void,
}

test_tags! {
    iter_buf_null_deref: __failure, __msg("invalid mem access");
    iter_buf_null_check_ok: __success;
}

/* Verify that the verifier rejects direct access to nullable PTR_TO_BUF. */
#[link_section = "iter/bpf_map_elem"]
#[no_mangle]
extern "C" fn iter_buf_null_deref(ctx: *mut bpf_iter__bpf_map_elem) -> i32 {
    // C: volatile __u32 v = *(__u32 *)ctx->key; (void)v;
    let key = unsafe { (*ctx).key } as *const u32;
    let mut v: u32 = 0;
    unsafe { write_volatile(&mut v, *key) };
    0
}

/* Verify that access after a null check is still accepted. */
#[link_section = "iter/bpf_map_elem"]
#[no_mangle]
extern "C" fn iter_buf_null_check_ok(ctx: *mut bpf_iter__bpf_map_elem) -> i32 {
    let key = unsafe { (*ctx).key } as *const u32;
    if key.is_null() {
        return 0;
    }
    let mut v: u32 = 0;
    unsafe { write_volatile(&mut v, *key) };
    0
}

bpf_object!("GPL");
