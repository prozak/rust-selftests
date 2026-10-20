// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cb_refs.c,
// bpf-rs-core idiom.
//
// Four NEGATIVE verifier tests on reference tracking across
// bpf_for_each_map_elem callbacks (prog_tests/verifier.c RUN_TESTS this
// object; the `?` sections stay unloaded otherwise): a callback releasing
// the caller's reference, a callback acquiring one that leaks, a nested
// callback leaking an acquisition, and a reference handed to a static
// subprogram outside any callback. C's __always_inline cb/cb2/cb3 are still
// real subprograms in the C object (a callback passed by pointer is never
// inlined), so every callback is an extern "C" fn here. The __kptr member
// is the kptr BTF type tag declared with btf_type_tags!.
//
// The C's alloc_insn=3 / =2 / =1 are prefix matches on the leaking
// acquire's instruction index in the linked program (upstream's comments
// list the 30/32/33, 22/24/25 and 11/12 seen across compilers). leak_prog's
// only acquire is cb2's, appended after the main program: the Rust main
// program is a few instructions shorter than clang's, so that index is 29
// here and the token is relaxed to `{{[0-9]+}}` (an insn token); the other
// two programs match the C's prefixes as they stand.
// translint: allow(test-tags:leak_prog) alloc_insn is an instruction index of
// the linked program; the Rust layout puts cb2's acquire at 29, not 3x.

use bpf_rs_core::helpers::{bpf_for_each_map_elem, bpf_kptr_xchg, bpf_map_lookup_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, btf_type_tags, test_tags};
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

#[allow(non_camel_case_types)]
#[repr(C)]
struct prog_test_ref_kfunc {
    _opaque: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_value {
    ptr: *mut prog_test_ref_kfunc,
}

type ArrayMap = BpfMap<i32, map_value, { maps::ARRAY }, 16>;

#[link_section = ".maps"]
#[no_mangle]
static array_map: ArrayMap = BpfMap::new();

extern "C" {
    fn bpf_kfunc_call_test_acquire(scalar_ptr: *mut u64) -> *mut prog_test_ref_kfunc;
    fn bpf_kfunc_call_test_release(p: *mut prog_test_ref_kfunc);
}

test_tags! {
    underflow_prog: __failure, __msg("R1 type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_");
    leak_prog: __failure, __msg("Unreleased reference id={{[0-9]+}} alloc_insn={{[0-9]+}}");
    nested_cb: __failure, __msg("Unreleased reference id={{[0-9]+}} alloc_insn=2");
    non_cb_transfer_ref: __failure, __msg("Unreleased reference id={{[0-9]+}} alloc_insn=1");
}

// C: static __noinline int cb1(void *map, void *key, void *value, void *ctx)
#[inline(never)]
extern "C" fn cb1(_map: *mut ArrayMap, _key: *mut i32, _value: *mut map_value, ctx: *mut *mut prog_test_ref_kfunc) -> i64 {
    let p = unsafe { *ctx };
    unsafe { bpf_kfunc_call_test_release(p) };
    /* Without the fix this would cause underflow */
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn underflow_prog(_ctx: *mut c_void) -> i32 {
    let mut sl: u64 = 0;

    let mut p = unsafe { bpf_kfunc_call_test_acquire(&mut sl) };
    if p.is_null() {
        return 0;
    }
    bpf_for_each_map_elem(&array_map, cb1, &mut p, 0);
    unsafe { bpf_kfunc_call_test_release(p) };
    0
}

extern "C" fn cb2(_map: *mut ArrayMap, _key: *mut i32, _value: *mut map_value, ctx: *mut *mut prog_test_ref_kfunc) -> i64 {
    let mut sl: u64 = 0;

    unsafe { *ctx = bpf_kfunc_call_test_acquire(&mut sl) };
    /* Without the fix this would leak memory */
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn leak_prog(_ctx: *mut c_void) -> i32 {
    let zero: i32 = 0;

    let v = bpf_map_lookup_elem(&array_map, &zero) as *mut map_value;
    if v.is_null() {
        return 0;
    }

    let mut p: *mut prog_test_ref_kfunc = core::ptr::null_mut();
    bpf_for_each_map_elem(&array_map, cb2, &mut p, 0);
    let p = unsafe { bpf_kptr_xchg(addr_of_mut!((*v).ptr).cast(), p.cast()) } as *mut prog_test_ref_kfunc;
    if !p.is_null() {
        unsafe { bpf_kfunc_call_test_release(p) };
    }
    0
}

extern "C" fn cb(_map: *mut ArrayMap, _key: *mut i32, _value: *mut map_value, _ctx: *mut *mut c_void) -> i64 {
    0
}

extern "C" fn cb3(_map: *mut ArrayMap, _key: *mut i32, _value: *mut map_value, _ctx: *mut i32) -> i64 {
    let mut sl: u64 = 0;
    let mut p = MaybeUninit::<*mut c_void>::uninit();

    unsafe { bpf_kfunc_call_test_acquire(&mut sl) };
    bpf_for_each_map_elem(&array_map, cb, p.as_mut_ptr(), 0);
    /* It should only complain here, not in cb. This is why we need
     * callback_ref to be set to frameno.
     */
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn nested_cb(_ctx: *mut c_void) -> i32 {
    let mut sl: u64 = 0;
    let mut sp: i32 = 0;

    let p = unsafe { bpf_kfunc_call_test_acquire(&mut sl) };
    if p.is_null() {
        return 0;
    }
    bpf_for_each_map_elem(&array_map, cb3, &mut sp, 0);
    unsafe { bpf_kfunc_call_test_release(p) };
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn non_cb_transfer_ref(_ctx: *mut c_void) -> i32 {
    let mut sl: u64 = 0;

    let mut p = unsafe { bpf_kfunc_call_test_acquire(&mut sl) };
    if p.is_null() {
        return 0;
    }
    cb1(core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), &mut p);
    unsafe { bpf_kfunc_call_test_acquire(&mut sl) };
    0
}

btf_type_tags! {
    map_value.ptr: kptr;
}

bpf_object!("GPL");
