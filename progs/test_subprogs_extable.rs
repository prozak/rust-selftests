#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_subprogs_extable.c,
// bpf-rs-core idiom.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_for_each_map_elem;
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

// Minimal local CO-RE view of the kernel's real `struct file` (matched
// against target BTF by name), same pattern as fexit_bpf2bpf_simple.rs's
// `sk_buff`. Only `f_mode` is needed.
#[btf]
struct file {
    f_mode: u32,
}

type TestArrayMap = BpfMap<u32, u64, { maps::ARRAY }, 8>;

#[link_section = ".maps"]
#[no_mangle]
static test_array: TestArrayMap = BpfMap::new();

#[no_mangle]
static mut triggered: u32 = 0;

extern "C" fn test_cb(
    _map: *mut TestArrayMap,
    _key: *mut u32,
    _val: *mut u64,
    _data: *mut c_void,
) -> i64 {
    1
}

// The three programs below are intentionally byte-for-byte identical (as in
// the C source): the test exercises that the kernel's extable fixup applies
// independently to each fexit program's own copy of the probed loads below,
// not just to one shared subprogram.

#[link_section = "fexit/bpf_testmod_return_ptr"]
#[no_mangle]
extern "C" fn handle_fexit_ret_subprogs(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 1) as *const file;

    unsafe { core::ptr::read_volatile(ret as *const i32) };
    let f_mode = unsafe { &*ret }.f_mode().as_ptr() as *const i32;
    unsafe { core::ptr::read_volatile(f_mode) };

    bpf_for_each_map_elem(&test_array, test_cb, core::ptr::null_mut::<c_void>(), 0);
    unsafe { triggered += 1 };
    0
}

#[link_section = "fexit/bpf_testmod_return_ptr"]
#[no_mangle]
extern "C" fn handle_fexit_ret_subprogs2(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 1) as *const file;

    unsafe { core::ptr::read_volatile(ret as *const i32) };
    let f_mode = unsafe { &*ret }.f_mode().as_ptr() as *const i32;
    unsafe { core::ptr::read_volatile(f_mode) };

    bpf_for_each_map_elem(&test_array, test_cb, core::ptr::null_mut::<c_void>(), 0);
    unsafe { triggered += 1 };
    0
}

#[link_section = "fexit/bpf_testmod_return_ptr"]
#[no_mangle]
extern "C" fn handle_fexit_ret_subprogs3(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 1) as *const file;

    unsafe { core::ptr::read_volatile(ret as *const i32) };
    let f_mode = unsafe { &*ret }.f_mode().as_ptr() as *const i32;
    unsafe { core::ptr::read_volatile(f_mode) };

    bpf_for_each_map_elem(&test_array, test_cb, core::ptr::null_mut::<c_void>(), 0);
    unsafe { triggered += 1 };
    0
}

bpf_object!("GPL");
