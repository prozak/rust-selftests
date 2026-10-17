// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

#[path = "common/arena.rs"]
mod arena_cast;
use arena_cast::{cast_kern, cast_user};
use core::{ffi::c_void, ptr::{read_volatile, write_volatile}};
use bpf_rs_core::bpf_map;

bpf_map! { arena { r#type: *const [i32; 33], map_flags: *const [i32; 1024], max_entries: *const [i32; 2], } }

// add_ksyms mirrors the kernel prototypes (16-byte aggregate returns) onto
// these declarations, so the BTF carries the real return types.
extern "C" {
    fn bpf_arena_alloc_pages(map: *const c_void, addr: *mut c_void, count: u32, node: i32, flags: u64) -> *mut u32;
    fn bpf_kfunc_call_test_ret_arena(addr: u64) -> u64;
    fn bpf_kfunc_call_test_ret_arena_mixed(addr: u64) -> u64;
    fn bpf_kfunc_call_test_ret_arena_untagged(addr: u64) -> u64;
    fn bpf_kfunc_call_test_ret_arena_union(addr: u64) -> u64;
}

/// The second half of a 16-byte aggregate return: the kernel hands it back
/// in R0:R2 (clang 23 lowers that natively; rustc's C ABI knows only R0, so
/// R2 is read right after the call).
#[inline(always)]
unsafe fn r2() -> u64 {
    let v: u64;
    core::arch::asm!("", out("r2") v, options(nomem, nostack, preserves_flags));
    v
}

#[inline(always)]
unsafe fn alloc_page() -> *mut u32 { bpf_arena_alloc_pages(&arena as *const _ as *const c_void, core::ptr::null_mut(), 1, -1, 0) }

#[no_mangle]
#[link_section = "syscall"]
extern "C" fn aggregate_ret_kfunc_arena(_ctx: *mut c_void) -> i32 {
    unsafe {
        let page = alloc_page();
        if page.is_null() { return 1; }

        // Both halves come back in R0:R2, pointing at page and page + 4.
        let ra = bpf_kfunc_call_test_ret_arena(page as u64);
        let rb = r2();
        if ra == 0 || rb == 0 { return 2; }

        let a = cast_kern(cast_user(ra as *mut u32));
        let b = cast_kern(cast_user(rb as *mut u32));
        write_volatile(a, 1);
        write_volatile(b, 2);
        if read_volatile(a) != 1 { return 3; }
        if read_volatile(b) != 2 { return 4; }

        let page = cast_kern(page);
        write_volatile(page, 7);
        if read_volatile(a) != 7 { return 5; }
        write_volatile(page.add(1), 9);
        if read_volatile(b) != 9 { return 6; }
    }
    0
}

#[no_mangle]
#[link_section = "syscall"]
extern "C" fn aggregate_ret_kfunc_arena_mixed(_ctx: *mut c_void) -> i32 {
    unsafe {
        let page = alloc_page();
        if page.is_null() { return 1; }

        // An arena pointer in R0 beside a scalar in R2.
        let rp = bpf_kfunc_call_test_ret_arena_mixed(page as u64);
        let tag = r2();
        if rp == 0 { return 2; }
        if tag != 0xbeef { return 3; }

        let p = cast_kern(cast_user(rp as *mut u32));
        write_volatile(p, 3);
        if read_volatile(p) != 3 { return 4; }
    }
    0
}

#[no_mangle]
#[link_section = "syscall"]
extern "C" fn aggregate_ret_kfunc_arena_untagged_fail(_ctx: *mut c_void) -> i32 {
    let a = unsafe { bpf_kfunc_call_test_ret_arena_untagged(0) };
    let b = unsafe { r2() };
    (a == b) as i32
}

#[no_mangle]
#[link_section = "syscall"]
extern "C" fn aggregate_ret_kfunc_arena_union_fail(_ctx: *mut c_void) -> i32 {
    // The union's two members alias, so `r.a == r.b` is always true.
    let a = unsafe { bpf_kfunc_call_test_ret_arena_union(0) };
    (a == a) as i32
}

bpf_rs_core::bpf_object!("GPL");
bpf_rs_core::test_tags! {
    aggregate_ret_kfunc_arena: __arch_x86_64, __arch_arm64, __load_if_JITed, __success, __retval("0");
    aggregate_ret_kfunc_arena_mixed: __arch_x86_64, __arch_arm64, __load_if_JITed, __success, __retval("0");
    aggregate_ret_kfunc_arena_untagged_fail: __arch_x86_64, __arch_arm64, __failure, __msg("is not composed of scalars or arena pointers"), __msg("member 'b' has type PTR");
    aggregate_ret_kfunc_arena_union_fail: __arch_x86_64, __arch_arm64, __failure, __msg("is not composed of scalars or arena pointers"), __msg("member 'b' has type PTR");
}
