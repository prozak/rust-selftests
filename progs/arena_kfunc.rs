#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

#[path = "common/arena.rs"]
mod arena_cast;
use arena_cast::{cast_kern, cast_user};
use core::{ffi::c_void, ptr::{addr_of_mut, read_volatile, write_volatile}};
use bpf_rs_core::bpf_map;

bpf_map! { arena { r#type: *const [i32; 33], map_flags: *const [i32; 1024], max_entries: *const [i32; 2], } }
#[no_mangle]
#[link_section = ".addr_space.1"]
static mut arena_pad: u64 = 0;
#[no_mangle]
static mut stash: u64 = 0;

extern "C" {
    fn bpf_arena_alloc_pages(map: *const c_void, addr: *mut c_void, count: u32, node: i32, flags: u64) -> *mut u64;
    fn bpf_arena_free_pages(map: *const c_void, addr: *mut c_void, count: u32);
    fn bpf_kfunc_arena_arg_test(p: *mut u64) -> u64;
    fn bpf_kfunc_arena_cap_test(p: *mut u64) -> u64;
    fn bpf_kfunc_arena_cap_nullable_test(p: *mut u64) -> u64;
    fn bpf_kfunc_arena_args5_test(a: *mut u64, b: *mut u64, c: *mut u64, d: *mut u64, e: *mut u64) -> u64;
    fn bpf_kfunc_arena_mixed_test(a: *mut u64, b: *mut u64) -> u64;
}
#[inline(always)]
unsafe fn alloc_page() -> *mut u64 { bpf_arena_alloc_pages(&arena as *const _ as *const c_void, core::ptr::null_mut(), 1, -1, 0) }
#[inline(always)]
unsafe fn free_page(p: *mut u64) { bpf_arena_free_pages(&arena as *const _ as *const c_void, p.cast(), 1); }
#[inline(always)]
unsafe fn set_stash(v: u64) { write_volatile(addr_of_mut!(stash), v); }
#[inline(always)]
unsafe fn get_stash() -> *mut u64 { read_volatile(addr_of_mut!(stash)) as *mut u64 }

#[no_mangle]
#[link_section = "syscall"]
extern "C" fn arena_arg_forms(_ctx: *const c_void) -> i32 {
    unsafe {
        let val = alloc_page();
        if val.is_null() { return 1; }
        *cast_kern(val) = 41;
        if bpf_kfunc_arena_arg_test(val) != 41 || *cast_kern(val) != 42 { return 2; }
        set_stash(val as u64 as u32 as u64);
        if bpf_kfunc_arena_arg_test(get_stash()) != 42 || *cast_kern(val) != 43 { return 3; }
        set_stash(val as u64);
        set_stash(cast_user(get_stash()) as u64);
        if bpf_kfunc_arena_arg_test(get_stash()) != 43 || *cast_kern(val) != 44 { return 4; }
        free_page(val);
    }
    0
}
#[no_mangle]
#[link_section = "syscall"]
extern "C" fn arena_arg_rebase(_ctx: *const c_void) -> i32 {
    unsafe {
        let val = alloc_page();
        if val.is_null() { return 1; }
        let base = bpf_kfunc_arena_cap_test(core::ptr::null_mut());
        if base == 0 { return 2; }
        set_stash(0xbadc0ffe00000000);
        if bpf_kfunc_arena_cap_test(get_stash()) != base { return 3; }
        let off = val as u64 as u32 as u64;
        if bpf_kfunc_arena_cap_test(val) != base.wrapping_add(off) { return 4; }
        if bpf_kfunc_arena_cap_nullable_test(core::ptr::null_mut()) != 0 { return 5; }
        set_stash(0xbadc0ffe00000000);
        if bpf_kfunc_arena_cap_nullable_test(get_stash()) != 0 { return 6; }
        if bpf_kfunc_arena_cap_nullable_test(val) != base.wrapping_add(off) { return 7; }
        free_page(val);
    }
    0
}
#[no_mangle]
#[link_section = "syscall"]
extern "C" fn arena_args5(_ctx: *const c_void) -> i32 {
    unsafe {
        let val = alloc_page();
        if val.is_null() { return 1; }
        let p = cast_kern(val);
        *p = 1; *p.add(1) = 2; *p.add(2) = 4; *p.add(3) = 8; *p.add(4) = 16;
        if bpf_kfunc_arena_args5_test(val, val.wrapping_add(1), val.wrapping_add(2), val.wrapping_add(3), val.wrapping_add(4)) != 31 { return 2; }
        if bpf_kfunc_arena_args5_test(val, val.wrapping_add(1), val.wrapping_add(2), val.wrapping_add(3), core::ptr::null_mut()) != 15 { return 3; }
        free_page(val);
    }
    0
}
#[no_mangle]
#[link_section = "syscall"]
extern "C" fn arena_arg_mixed(_ctx: *const c_void) -> i32 {
    unsafe {
        let val = alloc_page();
        if val.is_null() { return 1; }
        let p = cast_kern(val);
        *p = 7; *p.add(1) = 5;
        if bpf_kfunc_arena_mixed_test(val, core::ptr::null_mut()) != 7 { return 2; }
        if bpf_kfunc_arena_mixed_test(val, val.wrapping_add(1)) != 12 { return 3; }
        free_page(val);
    }
    0
}
#[no_mangle]
#[link_section = "syscall"]
extern "C" fn arena_arg_unpopulated(_ctx: *const c_void) -> i32 {
    unsafe {
        let val = alloc_page();
        if val.is_null() { return 1; }
        set_stash((val as u64).wrapping_add(4096));
        bpf_kfunc_arena_arg_test(get_stash());
        free_page(val);
    }
    0
}
#[no_mangle]
#[link_section = "syscall"]
extern "C" fn arena_arg_no_arena(_ctx: *const c_void) -> i32 {
    unsafe { bpf_kfunc_arena_arg_test(1 as *mut u64); }
    0
}
#[no_mangle]
#[link_section = "syscall"]
extern "C" fn arena_arg_bad_reg(_ctx: *const c_void) -> i32 {
    let mut buf = 0;
    unsafe { alloc_page(); bpf_kfunc_arena_arg_test(&mut buf); }
    0
}
// LLVM 22 selects the C source's explicit stack-argument fallback.
#[no_mangle]
#[link_section = "syscall"]
extern "C" fn dummy_test(_ctx: *const c_void) -> i32 { 0 }

bpf_rs_core::bpf_object!("GPL");
bpf_rs_core::test_tags! {
    arena_arg_forms: __arch_x86_64, __arch_arm64, __success, __retval("0");
    arena_arg_rebase: __arch_x86_64, __arch_arm64, __success, __retval("0");
    arena_args5: __arch_x86_64, __arch_arm64, __success, __retval("0");
    arena_arg_mixed: __arch_x86_64, __arch_arm64, __success, __retval("0");
    arena_arg_unpopulated: __arch_x86_64, __arch_arm64, __success, __retval("0");
    arena_arg_no_arena: __arch_x86_64, __arch_arm64, __failure, __msg("arena pointer requires a program with an associated arena");
    arena_arg_bad_reg: __arch_x86_64, __arch_arm64, __failure, __msg("is not a pointer to arena or scalar");
    dummy_test: __arch_x86_64, __arch_arm64, __description("arena_arg_stack: not supported, dummy test"), __skip("arena_arg_stack: not supported"), __success;
}
