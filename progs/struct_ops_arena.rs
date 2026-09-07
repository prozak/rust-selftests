#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

#[path = "common/arena.rs"]
mod arena_cast;
use arena_cast::cast_kern;
use core::{ffi::c_void, ptr::addr_of_mut};
use bpf_rs_core::{bpf_map, progs::fentry_arg as arg};

bpf_map! { arena { r#type: *const [i32; 33], map_flags: *const [i32; 1024], max_entries: *const [i32; 2], } }
#[no_mangle]
#[link_section = ".addr_space.1"]
static mut arena_touch: u64 = 0;
#[no_mangle]
#[link_section = ".addr_space.1"]
static mut cb_ptr_val: u64 = 0;

#[inline(always)]
unsafe fn touch() {
    let p = cast_kern(addr_of_mut!(arena_touch));
    *p = (*p).wrapping_add(1);
}
#[inline(always)]
unsafe fn increment(p: u64) {
    let p = cast_kern(p as *mut u64);
    *p = (*p).wrapping_add(1);
}
#[no_mangle]
#[link_section = "struct_ops/test_arena"]
extern "C" fn test_arena_cb(ctx: *const u64) -> i32 {
    unsafe {
        touch();
        *cast_kern(addr_of_mut!(cb_ptr_val)) = arg(ctx, 0);
        increment(arg(ctx, 0));
    }
    0
}
#[no_mangle]
#[link_section = "struct_ops/test_arena_nullable"]
extern "C" fn test_arena_nullable_cb(ctx: *const u64) -> i32 {
    unsafe {
        touch();
        let p = arg(ctx, 0);
        if p == 0 { return 0xbee; }
        increment(p);
    }
    0
}
#[no_mangle]
#[link_section = "struct_ops/test_arena_stack"]
extern "C" fn test_arena_stack_cb(ctx: *const u64) -> i32 {
    unsafe {
        touch();
        if arg(ctx, 0) != 1 || arg(ctx, 7) != 8 { return 0xbad; }
        increment(arg(ctx, 8));
    }
    0
}
#[no_mangle]
#[link_section = "struct_ops/test_arena_multislot"]
extern "C" fn test_arena_multislot_cb(ctx: *const u64) -> i32 {
    unsafe {
        touch();
        if arg(ctx, 0) != 11 || arg(ctx, 1) != 22 { return 0xbad; }
        increment(arg(ctx, 2));
    }
    0
}

type Callback = extern "C" fn(*const u64) -> i32;
#[repr(C)]
struct bpf_testmod_ops3 {
    // libbpf matches initialized members by name. Plain function pointers
    // retain FUNC_PROTO BTF; Rust Option<fn> would emit an enum wrapper.
    test_arena: Callback, test_arena_nullable: Callback,
    test_arena_stack: Callback, test_arena_multislot: Callback,
}
#[no_mangle]
#[link_section = ".struct_ops.link"]
static testmod_arena: bpf_testmod_ops3 = bpf_testmod_ops3 {
    test_arena: test_arena_cb,
    test_arena_nullable: test_arena_nullable_cb,
    test_arena_stack: test_arena_stack_cb, test_arena_multislot: test_arena_multislot_cb,
};

extern "C" {
    fn bpf_arena_alloc_pages(map: *const c_void, addr: *mut c_void, count: u32, node: i32, flags: u64) -> *mut u64;
    fn bpf_arena_free_pages(map: *const c_void, addr: *mut c_void, count: u32);
    fn bpf_testmod_ops3_call_test_arena(p: *mut u64) -> i32;
    fn bpf_testmod_ops3_call_test_arena_nullable(p: *mut u64) -> i32;
    fn bpf_testmod_ops3_call_test_arena_stack(p: *mut u64) -> i32;
    fn bpf_testmod_ops3_call_test_arena_multislot(p: *mut u64) -> i32;
}
#[no_mangle]
#[link_section = "syscall"]
extern "C" fn trigger(_ctx: *const c_void) -> i32 {
    unsafe {
        let val = bpf_arena_alloc_pages(&arena as *const _ as *const c_void, core::ptr::null_mut(), 1, -1, 0);
        if val.is_null() { return 1; }
        *cast_kern(val) = 41;
        if bpf_testmod_ops3_call_test_arena(val) != 0 { return 2; }
        if *cast_kern(val) != 42 { return 3; }
        if *cast_kern(addr_of_mut!(cb_ptr_val)) != val as u64 as u32 as u64 { return 4; }
        if bpf_testmod_ops3_call_test_arena_nullable(val) != 0 { return 5; }
        if *cast_kern(val) != 43 { return 6; }
        if bpf_testmod_ops3_call_test_arena_nullable(core::ptr::null_mut()) != 0xbee { return 7; }
        if bpf_testmod_ops3_call_test_arena_stack(val) != 0 { return 8; }
        if *cast_kern(val) != 44 { return 9; }
        if bpf_testmod_ops3_call_test_arena_multislot(val) != 0 { return 10; }
        if *cast_kern(val) != 45 { return 11; }
        bpf_arena_free_pages(&arena as *const _ as *const c_void, val.cast(), 1);
    }
    0
}
bpf_rs_core::bpf_object!("GPL");
