// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/stack_arg.c
// (bpf-rs-core idiom).
//
// The C source is a #if/#else pair keyed on __BPF_FEATURE_STACK_ARGUMENT.
// LLVM 23 defines it: calls with more than five arguments pass the rest
// through the r11 stack-argument area, and the C oracle built with clang 23
// takes the #if branch, so this translates that branch (until 2026-10 the
// LLVM 22 oracle and this file took the #else fallback). rustc lowers a
// >5-argument call the same way; the verifier sizes a callee's incoming
// area from its BTF prototype, which scripts/stack_args.py checks against
// the IR parameter list.

// BTF_C_VOID: c_void

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, read_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_timer_init, bpf_timer_set_callback, bpf_timer_start,
};
use bpf_rs_core::maps::{self, BpfMap};

const CLOCK_MONOTONIC: u64 = 1;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

// struct timer_elem { struct bpf_timer timer; };
#[allow(non_camel_case_types)]
#[repr(C)]
struct timer_elem {
    timer: bpf_timer,
}

#[link_section = ".maps"]
#[no_mangle]
static timer_map: BpfMap<i32, timer_elem, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut timer_result: i32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static has_stack_arg: bool = true;

#[inline(never)]
fn static_func_many_args(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32, i: i32, j: i32) -> i32 {
    a + b + c + d + e + f + g + h + i + j
}

#[inline(never)]
#[no_mangle]
extern "C" fn global_calls_many_args(a: i32, b: i32, c: i32) -> i32 {
    static_func_many_args(a, b, c, a + 3, a + 4, a + 5, a + 6, a + 7, a + 8, a + 9)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_global_many_args(_ctx: *const __sk_buff) -> i32 {
    global_calls_many_args(1, 2, 3)
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct test_data {
    x: i64,
    y: i64,
}

// `p->x` / `p->y` in the static callees, as volatile loads: the same ldx
// insn, but LLVM neither promotes the pointer argument into its two
// fields (eleven IR parameters against ten in BTF) nor folds the callers'
// constant initializers through it (nine). clang marks C static functions
// DW_CC_nocall and LLVM 23 shapes their BTF prototype after the surviving
// parameters; rustc does not, so the IR has to keep the source signature.
#[inline(always)]
fn field_x(p: *const test_data) -> i64 { unsafe { read_volatile(addr_of!((*p).x)) } }
#[inline(always)]
fn field_y(p: *const test_data) -> i64 { unsafe { read_volatile(addr_of!((*p).y)) } }

// 1+2+3+4+5+6+7+8+9+10+20 = 75
#[inline(never)]
fn func_with_ptr_stack_arg(a: i64, b: i64, c: i64, d: i64, e: i64, f: i64, g: i64, h: i64, i: i64, p: *const test_data) -> i64 {
    a + b + c + d + e + f + g + h + i + field_x(p) + field_y(p)
}

#[inline(never)]
#[no_mangle]
extern "C" fn global_ptr_stack_arg(a: i64, b: i64, c: i64, d: i64, e: i64) -> i64 {
    let data = test_data { x: 10, y: 20 };

    func_with_ptr_stack_arg(a, b, c, d, e, a + 5, a + 6, a + 7, a + 8, &data)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_bpf2bpf_ptr_stack_arg(_ctx: *const __sk_buff) -> i32 {
    global_ptr_stack_arg(1, 2, 3, 4, 5) as i32
}

// 1+2+3+4+5+6+7+10+8+20 = 66
#[inline(never)]
fn func_with_mix_stack_args(a: i64, b: i64, c: i64, d: i64, e: i64, f: i64, g: i64, p: *const test_data, h: i64, q: *const test_data) -> i64 {
    a + b + c + d + e + f + g + field_x(p) + h + field_y(q)
}

#[inline(never)]
#[no_mangle]
extern "C" fn global_mix_stack_args(a: i64, b: i64, c: i64, d: i64, e: i64) -> i64 {
    let p = test_data { x: 10, y: 0 };
    let q = test_data { x: 0, y: 20 };

    func_with_mix_stack_args(a, b, c, d, e, e + 1, e + 2, &p, e + 3, &q)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_bpf2bpf_mix_stack_args(_ctx: *const __sk_buff) -> i32 {
    global_mix_stack_args(1, 2, 3, 4, 5) as i32
}

// Nesting test: func_outer calls func_inner, both with struct pointer
// as stack arg.
//
// func_inner: (a+1)+...+(i+1) + p->x + p->y
//           = 2+3+4+5+6+7+8+9+10+10+20 = 84
#[inline(never)]
fn func_inner_ptr(a: i64, b: i64, c: i64, d: i64, e: i64, f: i64, g: i64, h: i64, i: i64, p: *const test_data) -> i64 {
    a + b + c + d + e + f + g + h + i + field_x(p) + field_y(p)
}

#[inline(never)]
fn func_outer_ptr(a: i64, b: i64, c: i64, d: i64, e: i64, f: i64, g: i64, h: i64, i: i64, p: *const test_data) -> i64 {
    func_inner_ptr(a + 1, b + 1, c + 1, d + 1, e + 1, f + 1, g + 1, h + 1, i + 1, p)
}

#[inline(never)]
#[no_mangle]
extern "C" fn global_nesting_ptr(a: i64, b: i64, c: i64, d: i64, e: i64) -> i64 {
    let data = test_data { x: 10, y: 20 };

    func_outer_ptr(a, b, c, d, e, a + 5, a + 6, a + 7, a + 8, &data)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_bpf2bpf_nesting_stack_arg(_ctx: *const __sk_buff) -> i32 {
    global_nesting_ptr(1, 2, 3, 4, 5) as i32
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

extern "C" {
    fn bpf_dynptr_from_skb(skb: *mut c_void, flags: u64, ptr: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_size(ptr: *const bpf_dynptr) -> u32;
}

// 1+2+3+4+5+6+7+8+9+sizeof(pkt_v4) = 45+54 = 99
#[inline(never)]
fn func_with_dynptr(a: i64, b: i64, c: i64, d: i64, e: i64, f: i64, g: i64, h: i64, i: i64, ptr: *const bpf_dynptr) -> i64 {
    a + b + c + d + e + f + g + h + i + unsafe { bpf_dynptr_size(ptr) } as i64
}

// `void *ctx __arg_ctx` in C: the arg:ctx decl tag is declared with
// arg_tags! at the end of the file; BTF_C_VOID makes the `*mut c_void` a
// BTF `void *`, which that tag requires.
#[inline(never)]
#[no_mangle]
extern "C" fn global_dynptr_stack_arg(ctx: *mut c_void, a: i64, b: i64, c: i64, d: i64) -> i64 {
    let mut ptr = bpf_dynptr { __opaque: [0; 2] };

    unsafe { bpf_dynptr_from_skb(ctx, 0, &mut ptr) };
    func_with_dynptr(a, b, c, d, d + 1, d + 2, d + 3, d + 4, d + 5, &ptr)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_bpf2bpf_dynptr_stack_arg(skb: *mut __sk_buff) -> i32 {
    global_dynptr_stack_arg(skb as *mut c_void, 1, 2, 3, 4) as i32
}

// foo1: a+b+c+d+e+f+g+h+i+j
#[inline(never)]
fn foo1(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32, i: i32, j: i32) -> i32 {
    a + b + c + d + e + f + g + h + i + j
}

// foo2: a+b+c+d+e+f+g+h+i+j+k+l
#[inline(never)]
fn foo2(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32, i: i32, j: i32, k: i32, l: i32) -> i32 {
    a + b + c + d + e + f + g + h + i + j + k + l
}

// global_two_callees calls foo1 (5 stack args) and foo2 (7 stack args).
// The outgoing stack arg area is sized for foo2 (the larger callee).
// Stores for foo1 are a subset of the area used by foo2.
// Result: foo1(1..10) + foo2(1..12) = 55 + 78 = 133
//
// Pass a-e through so the compiler can't constant-fold the stack args away.
#[inline(never)]
#[no_mangle]
extern "C" fn global_two_callees(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {
    let mut ret;

    ret = foo1(a, b, c, d, e, a + 5, a + 6, a + 7, a + 8, a + 9);
    ret += foo2(a, b, c, d, e, a + 5, a + 6, a + 7, a + 8, a + 9, a + 10, a + 11);
    ret
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_two_callees(_ctx: *const __sk_buff) -> i32 {
    global_two_callees(1, 2, 3, 4, 5)
}

#[link_section = ".rodata"]
#[no_mangle]
static timer_base: i32 = 10;

extern "C" fn timer_cb_many_args(_map: *mut c_void, _key: *mut i32, _timer: *mut bpf_timer) -> i64 {
    // `const volatile int timer_base`: read, never folded.
    let v = unsafe { read_volatile(addr_of!(timer_base)) };

    unsafe {
        timer_result = static_func_many_args(v, v * 2, v * 3, v * 4, v * 5, v * 6, v * 7, v * 8, v * 9, v * 10);
    }
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_async_cb_many_args(_ctx: *const __sk_buff) -> i32 {
    let key: i32 = 0;

    let elem = bpf_map_lookup_elem(&timer_map, &key) as *mut timer_elem;
    if elem.is_null() {
        return -1;
    }

    let timer = unsafe { addr_of_mut!((*elem).timer) };
    bpf_timer_init(timer, &timer_map, CLOCK_MONOTONIC);
    bpf_timer_set_callback(timer, timer_cb_many_args);
    bpf_timer_start(timer, 1, 0);
    0
}

bpf_object!("GPL");
bpf_rs_core::arg_tags! {
    global_dynptr_stack_arg: 0: "arg:ctx";
}
