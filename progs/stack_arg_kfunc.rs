// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/stack_arg_kfunc.c
// (bpf-rs-core idiom).
//
// The C source is a #if/#else pair keyed on __BPF_FEATURE_STACK_ARGUMENT,
// which LLVM 23 defines: the clang 23 oracle takes the #if branch, whose
// kfunc calls pass their sixth and later arguments through the r11 stack
// area, and so does this file (the LLVM 22 oracle and translation took the
// #else fallback until 2026-10). add_ksyms mirrors the kernel prototypes
// onto the kfunc declarations.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_map_lookup_elem;
use bpf_rs_core::maps::{self, BpfMap};

#[link_section = ".rodata"]
#[no_mangle]
static has_stack_arg: bool = true;

// struct bpf_iter_testmod_seq { u64 :64; u64 :64; };
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_iter_testmod_seq {
    __opaque: [u64; 2],
}

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

// struct timer_map_value { struct bpf_timer timer; };
#[allow(non_camel_case_types)]
#[repr(C)]
struct timer_map_value {
    timer: bpf_timer,
}

#[link_section = ".maps"]
#[no_mangle]
static kfunc_timer_map: BpfMap<i32, timer_map_value, { maps::ARRAY }, 1> = BpfMap::new();

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

// struct prog_test_pass1 { int x0; struct { int x1; struct { int x2;
// struct { int x3; }; }; }; }: the nested anonymous structs flattened,
// same 16-byte layout.
#[allow(non_camel_case_types)]
#[repr(C)]
struct prog_test_pass1 {
    x0: i32,
    x1: i32,
    x2: i32,
    x3: i32,
}

extern "C" {
    fn bpf_iter_testmod_seq_new(it: *mut bpf_iter_testmod_seq, value: i64, cnt: i32) -> i32;
    fn bpf_iter_testmod_seq_destroy(it: *mut bpf_iter_testmod_seq);
    fn bpf_dynptr_from_skb(skb: *mut c_void, flags: u64, ptr: *mut bpf_dynptr) -> i32;
    fn bpf_kfunc_call_stack_arg(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64) -> u64;
    fn bpf_kfunc_call_stack_arg_ptr(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, p: *mut prog_test_pass1) -> u64;
    fn bpf_kfunc_call_stack_arg_mix(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, p: *mut prog_test_pass1, h: u64, q: *mut prog_test_pass1) -> u64;
    fn bpf_kfunc_call_stack_arg_dynptr(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, ptr: *mut bpf_dynptr) -> u64;
    fn bpf_kfunc_call_stack_arg_mem(a: u64, b: u64, c: u64, d: u64, e: u64, mem: *mut c_void, mem__sz: i32) -> u64;
    fn bpf_kfunc_call_stack_arg_iter(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, it__iter: *mut bpf_iter_testmod_seq) -> u64;
    fn bpf_kfunc_call_stack_arg_const_str(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, str__str: *const u8) -> u64;
    fn bpf_kfunc_call_stack_arg_timer(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, timer: *mut bpf_timer) -> u64;
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_scalar(_skb: *const __sk_buff) -> i32 {
    unsafe { bpf_kfunc_call_stack_arg(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) as i32 }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_ptr(_skb: *const __sk_buff) -> i32 {
    let mut p = prog_test_pass1 { x0: 10, x1: 20, x2: 0, x3: 0 };

    unsafe { bpf_kfunc_call_stack_arg_ptr(1, 2, 3, 4, 5, 6, 7, 8, 9, &mut p) as i32 }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_mix(_skb: *const __sk_buff) -> i32 {
    let mut p = prog_test_pass1 { x0: 10, x1: 0, x2: 0, x3: 0 };
    let mut q = prog_test_pass1 { x0: 0, x1: 20, x2: 0, x3: 0 };

    unsafe { bpf_kfunc_call_stack_arg_mix(1, 2, 3, 4, 5, 6, 7, &mut p, 8, &mut q) as i32 }
}

// 1+2+3+4+5+6+7+8+9+sizeof(pkt_v4) = 45+54 = 99
#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_dynptr(skb: *mut __sk_buff) -> i32 {
    let mut ptr = bpf_dynptr { __opaque: [0; 2] };

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, &mut ptr);
        bpf_kfunc_call_stack_arg_dynptr(1, 2, 3, 4, 5, 6, 7, 8, 9, &mut ptr) as i32
    }
}

// 1 + 2 + 3 + 4 + 5 + (1 + 2 + ... + 16) = 15 + 136 = 151
#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_mem(_skb: *const __sk_buff) -> i32 {
    let mut buf: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

    unsafe { bpf_kfunc_call_stack_arg_mem(1, 2, 3, 4, 5, buf.as_mut_ptr() as *mut c_void, 16) as i32 }
}

// 1+2+3+4+5+6+7+8+9+100 = 145
#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_iter(_skb: *const __sk_buff) -> i32 {
    let mut it = bpf_iter_testmod_seq { __opaque: [0; 2] };

    unsafe {
        bpf_iter_testmod_seq_new(&mut it, 100, 10);
        let ret = bpf_kfunc_call_stack_arg_iter(1, 2, 3, 4, 5, 6, 7, 8, 9, &mut it);
        bpf_iter_testmod_seq_destroy(&mut it);
        ret as i32
    }
}

#[link_section = ".rodata"]
#[no_mangle]
static cstr: [u8; 6] = *b"hello\0";

// 1+2+3+4+5+6+7+8+9 = 45
#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_const_str(_skb: *const __sk_buff) -> i32 {
    unsafe { bpf_kfunc_call_stack_arg_const_str(1, 2, 3, 4, 5, 6, 7, 8, 9, cstr.as_ptr()) as i32 }
}

// 1+2+3+4+5+6+7+8+9 = 45
#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_stack_arg_timer(_skb: *const __sk_buff) -> i32 {
    let key: i32 = 0;

    let val = bpf_map_lookup_elem(&kfunc_timer_map, &key) as *mut timer_map_value;
    if val.is_null() {
        return 0;
    }
    unsafe {
        bpf_kfunc_call_stack_arg_timer(1, 2, 3, 4, 5, 6, 7, 8, 9, core::ptr::addr_of_mut!((*val).timer)) as i32
    }
}

bpf_object!("GPL");
