// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_runtime_jit.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_runtime_jit` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: dummy_prog_42_socket dummy_prog_24_socket dummy_prog_loop1_socket dummy_prog_loop2_socket call_within_bounds_prog_once call_within_bounds_prog_loop call_within_bounds_no_prog call_within_bounds_key_2 _2_key_2_first_branch _2_key_2_second_branch _0_key_2_first_branch _0_key_2_second_branch bounds_different_maps_first_branch bounds_different_maps_second_branch tail_call_out_of_bounds negative_index_to_tail_call _32bit_index_to_tail_call

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    dummy_prog_42_socket:
        __auxiliary,
        __auxiliary_unpriv;
    dummy_prog_24_socket:
        __auxiliary,
        __auxiliary_unpriv;
    dummy_prog_loop1_socket:
        __auxiliary,
        __auxiliary_unpriv;
    dummy_prog_loop2_socket:
        __auxiliary,
        __auxiliary_unpriv;
    call_within_bounds_prog_once:
        __description("runtime/jit: tail_call within bounds, prog once"),
        __success,
        __success_unpriv,
        __retval("42");
    call_within_bounds_prog_loop:
        __description("runtime/jit: tail_call within bounds, prog loop"),
        __success,
        __success_unpriv,
        __retval("41");
    call_within_bounds_no_prog:
        __description("runtime/jit: tail_call within bounds, no prog"),
        __success,
        __success_unpriv,
        __retval("1");
    call_within_bounds_key_2:
        __description("runtime/jit: tail_call within bounds, key 2"),
        __success,
        __success_unpriv,
        __retval("24");
    _2_key_2_first_branch:
        __description("runtime/jit: tail_call within bounds, key 2 / key 2, first branch"),
        __success,
        __success_unpriv,
        __retval("24");
    _2_key_2_second_branch:
        __description("runtime/jit: tail_call within bounds, key 2 / key 2, second branch"),
        __success,
        __success_unpriv,
        __retval("24");
    _0_key_2_first_branch:
        __description("runtime/jit: tail_call within bounds, key 0 / key 2, first branch"),
        __success,
        __success_unpriv,
        __retval("24");
    _0_key_2_second_branch:
        __description("runtime/jit: tail_call within bounds, key 0 / key 2, second branch"),
        __success,
        __success_unpriv,
        __retval("42");
    bounds_different_maps_first_branch:
        __description("runtime/jit: tail_call within bounds, different maps, first branch"),
        __success,
        __failure_unpriv,
        __msg_unpriv("tail_call abusing map_ptr"),
        __retval("1");
    bounds_different_maps_second_branch:
        __description("runtime/jit: tail_call within bounds, different maps, second branch"),
        __success,
        __failure_unpriv,
        __msg_unpriv("tail_call abusing map_ptr"),
        __retval("42");
    tail_call_out_of_bounds:
        __description("runtime/jit: tail_call out of bounds"),
        __success,
        __success_unpriv,
        __retval("2");
    negative_index_to_tail_call:
        __description("runtime/jit: pass negative index to tail_call"),
        __success,
        __success_unpriv,
        __retval("2");
    _32bit_index_to_tail_call:
        __description("runtime/jit: pass > 32bit index to tail_call"),
        __success,
        __success_unpriv,
        __retval("42"),
        __retval_unpriv("2");
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_prog1_socket {
    r#type: *const [i32; 3],
    max_entries: *const [i32; 4],
    key_size: *const [i32; 4],
    values: [*const c_void; 3],
}
unsafe impl Sync for map_prog1_socket {}

#[link_section = ".maps"]
#[no_mangle]
static map_prog1_socket: map_prog1_socket = map_prog1_socket {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [dummy_prog_42_socket as extern "C" fn() as *const c_void, dummy_prog_loop1_socket as extern "C" fn() as *const c_void, dummy_prog_24_socket as extern "C" fn() as *const c_void],
};

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_prog2_socket {
    r#type: *const [i32; 3],
    max_entries: *const [i32; 8],
    key_size: *const [i32; 4],
    values: [*const c_void; 8],
}
unsafe impl Sync for map_prog2_socket {}

#[link_section = ".maps"]
#[no_mangle]
static map_prog2_socket: map_prog2_socket = map_prog2_socket {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [core::ptr::null(), dummy_prog_loop2_socket as extern "C" fn() as *const c_void, dummy_prog_24_socket as extern "C" fn() as *const c_void, core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(), dummy_prog_42_socket as extern "C" fn() as *const c_void],
};

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dummy_prog_42_socket
extern "C" fn dummy_prog_42_socket() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dummy_prog_24_socket
extern "C" fn dummy_prog_24_socket() {
    unsafe {
        core::arch::asm!(
            "r0 = 24;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dummy_prog_loop1_socket
extern "C" fn dummy_prog_loop1_socket() {
    unsafe {
        core::arch::asm!(
            "r3 = 1;",
            "r2 = {map_prog1_socket} ll;",
            "call 12;",
            "r0 = 41;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dummy_prog_loop2_socket
extern "C" fn dummy_prog_loop2_socket() {
    unsafe {
        core::arch::asm!(
            "r3 = 1;",
            "r2 = {map_prog2_socket} ll;",
            "call 12;",
            "r0 = 41;",
            "exit;",
            map_prog2_socket = sym map_prog2_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: call_within_bounds_prog_once
extern "C" fn call_within_bounds_prog_once() {
    unsafe {
        core::arch::asm!(
            "r3 = 0;",
            "r2 = {map_prog1_socket} ll;",
            "call 12;",
            "r0 = 1;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: call_within_bounds_prog_loop
extern "C" fn call_within_bounds_prog_loop() {
    unsafe {
        core::arch::asm!(
            "r3 = 1;",
            "r2 = {map_prog1_socket} ll;",
            "call 12;",
            "r0 = 1;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: call_within_bounds_no_prog
extern "C" fn call_within_bounds_no_prog() {
    unsafe {
        core::arch::asm!(
            "r3 = 3;",
            "r2 = {map_prog1_socket} ll;",
            "call 12;",
            "r0 = 1;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: call_within_bounds_key_2
extern "C" fn call_within_bounds_key_2() {
    unsafe {
        core::arch::asm!(
            "r3 = 2;",
            "r2 = {map_prog1_socket} ll;",
            "call 12;",
            "r0 = 1;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _2_key_2_first_branch
extern "C" fn _2_key_2_first_branch() {
    unsafe {
        core::arch::asm!(
            "r0 = 13;",
            "*(u8*)(r1 + 48) = r0;",
            "r0 = *(u8*)(r1 + 48);",
            "if r0 == 13 goto l0_0;",
            "r3 = 2;",
            "r2 = {map_prog1_socket} ll;",
            "goto l1_0;",
            "l0_0:",
            "r3 = 2;",
            "r2 = {map_prog1_socket} ll;",
            "l1_0:",
            "call 12;",
            "r0 = 1;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _2_key_2_second_branch
extern "C" fn _2_key_2_second_branch() {
    unsafe {
        core::arch::asm!(
            "r0 = 14;",
            "*(u8*)(r1 + 48) = r0;",
            "r0 = *(u8*)(r1 + 48);",
            "if r0 == 13 goto l0_1;",
            "r3 = 2;",
            "r2 = {map_prog1_socket} ll;",
            "goto l1_1;",
            "l0_1:",
            "r3 = 2;",
            "r2 = {map_prog1_socket} ll;",
            "l1_1:",
            "call 12;",
            "r0 = 1;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _0_key_2_first_branch
extern "C" fn _0_key_2_first_branch() {
    unsafe {
        core::arch::asm!(
            "r0 = 13;",
            "*(u8*)(r1 + 48) = r0;",
            "r0 = *(u8*)(r1 + 48);",
            "if r0 == 13 goto l0_2;",
            "r3 = 0;",
            "r2 = {map_prog1_socket} ll;",
            "goto l1_2;",
            "l0_2:",
            "r3 = 2;",
            "r2 = {map_prog1_socket} ll;",
            "l1_2:",
            "call 12;",
            "r0 = 1;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _0_key_2_second_branch
extern "C" fn _0_key_2_second_branch() {
    unsafe {
        core::arch::asm!(
            "r0 = 14;",
            "*(u8*)(r1 + 48) = r0;",
            "r0 = *(u8*)(r1 + 48);",
            "if r0 == 13 goto l0_3;",
            "r3 = 0;",
            "r2 = {map_prog1_socket} ll;",
            "goto l1_3;",
            "l0_3:",
            "r3 = 2;",
            "r2 = {map_prog1_socket} ll;",
            "l1_3:",
            "call 12;",
            "r0 = 1;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_different_maps_first_branch
extern "C" fn bounds_different_maps_first_branch() {
    unsafe {
        core::arch::asm!(
            "r0 = 13;",
            "*(u8*)(r1 + 48) = r0;",
            "r0 = *(u8*)(r1 + 48);",
            "if r0 == 13 goto l0_4;",
            "r3 = 0;",
            "r2 = {map_prog1_socket} ll;",
            "goto l1_4;",
            "l0_4:",
            "r3 = 0;",
            "r2 = {map_prog2_socket} ll;",
            "l1_4:",
            "call 12;",
            "r0 = 1;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            map_prog2_socket = sym map_prog2_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_different_maps_second_branch
extern "C" fn bounds_different_maps_second_branch() {
    unsafe {
        core::arch::asm!(
            "r0 = 14;",
            "*(u8*)(r1 + 48) = r0;",
            "r0 = *(u8*)(r1 + 48);",
            "if r0 == 13 goto l0_5;",
            "r3 = 0;",
            "r2 = {map_prog1_socket} ll;",
            "goto l1_5;",
            "l0_5:",
            "r3 = 0;",
            "r2 = {map_prog2_socket} ll;",
            "l1_5:",
            "call 12;",
            "r0 = 1;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            map_prog2_socket = sym map_prog2_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tail_call_out_of_bounds
extern "C" fn tail_call_out_of_bounds() {
    unsafe {
        core::arch::asm!(
            "r3 = 256;",
            "r2 = {map_prog1_socket} ll;",
            "call 12;",
            "r0 = 2;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: negative_index_to_tail_call
extern "C" fn negative_index_to_tail_call() {
    unsafe {
        core::arch::asm!(
            "r3 = -1;",
            "r2 = {map_prog1_socket} ll;",
            "call 12;",
            "r0 = 2;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _32bit_index_to_tail_call
extern "C" fn _32bit_index_to_tail_call() {
    unsafe {
        core::arch::asm!(
            "r3 = 0x100000000 ll;",
            "r2 = {map_prog1_socket} ll;",
            "call 12;",
            "r0 = 2;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
