// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_subprog_topo.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_subprog_topo.rs
// (include!d below): global_a, global_b, loop_cb, topo_loop_cb, loop_cb2, topo_loop_cb_chain.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_subprog_topo` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: linear_b linear_a topo_linear diamond_c diamond_b diamond_a topo_diamond static_leaf global_a topo_mixed shared_leaf global_b topo_shared dup_leaf topo_dup_calls loop_cb topo_loop_cb loop_cb2_leaf loop_cb2 topo_loop_cb_chain topo_no_calls

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    topo_linear:
        __success,
        __log_level("2"),
        __msg("topo_order[0] = linear_b"),
        __msg("topo_order[1] = linear_a"),
        __msg("topo_order[2] = topo_linear");
    topo_diamond:
        __success,
        __log_level("2"),
        __msg("topo_order[0] = diamond_c"),
        __msg("topo_order[3] = topo_diamond");
    topo_mixed:
        __success,
        __log_level("2"),
        __msg("topo_order[0] = static_leaf"),
        __msg("topo_order[1] = global_a"),
        __msg("topo_order[2] = topo_mixed");
    topo_shared:
        __success,
        __log_level("2"),
        __msg("topo_order[0] = shared_leaf"),
        __msg("topo_order[1] = global_b"),
        __msg("topo_order[2] = topo_shared");
    topo_dup_calls:
        __success,
        __log_level("2"),
        __msg("topo_order[0] = dup_leaf"),
        __msg("topo_order[1] = topo_dup_calls");
    topo_loop_cb:
        __success,
        __log_level("2"),
        __msg("topo_order[0] = loop_cb"),
        __msg("topo_order[1] = topo_loop_cb");
    topo_loop_cb_chain:
        __success,
        __log_level("2"),
        __msg("topo_order[0] = loop_cb2_leaf"),
        __msg("topo_order[1] = loop_cb2"),
        __msg("topo_order[2] = topo_loop_cb_chain");
    topo_no_calls:
        __success,
        __log_level("2"),
        __msg("topo_order[0] = topo_no_calls");
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: linear_b
extern "C" fn linear_b() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: linear_a
extern "C" fn linear_a() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {linear_b};",
            "exit;",
            linear_b = sym linear_b,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: topo_linear
extern "C" fn topo_linear() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call {linear_a};",
            "exit;",
            linear_a = sym linear_a,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: diamond_c
extern "C" fn diamond_c() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: diamond_b
extern "C" fn diamond_b() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {diamond_c};",
            "exit;",
            diamond_c = sym diamond_c,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: diamond_a
extern "C" fn diamond_a() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call {diamond_c};",
            "exit;",
            diamond_c = sym diamond_c,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: topo_diamond
extern "C" fn topo_diamond() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call {diamond_a};",
            "call {diamond_b};",
            "exit;",
            diamond_a = sym diamond_a,
            diamond_b = sym diamond_b,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: static_leaf
extern "C" fn static_leaf() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 7;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: topo_mixed
extern "C" fn topo_mixed() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "call {global_a};",
            "exit;",
            global_a = sym global_a,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: shared_leaf
extern "C" fn shared_leaf() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 99;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: topo_shared
extern "C" fn topo_shared() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call {shared_leaf};",
            "r1 = 0;",
            "call {global_b};",
            "exit;",
            shared_leaf = sym shared_leaf,
            global_b = sym global_b,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: dup_leaf
extern "C" fn dup_leaf() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: topo_dup_calls
extern "C" fn topo_dup_calls() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call {dup_leaf};",
            "call {dup_leaf};",
            "exit;",
            dup_leaf = sym dup_leaf,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_cb2_leaf
extern "C" fn loop_cb2_leaf() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: topo_no_calls
extern "C" fn topo_no_calls() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

include!("hand/verifier_subprog_topo.rs");

bpf_object!("GPL");
