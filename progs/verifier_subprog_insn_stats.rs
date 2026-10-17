// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_subprog_insn_stats.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_subprog_insn_stats.rs
// (include!d below): stats_async_leaf, stats_async_schedule, stats_async_nested_leaf, stats_async_outer, stats_async_nested_schedule.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_subprog_insn_stats` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: stats_main_only stats_chain_leaf stats_chain_parent stats_static_chain stats_shared_leaf stats_global_root stats_shared_roots stats_async_leaf stats_async_schedule stats_async_direct stats_async_nested_leaf stats_async_outer stats_async_nested_schedule stats_async_nested

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    stats_main_only:
        __success,
        __log_level("4"),
        __msg("subprog 0 (stats_main_only) main insns_self 2 insns_total 2 stack 0"),
        __msg("processed 2 insns");
    stats_static_chain:
        __success,
        __log_level("4"),
        __msg("subprog 0 (stats_static_chain) main insns_self 2 insns_total 6 stack 0"),
        __msg("subprog {{[0-9]+}} (stats_chain_parent) static insns_self 2 insns_total 4 stack 0"),
        __msg("subprog {{[0-9]+}} (stats_chain_leaf) static insns_self 2 insns_total 2 stack 0"),
        __msg("processed 6 insns");
    stats_shared_roots:
        __success,
        __log_level("4"),
        __msg("subprog 0 (stats_shared_roots) main insns_self 3 insns_total 5 stack 0"),
        __msg("subprog {{[0-9]+}} (stats_shared_leaf) static insns_self 4 insns_total 4 stack 0"),
        __msg("subprog {{[0-9]+}} (stats_global_root) global insns_self 2 insns_total 4 stack 0"),
        __msg("processed 9 insns");
    stats_async_direct:
        __success,
        __log_level("4"),
        __msg("subprog 0 (stats_async_direct) main insns_self 9 insns_total 18 stack 0"),
        __msg("subprog {{[0-9]+}} (stats_async_schedule) static insns_self 7 insns_total 7 stack 0"),
        __msg("subprog {{[0-9]+}} (stats_async_leaf) static insns_self 2 insns_total 2 stack 0"),
        __msg("processed 18 insns");
    stats_async_nested:
        __success,
        __log_level("4"),
        __msg("subprog 0 (stats_async_nested) main insns_self 9 insns_total 25 stack 0"),
        __msg("subprog {{[0-9]+}} (stats_async_nested_schedule) static insns_self 7 insns_total 7 stack 0"),
        __msg("subprog {{[0-9]+}} (stats_async_outer) static insns_self 7 insns_total 7 stack 0"),
        __msg("subprog {{[0-9]+}} (stats_async_nested_leaf) static insns_self 2 insns_total 2 stack 0"),
        __msg("processed 25 insns");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct timer_value {
    timer: bpf_timer,
}

bpf_map! {
    timer_map {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const timer_value,
    }
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stats_main_only
extern "C" fn stats_main_only() -> i32 {
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

#[no_mangle]
#[inline(never)]
// BPF_NAKED: stats_chain_leaf
extern "C" fn stats_chain_leaf() -> i32 {
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

#[no_mangle]
#[inline(never)]
// BPF_NAKED: stats_chain_parent
extern "C" fn stats_chain_parent() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call {stats_chain_leaf};",
            "exit;",
            stats_chain_leaf = sym stats_chain_leaf,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stats_static_chain
extern "C" fn stats_static_chain() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call {stats_chain_parent};",
            "exit;",
            stats_chain_parent = sym stats_chain_parent,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: stats_shared_leaf
extern "C" fn stats_shared_leaf() -> i32 {
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

#[no_mangle]
#[inline(never)]
// BPF_NAKED: stats_global_root
extern "C" fn stats_global_root() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call {stats_shared_leaf};",
            "exit;",
            stats_shared_leaf = sym stats_shared_leaf,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stats_shared_roots
extern "C" fn stats_shared_roots() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call {stats_shared_leaf};",
            "call {stats_global_root};",
            "exit;",
            stats_shared_leaf = sym stats_shared_leaf,
            stats_global_root = sym stats_global_root,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stats_async_direct
extern "C" fn stats_async_direct() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {timer_map} ll;",
            "r2 = {stats_async_schedule};",
            "r3 = 0;",
            "r4 = 0;",
            "call 164;",
            "r0 = 0;",
            "exit;",
            timer_map = sym timer_map,
            stats_async_schedule = in(reg) stats_async_schedule as usize,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stats_async_nested
extern "C" fn stats_async_nested() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {timer_map} ll;",
            "r2 = {stats_async_nested_schedule};",
            "r3 = 0;",
            "r4 = 0;",
            "call 164;",
            "r0 = 0;",
            "exit;",
            timer_map = sym timer_map,
            stats_async_nested_schedule = in(reg) stats_async_nested_schedule as usize,
            out("r0") ret,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            options(nostack)
        );
    }
    ret
}

include!("hand/verifier_subprog_insn_stats.rs");

bpf_object!("GPL");
