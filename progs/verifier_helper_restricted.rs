// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_helper_restricted.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_helper_restricted` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: in_bpf_prog_type_kprobe_1 in_bpf_prog_type_tracepoint_1 bpf_prog_type_perf_event_1 bpf_prog_type_raw_tracepoint_1 in_bpf_prog_type_kprobe_3 in_bpf_prog_type_tracepoint_3 bpf_prog_type_perf_event_3 bpf_prog_type_raw_tracepoint_3

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    in_bpf_prog_type_kprobe_1:
        __description("bpf_ktime_get_coarse_ns is forbidden in BPF_PROG_TYPE_KPROBE"),
        __failure,
        __msg("program of this type cannot use helper bpf_ktime_get_coarse_ns");
    in_bpf_prog_type_tracepoint_1:
        __description("bpf_ktime_get_coarse_ns is forbidden in BPF_PROG_TYPE_TRACEPOINT"),
        __failure,
        __msg("program of this type cannot use helper bpf_ktime_get_coarse_ns");
    bpf_prog_type_perf_event_1:
        __description("bpf_ktime_get_coarse_ns is forbidden in BPF_PROG_TYPE_PERF_EVENT"),
        __failure,
        __msg("program of this type cannot use helper bpf_ktime_get_coarse_ns");
    bpf_prog_type_raw_tracepoint_1:
        __description("bpf_ktime_get_coarse_ns is forbidden in BPF_PROG_TYPE_RAW_TRACEPOINT"),
        __failure,
        __msg("program of this type cannot use helper bpf_ktime_get_coarse_ns");
    in_bpf_prog_type_kprobe_3:
        __description("bpf_spin_lock is forbidden in BPF_PROG_TYPE_KPROBE"),
        __failure,
        __msg("tracing progs cannot use bpf_spin_lock yet");
    in_bpf_prog_type_tracepoint_3:
        __description("bpf_spin_lock is forbidden in BPF_PROG_TYPE_TRACEPOINT"),
        __failure,
        __msg("tracing progs cannot use bpf_spin_lock yet");
    bpf_prog_type_perf_event_3:
        __description("bpf_spin_lock is forbidden in BPF_PROG_TYPE_PERF_EVENT"),
        __failure,
        __msg("tracing progs cannot use bpf_spin_lock yet");
    bpf_prog_type_raw_tracepoint_3:
        __description("bpf_spin_lock is forbidden in BPF_PROG_TYPE_RAW_TRACEPOINT"),
        __failure,
        __msg("tracing progs cannot use bpf_spin_lock yet");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct val {
    cnt: i32,
    l: bpf_spin_lock,
}

bpf_map! {
    map_spin_lock {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const val,
    }
}

#[link_section = "kprobe"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: in_bpf_prog_type_kprobe_1
extern "C" fn in_bpf_prog_type_kprobe_1() {
    unsafe {
        core::arch::asm!(
            "call 160;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: in_bpf_prog_type_tracepoint_1
extern "C" fn in_bpf_prog_type_tracepoint_1() {
    unsafe {
        core::arch::asm!(
            "call 160;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "perf_event"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_prog_type_perf_event_1
extern "C" fn bpf_prog_type_perf_event_1() {
    unsafe {
        core::arch::asm!(
            "call 160;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_prog_type_raw_tracepoint_1
extern "C" fn bpf_prog_type_raw_tracepoint_1() {
    unsafe {
        core::arch::asm!(
            "call 160;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "kprobe"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: in_bpf_prog_type_kprobe_3
extern "C" fn in_bpf_prog_type_kprobe_3() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r1 = r0;",
            "call 93;",
            "l0_0:",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: in_bpf_prog_type_tracepoint_3
extern "C" fn in_bpf_prog_type_tracepoint_3() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            "r1 = r0;",
            "call 93;",
            "l0_1:",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "perf_event"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_prog_type_perf_event_3
extern "C" fn bpf_prog_type_perf_event_3() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 == 0 goto l0_2;",
            "r1 = r0;",
            "call 93;",
            "l0_2:",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

#[link_section = "raw_tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_prog_type_raw_tracepoint_3
extern "C" fn bpf_prog_type_raw_tracepoint_3() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_spin_lock} ll;",
            "call 1;",
            "if r0 == 0 goto l0_3;",
            "r1 = r0;",
            "call 93;",
            "l0_3:",
            "exit;",
            map_spin_lock = sym map_spin_lock,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
