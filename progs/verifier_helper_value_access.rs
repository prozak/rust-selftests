// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_helper_value_access.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_helper_value_access` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: access_to_map_full_range access_to_map_partial_range access_to_map_empty_range access_to_map_possibly_empty_range map_out_of_bound_range access_to_map_negative_range via_const_imm_full_range via_const_imm_partial_range via_const_imm_empty_range imm_out_of_bound_range const_imm_negative_range_adjustment_1 const_imm_negative_range_adjustment_2 via_const_reg_full_range via_const_reg_partial_range via_const_reg_empty_range reg_out_of_bound_range const_reg_negative_range_adjustment_1 const_reg_negative_range_adjustment_2 map_via_variable_full_range map_via_variable_partial_range map_via_variable_empty_range via_variable_no_max_check_1 via_variable_wrong_max_check_1 bounds_check_using_good_access_1 bounds_check_using_bad_access_1 bounds_check_using_good_access_2 bounds_check_using_bad_access_2 check_using_s_good_access_1 using_s_good_access_2_1 check_using_s_bad_access_1 check_using_s_good_access_2 using_s_good_access_2_2 check_using_s_bad_access_2 lookup_helper_access_to_map update_helper_access_to_map access_to_map_wrong_size adjusted_map_via_const_imm imm_out_of_bound_1 imm_out_of_bound_2 adjusted_map_via_const_reg reg_out_of_bound_1 reg_out_of_bound_2 to_adjusted_map_via_variable via_variable_no_max_check_2 via_variable_wrong_max_check_2

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    access_to_map_full_range:
        __description("helper access to map: full range"),
        __success;
    access_to_map_partial_range:
        __description("helper access to map: partial range"),
        __success;
    access_to_map_empty_range:
        __description("helper access to map: empty range"),
        __failure,
        __msg("R2 invalid zero-sized read: u64=[0,0]");
    access_to_map_possibly_empty_range:
        __description("helper access to map: possibly-empty ange"),
        __failure,
        __msg("R2 invalid zero-sized read: u64=[0,4]");
    map_out_of_bound_range:
        __description("helper access to map: out-of-bound range"),
        __failure,
        __msg("invalid access to map value, value_size=48 off=0 size=56");
    access_to_map_negative_range:
        __description("helper access to map: negative range"),
        __failure,
        __msg("R2 min value is negative");
    via_const_imm_full_range:
        __description("helper access to adjusted map (via const imm): full range"),
        __success;
    via_const_imm_partial_range:
        __description("helper access to adjusted map (via const imm): partial range"),
        __success;
    via_const_imm_empty_range:
        __description("helper access to adjusted map (via const imm): empty range"),
        __failure,
        __msg("R2 invalid zero-sized read");
    imm_out_of_bound_range:
        __description("helper access to adjusted map (via const imm): out-of-bound range"),
        __failure,
        __msg("invalid access to map value, value_size=48 off=4 size=52");
    const_imm_negative_range_adjustment_1:
        __description("helper access to adjusted map (via const imm): negative range (> adjustment)"),
        __failure,
        __msg("R2 min value is negative");
    const_imm_negative_range_adjustment_2:
        __description("helper access to adjusted map (via const imm): negative range (< adjustment)"),
        __failure,
        __msg("R2 min value is negative");
    via_const_reg_full_range:
        __description("helper access to adjusted map (via const reg): full range"),
        __success;
    via_const_reg_partial_range:
        __description("helper access to adjusted map (via const reg): partial range"),
        __success;
    via_const_reg_empty_range:
        __description("helper access to adjusted map (via const reg): empty range"),
        __failure,
        __msg("R2 invalid zero-sized read");
    reg_out_of_bound_range:
        __description("helper access to adjusted map (via const reg): out-of-bound range"),
        __failure,
        __msg("invalid access to map value, value_size=48 off=4 size=52");
    const_reg_negative_range_adjustment_1:
        __description("helper access to adjusted map (via const reg): negative range (> adjustment)"),
        __failure,
        __msg("R2 min value is negative");
    const_reg_negative_range_adjustment_2:
        __description("helper access to adjusted map (via const reg): negative range (< adjustment)"),
        __failure,
        __msg("R2 min value is negative");
    map_via_variable_full_range:
        __description("helper access to adjusted map (via variable): full range"),
        __success;
    map_via_variable_partial_range:
        __description("helper access to adjusted map (via variable): partial range"),
        __success;
    map_via_variable_empty_range:
        __description("helper access to adjusted map (via variable): empty range"),
        __failure,
        __msg("R2 invalid zero-sized read");
    via_variable_no_max_check_1:
        __description("helper access to adjusted map (via variable): no max check"),
        __failure,
        __msg("R1 unbounded memory access");
    via_variable_wrong_max_check_1:
        __description("helper access to adjusted map (via variable): wrong max check"),
        __failure,
        __msg("invalid access to map value, value_size=48 off=4 size=45");
    bounds_check_using_good_access_1:
        __description("helper access to map: bounds check using <, good access"),
        __success;
    bounds_check_using_bad_access_1:
        __description("helper access to map: bounds check using <, bad access"),
        __failure,
        __msg("R1 unbounded memory access");
    bounds_check_using_good_access_2:
        __description("helper access to map: bounds check using <=, good access"),
        __success;
    bounds_check_using_bad_access_2:
        __description("helper access to map: bounds check using <=, bad access"),
        __failure,
        __msg("R1 unbounded memory access");
    check_using_s_good_access_1:
        __description("helper access to map: bounds check using s<, good access"),
        __success;
    using_s_good_access_2_1:
        __description("helper access to map: bounds check using s<, good access 2"),
        __success;
    check_using_s_bad_access_1:
        __description("helper access to map: bounds check using s<, bad access"),
        __failure,
        __msg("R1 min value is negative");
    check_using_s_good_access_2:
        __description("helper access to map: bounds check using s<=, good access"),
        __success;
    using_s_good_access_2_2:
        __description("helper access to map: bounds check using s<=, good access 2"),
        __success;
    check_using_s_bad_access_2:
        __description("helper access to map: bounds check using s<=, bad access"),
        __failure,
        __msg("R1 min value is negative");
    lookup_helper_access_to_map:
        __description("map lookup helper access to map"),
        __success;
    update_helper_access_to_map:
        __description("map update helper access to map"),
        __success;
    access_to_map_wrong_size:
        __description("map update helper access to map: wrong size"),
        __failure,
        __msg("invalid access to map value, value_size=8 off=0 size=16");
    adjusted_map_via_const_imm:
        __description("map helper access to adjusted map (via const imm)"),
        __success;
    imm_out_of_bound_1:
        __description("map helper access to adjusted map (via const imm): out-of-bound 1"),
        __failure,
        __msg("invalid access to map value, value_size=16 off=12 size=8");
    imm_out_of_bound_2:
        __description("map helper access to adjusted map (via const imm): out-of-bound 2"),
        __failure,
        __msg("R2 min value is negative");
    adjusted_map_via_const_reg:
        __description("map helper access to adjusted map (via const reg)"),
        __success;
    reg_out_of_bound_1:
        __description("map helper access to adjusted map (via const reg): out-of-bound 1"),
        __failure,
        __msg("invalid access to map value, value_size=16 off=12 size=8");
    reg_out_of_bound_2:
        __description("map helper access to adjusted map (via const reg): out-of-bound 2"),
        __failure,
        __msg("R2 min value is negative");
    to_adjusted_map_via_variable:
        __description("map helper access to adjusted map (via variable)"),
        __success;
    via_variable_no_max_check_2:
        __description("map helper access to adjusted map (via variable): no max check"),
        __failure,
        __msg("R2 unbounded memory access, make sure to bounds check any such access");
    via_variable_wrong_max_check_2:
        __description("map helper access to adjusted map (via variable): wrong max check"),
        __failure,
        __msg("invalid access to map value, value_size=16 off=9 size=8");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct test_val {
    index: u32,
    foo: [i32; 11],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct other_val {
    foo: i64,
    bar: i64,
}

bpf_map! {
    map_hash_48b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const test_val,
    }
}

bpf_map! {
    map_hash_16b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const other_val,
    }
}

bpf_map! {
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_to_map_full_range
extern "C" fn access_to_map_full_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r1 = r0;",
            "r2 = 48;",
            "r3 = 0;",
            "call 113;",
            "l0_0:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_to_map_partial_range
extern "C" fn access_to_map_partial_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            "r1 = r0;",
            "r2 = 8;",
            "r3 = 0;",
            "call 113;",
            "l0_1:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_to_map_empty_range
extern "C" fn access_to_map_empty_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_2;",
            "r1 = r0;",
            "r2 = 0;",
            "call 6;",
            "l0_2:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_to_map_possibly_empty_range
extern "C" fn access_to_map_possibly_empty_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_3;",
            "r1 = r0;",
            "r7 = *(u64*)(r0 + 0);",
            "r7 &= 4;",
            "r2 = 0;",
            "r2 += r7;",
            "call 6;",
            "l0_3:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_out_of_bound_range
extern "C" fn map_out_of_bound_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_4;",
            "r1 = r0;",
            "r2 = 56;",
            "r3 = 0;",
            "call 113;",
            "l0_4:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_to_map_negative_range
extern "C" fn access_to_map_negative_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_5;",
            "r1 = r0;",
            "r2 = -8;",
            "r3 = 0;",
            "call 113;",
            "l0_5:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: via_const_imm_full_range
extern "C" fn via_const_imm_full_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_6;",
            "r1 = r0;",
            "r1 += 4;",
            "r2 = 44;",
            "r3 = 0;",
            "call 113;",
            "l0_6:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: via_const_imm_partial_range
extern "C" fn via_const_imm_partial_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_7;",
            "r1 = r0;",
            "r1 += 4;",
            "r2 = 8;",
            "r3 = 0;",
            "call 113;",
            "l0_7:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: via_const_imm_empty_range
extern "C" fn via_const_imm_empty_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_8;",
            "r1 = r0;",
            "r1 += 4;",
            "r2 = 0;",
            "call 6;",
            "l0_8:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: imm_out_of_bound_range
extern "C" fn imm_out_of_bound_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_9;",
            "r1 = r0;",
            "r1 += 4;",
            "r2 = 52;",
            "r3 = 0;",
            "call 113;",
            "l0_9:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: const_imm_negative_range_adjustment_1
extern "C" fn const_imm_negative_range_adjustment_1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_10;",
            "r1 = r0;",
            "r1 += 4;",
            "r2 = -8;",
            "r3 = 0;",
            "call 113;",
            "l0_10:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: const_imm_negative_range_adjustment_2
extern "C" fn const_imm_negative_range_adjustment_2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_11;",
            "r1 = r0;",
            "r1 += 4;",
            "r2 = -1;",
            "r3 = 0;",
            "call 113;",
            "l0_11:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: via_const_reg_full_range
extern "C" fn via_const_reg_full_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_12;",
            "r1 = r0;",
            "r3 = 4;",
            "r1 += r3;",
            "r2 = 44;",
            "r3 = 0;",
            "call 113;",
            "l0_12:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: via_const_reg_partial_range
extern "C" fn via_const_reg_partial_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_13;",
            "r1 = r0;",
            "r3 = 4;",
            "r1 += r3;",
            "r2 = 8;",
            "r3 = 0;",
            "call 113;",
            "l0_13:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: via_const_reg_empty_range
extern "C" fn via_const_reg_empty_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_14;",
            "r1 = r0;",
            "r3 = 0;",
            "r1 += r3;",
            "r2 = 0;",
            "call 6;",
            "l0_14:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reg_out_of_bound_range
extern "C" fn reg_out_of_bound_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_15;",
            "r1 = r0;",
            "r3 = 4;",
            "r1 += r3;",
            "r2 = 52;",
            "r3 = 0;",
            "call 113;",
            "l0_15:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: const_reg_negative_range_adjustment_1
extern "C" fn const_reg_negative_range_adjustment_1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_16;",
            "r1 = r0;",
            "r3 = 4;",
            "r1 += r3;",
            "r2 = -8;",
            "r3 = 0;",
            "call 113;",
            "l0_16:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: const_reg_negative_range_adjustment_2
extern "C" fn const_reg_negative_range_adjustment_2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_17;",
            "r1 = r0;",
            "r3 = 4;",
            "r1 += r3;",
            "r2 = -1;",
            "r3 = 0;",
            "call 113;",
            "l0_17:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_via_variable_full_range
extern "C" fn map_via_variable_full_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_18;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 > 4 goto l0_18;",
            "r1 += r3;",
            "r2 = 44;",
            "r3 = 0;",
            "call 113;",
            "l0_18:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_via_variable_partial_range
extern "C" fn map_via_variable_partial_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_19;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 > 4 goto l0_19;",
            "r1 += r3;",
            "r2 = 8;",
            "r3 = 0;",
            "call 113;",
            "l0_19:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_via_variable_empty_range
extern "C" fn map_via_variable_empty_range() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_20;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 > 4 goto l0_20;",
            "r1 += r3;",
            "r2 = 0;",
            "call 6;",
            "l0_20:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: via_variable_no_max_check_1
extern "C" fn via_variable_no_max_check_1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_21;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "r1 += r3;",
            "r2 = 1;",
            "r3 = 0;",
            "call 113;",
            "l0_21:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: via_variable_wrong_max_check_1
extern "C" fn via_variable_wrong_max_check_1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_22;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 > 4 goto l0_22;",
            "r1 += r3;",
            "r2 = 45;",
            "r3 = 0;",
            "call 113;",
            "l0_22:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_check_using_good_access_1
extern "C" fn bounds_check_using_good_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_23;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 < 32 goto l1_23;",
            "r0 = 0;",
            "l0_23:",
            "exit;",
            "l1_23:",
            "r1 += r3;",
            "r0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_check_using_bad_access_1
extern "C" fn bounds_check_using_bad_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_24;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 < 32 goto l1_24;",
            "r1 += r3;",
            "l0_24:",
            "r0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            "l1_24:",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_check_using_good_access_2
extern "C" fn bounds_check_using_good_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_25;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 <= 32 goto l1_25;",
            "r0 = 0;",
            "l0_25:",
            "exit;",
            "l1_25:",
            "r1 += r3;",
            "r0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounds_check_using_bad_access_2
extern "C" fn bounds_check_using_bad_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_26;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 <= 32 goto l1_26;",
            "r1 += r3;",
            "l0_26:",
            "r0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            "l1_26:",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_using_s_good_access_1
extern "C" fn check_using_s_good_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_27;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 s< 32 goto l1_27;",
            "l2_27:",
            "r0 = 0;",
            "l0_27:",
            "exit;",
            "l1_27:",
            "if r3 s< 0 goto l2_27;",
            "r1 += r3;",
            "r0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: using_s_good_access_2_1
extern "C" fn using_s_good_access_2_1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_28;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 s< 32 goto l1_28;",
            "l2_28:",
            "r0 = 0;",
            "l0_28:",
            "exit;",
            "l1_28:",
            "if r3 s< -3 goto l2_28;",
            "r1 += r3;",
            "r0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_using_s_bad_access_1
extern "C" fn check_using_s_bad_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_29;",
            "r1 = r0;",
            "r3 = *(u64*)(r0 + 0);",
            "if r3 s< 32 goto l1_29;",
            "l2_29:",
            "r0 = 0;",
            "l0_29:",
            "exit;",
            "l1_29:",
            "if r3 s< -3 goto l2_29;",
            "r1 += r3;",
            "r0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_using_s_good_access_2
extern "C" fn check_using_s_good_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_30;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 s<= 32 goto l1_30;",
            "l2_30:",
            "r0 = 0;",
            "l0_30:",
            "exit;",
            "l1_30:",
            "if r3 s<= 0 goto l2_30;",
            "r1 += r3;",
            "r0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: using_s_good_access_2_2
extern "C" fn using_s_good_access_2_2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_31;",
            "r1 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 s<= 32 goto l1_31;",
            "l2_31:",
            "r0 = 0;",
            "l0_31:",
            "exit;",
            "l1_31:",
            "if r3 s<= -3 goto l2_31;",
            "r1 += r3;",
            "r0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_using_s_bad_access_2
extern "C" fn check_using_s_bad_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_32;",
            "r1 = r0;",
            "r3 = *(u64*)(r0 + 0);",
            "if r3 s<= 32 goto l1_32;",
            "l2_32:",
            "r0 = 0;",
            "l0_32:",
            "exit;",
            "l1_32:",
            "if r3 s<= -3 goto l2_32;",
            "r1 += r3;",
            "r0 = 0;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: lookup_helper_access_to_map
extern "C" fn lookup_helper_access_to_map() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_33;",
            "r2 = r0;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "l0_33:",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: update_helper_access_to_map
extern "C" fn update_helper_access_to_map() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_34;",
            "r4 = 0;",
            "r3 = r0;",
            "r2 = r0;",
            "r1 = {map_hash_16b} ll;",
            "call 2;",
            "l0_34:",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_to_map_wrong_size
extern "C" fn access_to_map_wrong_size() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_35;",
            "r4 = 0;",
            "r3 = r0;",
            "r2 = r0;",
            "r1 = {map_hash_16b} ll;",
            "call 2;",
            "l0_35:",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: adjusted_map_via_const_imm
extern "C" fn adjusted_map_via_const_imm() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_36;",
            "r2 = r0;",
            "r2 += 8;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "l0_36:",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: imm_out_of_bound_1
extern "C" fn imm_out_of_bound_1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_37;",
            "r2 = r0;",
            "r2 += 12;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "l0_37:",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: imm_out_of_bound_2
extern "C" fn imm_out_of_bound_2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_38;",
            "r2 = r0;",
            "r2 += -4;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "l0_38:",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: adjusted_map_via_const_reg
extern "C" fn adjusted_map_via_const_reg() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_39;",
            "r2 = r0;",
            "r3 = 8;",
            "r2 += r3;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "l0_39:",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reg_out_of_bound_1
extern "C" fn reg_out_of_bound_1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_40;",
            "r2 = r0;",
            "r3 = 12;",
            "r2 += r3;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "l0_40:",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reg_out_of_bound_2
extern "C" fn reg_out_of_bound_2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_41;",
            "r2 = r0;",
            "r3 = -4;",
            "r2 += r3;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "l0_41:",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_adjusted_map_via_variable
extern "C" fn to_adjusted_map_via_variable() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_42;",
            "r2 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 > 8 goto l0_42;",
            "r2 += r3;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "l0_42:",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: via_variable_no_max_check_2
extern "C" fn via_variable_no_max_check_2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_43;",
            "r2 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "r2 += r3;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "l0_43:",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: via_variable_wrong_max_check_2
extern "C" fn via_variable_wrong_max_check_2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_44;",
            "r2 = r0;",
            "r3 = *(u32*)(r0 + 0);",
            "if r3 > 9 goto l0_44;",
            "r2 += r3;",
            "r1 = {map_hash_16b} ll;",
            "call 1;",
            "l0_44:",
            "exit;",
            map_hash_16b = sym map_hash_16b,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
