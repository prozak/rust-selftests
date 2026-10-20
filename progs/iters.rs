// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/iters.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/iters.rs
// (include!d below): iter_err_unsafe_c_loop, iter_err_unsafe_asm_loop, iter_while_loop, iter_while_loop_auto_cleanup, iter_for_loop, iter_bpf_for_each_macro, iter_bpf_for_macro, iter_pragma_unroll_loop, iter_manual_unroll_loop, iter_multiple_sequential_loops, iter_limit_cond_break_loop, iter_obfuscate_counter, iter_search_loop, iter_array_fill, iter_nested_iters, iter_nested_deeply_iters, fill_inner_dimension, sum_inner_dimension, iter_subprog_iters, iter_err_too_permissive1, iter_err_too_permissive2, iter_err_too_permissive3, iter_tricky_but_fine, iter_stack_array_loop, fill, sum, iter_pass_iter_ptr_to_subprog, iter_arr_with_actual_elem_count, nest_2, nest_1, iter_subprog_check_stacksafe, iter_new_bad_arg, iter_next_bad_arg, iter_destroy_bad_arg, clean_live_states, loop_cb5, iter_nested_remake.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py iters` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: iter_err_unsafe_c_loop iter_err_unsafe_asm_loop iter_num_new_inlined iter_while_loop iter_while_loop_auto_cleanup iter_for_loop iter_bpf_for_each_macro iter_bpf_for_macro iter_pragma_unroll_loop iter_manual_unroll_loop iter_multiple_sequential_loops iter_limit_cond_break_loop iter_obfuscate_counter iter_search_loop iter_array_fill delayed_read_mark delayed_precision_mark loop_state_deps1 loop_state_deps2 loop_state_deps3 triple_continue widen_spill checkpoint_states_deletion absent_mark_in_the_middle_state noop absent_mark_in_the_middle_state2 absent_mark_in_the_middle_state3 loop1 loop1_wrapper absent_mark_in_the_middle_state4 loop_cb4 stack_misc_vs_scalar_in_a_loop loop_cb5 loop_counter_precision_2nd_iter iter_remake_jmp iter_remake iter_remake_callee_jmp iter_remake_after_next_jmp iter_remake_two_jmp iter_remake_inline iter_remake_callee iter_remake_after_next iter_remake_drained

// the C's anonymous types, named here; scripts/btf_anon.py clears
// the names in the object's BTF
// BTF_ANON

// a `*mut c_void` is the C's `void *` in BTF (scripts/btf_rename.py)
// BTF_C_VOID: c_void

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    iter_err_unsafe_c_loop:
        __failure,
        __msg("math between map_value pointer and register with unbounded min value is not allowed");
    iter_err_unsafe_asm_loop:
        __failure,
        __msg("unbounded memory access");
    iter_num_new_inlined:
        __arch_x86_64,
        __arch_arm64,
        __success,
        __xlated("r6 = r10"),
        __xlated("r6 += -8"),
        __xlated("call unknown"),
        __xlated("r3 = r0"),
        __xlated("r3 &= 65535"),
        __xlated("r1 = r6"),
        __xlated("r2 = 0"),
        __xlated("if w2 s> w3 goto pc+8"),
        __xlated("w0 = w3"),
        __xlated("w0 -= w2"),
        __xlated("if r0 > 0x800000 goto pc+8"),
        __xlated("w2 += -1"),
        __xlated("*(u32 *)(r1 +0) = r2"),
        __xlated("*(u32 *)(r1 +4) = r3"),
        __xlated("r0 = 0"),
        __xlated("goto pc+5"),
        __xlated("*(u64 *)(r1 +0) = 0"),
        __xlated("r0 = -22"),
        __xlated("goto pc+2"),
        __xlated("*(u64 *)(r1 +0) = 0"),
        __xlated("r0 = -7"),
        __xlated("r1 = r6"),
        __xlated("r0 = *(u32 *)(r1 +0)"),
        __xlated("w0 += 1"),
        __xlated("r2 = *(u32 *)(r1 +4)"),
        __xlated("if w0 s>= w2 goto pc+3"),
        __xlated("*(u32 *)(r1 +0) = r0"),
        __xlated("r0 = r1"),
        __xlated("goto pc+2"),
        __xlated("*(u64 *)(r1 +0) = 0"),
        __xlated("r0 = 0"),
        __xlated("if r0 != 0x0 goto pc-11"),
        __xlated("r1 = r6"),
        __xlated("goto pc+0"),
        __xlated("r0 = 0"),
        __xlated("exit");
    iter_while_loop:
        __success;
    iter_while_loop_auto_cleanup:
        __success;
    iter_for_loop:
        __success;
    iter_bpf_for_each_macro:
        __success;
    iter_bpf_for_macro:
        __success;
    iter_pragma_unroll_loop:
        __success;
    iter_manual_unroll_loop:
        __success;
    iter_multiple_sequential_loops:
        __success;
    iter_limit_cond_break_loop:
        __success;
    iter_obfuscate_counter:
        __success;
    iter_search_loop:
        __success;
    iter_array_fill:
        __success;
    delayed_read_mark:
        __failure,
        __msg("R1 type=scalar expected=fp");
    delayed_precision_mark:
        __failure,
        __msg("math between fp pointer and register with unbounded");
    loop_state_deps1:
        __failure,
        __msg("math between fp pointer and register with unbounded"),
        __flag("BPF_F_TEST_STATE_FREQ");
    loop_state_deps2:
        __failure,
        __msg("math between fp pointer and register with unbounded"),
        __flag("BPF_F_TEST_STATE_FREQ");
    loop_state_deps3:
        __failure,
        __msg("math between fp pointer and register with unbounded"),
        __flag("BPF_F_TEST_STATE_FREQ");
    triple_continue:
        __success;
    widen_spill:
        __success;
    checkpoint_states_deletion:
        __success;
    absent_mark_in_the_middle_state:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("misaligned stack access off -31+0 size 8");
    absent_mark_in_the_middle_state2:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("misaligned stack access off -31+0 size 8");
    absent_mark_in_the_middle_state3:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("misaligned stack access off -31+0 size 8");
    absent_mark_in_the_middle_state4:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("math between fp pointer and register with unbounded min value is not allowed");
    stack_misc_vs_scalar_in_a_loop:
        __success;
    loop_counter_precision_2nd_iter:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __failure,
        __msg("memory access is {{.*}} and is outside of the object of size 64");
    iter_remake_jmp:
        __description("iter: remake in the loop, jump to next"),
        __failure,
        __msg("infinite loop detected");
    iter_remake_callee_jmp:
        __description("iter: remake in a callee, jump to next"),
        __failure,
        __msg("infinite loop detected");
    iter_remake_after_next_jmp:
        __description("iter: remake after next, jump to next"),
        __failure,
        __msg("infinite loop detected");
    iter_remake_two_jmp:
        __description("iter: two iterators, remake each after its next"),
        __failure,
        __msg("infinite loop detected");
    iter_remake_inline:
        __description("iter: remake in the loop"),
        __failure,
        __msg("infinite loop detected"),
        __flag("BPF_F_TEST_STATE_FREQ");
    iter_remake_callee:
        __description("iter: remake in a callee"),
        __failure,
        __msg("infinite loop detected"),
        __flag("BPF_F_TEST_STATE_FREQ");
    iter_remake_after_next:
        __description("iter: remake after next"),
        __failure,
        __msg("infinite loop detected"),
        __flag("BPF_F_TEST_STATE_FREQ");
    iter_remake_drained:
        __description("iter: remake when drained"),
        __failure,
        __msg("infinite loop detected"),
        __flag("BPF_F_TEST_STATE_FREQ");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct __anon_type365 {
    data: [i32; 32],
    n: i32,
}

bpf_map! {
    hash_map {
        r#type: *const [i32; 1],
        key: *const i32,
        value: *const i32,
        max_entries: *const [i32; 1000],
    }
}

bpf_map! {
    amap {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 10],
        key: *const i32,
        value: *const i32,
    }
}

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut zero: i32 = 0;

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut arr: [i32; 256] = [0; 256];

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut arr2d: [[i32; 5]; 4] = [[0; 5], [0; 5], [0; 5], [0; 5]];

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut arr2d_row_sums: [i32; 4] = [0, 0, 0, 0];

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut arr2d_col_sums: [i32; 5] = [0; 5];

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut loop_data: __anon_type365 = __anon_type365 { data: [0; 32], n: 0 };

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut upper: u32 = 0;

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut select_n: u32 = 0;

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut result: u32 = 0;

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut global_it: bpf_iter_num = bpf_iter_num { __opaque: [0] };

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut my_pid: i32 = 0;

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut global: u64 = 0;

#[link_section = ".data.small_arr"]
#[no_mangle]
#[allow(non_upper_case_globals)]
static mut small_arr: [i32; 16] = [0; 16];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_while_loop.____fmt"]
static iter_while_loop_____fmt: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 49, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_while_loop_auto_cleanup.____fmt"]
static iter_while_loop_auto_cleanup_____fmt: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 49, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_for_loop.____fmt"]
static iter_for_loop_____fmt: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 50, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_bpf_for_each_macro.____fmt"]
static iter_bpf_for_each_macro_____fmt: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 50, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_bpf_for_macro.____fmt"]
static iter_bpf_for_macro_____fmt: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 50, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_pragma_unroll_loop.____fmt"]
static iter_pragma_unroll_loop_____fmt: [i8; 30] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 51, 32, 86, 65, 76, 58, 32, 105, 61, 37, 100, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_manual_unroll_loop.____fmt"]
static iter_manual_unroll_loop_____fmt: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 52, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_manual_unroll_loop.____fmt.1"]
static iter_manual_unroll_loop_____fmt_1: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 52, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_manual_unroll_loop.____fmt.2"]
static iter_manual_unroll_loop_____fmt_2: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 52, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_manual_unroll_loop.____fmt.3"]
static iter_manual_unroll_loop_____fmt_3: [i8; 26] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 52, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 10, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_multiple_sequential_loops.____fmt"]
static iter_multiple_sequential_loops_____fmt: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 49, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_multiple_sequential_loops.____fmt.4"]
static iter_multiple_sequential_loops_____fmt_4: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 50, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_multiple_sequential_loops.____fmt.5"]
static iter_multiple_sequential_loops_____fmt_5: [i8; 30] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 51, 32, 86, 65, 76, 58, 32, 105, 61, 37, 100, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_multiple_sequential_loops.____fmt.6"]
static iter_multiple_sequential_loops_____fmt_6: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 52, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_multiple_sequential_loops.____fmt.7"]
static iter_multiple_sequential_loops_____fmt_7: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 52, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_multiple_sequential_loops.____fmt.8"]
static iter_multiple_sequential_loops_____fmt_8: [i8; 25] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 52, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_multiple_sequential_loops.____fmt.9"]
static iter_multiple_sequential_loops_____fmt_9: [i8; 26] = [73, 84, 69, 82, 95, 66, 65, 83, 73, 67, 58, 32, 69, 52, 32, 86, 65, 76, 58, 32, 118, 61, 37, 100, 10, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_limit_cond_break_loop.____fmt"]
static iter_limit_cond_break_loop_____fmt: [i8; 23] = [73, 84, 69, 82, 95, 83, 73, 77, 80, 76, 69, 58, 32, 105, 61, 37, 100, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_limit_cond_break_loop.____fmt.10"]
static iter_limit_cond_break_loop_____fmt_10: [i8; 21] = [73, 84, 69, 82, 95, 83, 73, 77, 80, 76, 69, 58, 32, 115, 117, 109, 61, 37, 100, 10, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_obfuscate_counter.____fmt"]
static iter_obfuscate_counter_____fmt: [i8; 39] = [73, 84, 69, 82, 95, 79, 66, 70, 85, 83, 67, 65, 84, 69, 95, 67, 79, 85, 78, 84, 69, 82, 58, 32, 105, 61, 37, 100, 32, 118, 61, 37, 100, 32, 120, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_obfuscate_counter.____fmt.11"]
static iter_obfuscate_counter_____fmt_11: [i8; 32] = [73, 84, 69, 82, 95, 79, 66, 70, 85, 83, 67, 65, 84, 69, 95, 67, 79, 85, 78, 84, 69, 82, 58, 32, 115, 117, 109, 61, 37, 100, 10, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_search_loop.____fmt"]
static iter_search_loop_____fmt: [i8; 23] = [73, 84, 69, 82, 95, 83, 69, 65, 82, 67, 72, 95, 76, 79, 79, 80, 58, 32, 118, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_search_loop.____fmt.12"]
static iter_search_loop_____fmt_12: [i8; 34] = [73, 84, 69, 82, 95, 83, 69, 65, 82, 67, 72, 95, 76, 79, 79, 80, 58, 32, 70, 79, 85, 78, 68, 32, 73, 84, 32, 61, 32, 37, 100, 33, 10, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_search_loop.____fmt.13"]
static iter_search_loop_____fmt_13: [i8; 33] = [73, 84, 69, 82, 95, 83, 69, 65, 82, 67, 72, 95, 76, 79, 79, 80, 58, 32, 78, 79, 84, 32, 70, 79, 85, 78, 68, 32, 73, 84, 33, 10, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_array_fill.____fmt"]
static iter_array_fill_____fmt: [i8; 40] = [73, 84, 69, 82, 95, 65, 82, 82, 65, 89, 95, 70, 73, 76, 76, 58, 32, 115, 117, 109, 61, 37, 100, 32, 40, 115, 104, 111, 117, 108, 100, 32, 98, 101, 32, 37, 100, 41, 10, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_nested_iters.____fmt"]
static iter_nested_iters_____fmt: [i8; 32] = [73, 84, 69, 82, 95, 78, 69, 83, 84, 69, 68, 95, 73, 84, 69, 82, 83, 58, 32, 116, 111, 116, 97, 108, 32, 115, 117, 109, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_nested_iters.____fmt.14"]
static iter_nested_iters_____fmt_14: [i8; 34] = [73, 84, 69, 82, 95, 78, 69, 83, 84, 69, 68, 95, 73, 84, 69, 82, 83, 58, 32, 114, 111, 119, 32, 35, 37, 100, 32, 115, 117, 109, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_nested_iters.____fmt.15"]
static iter_nested_iters_____fmt_15: [i8; 36] = [73, 84, 69, 82, 95, 78, 69, 83, 84, 69, 68, 95, 73, 84, 69, 82, 83, 58, 32, 99, 111, 108, 32, 35, 37, 100, 32, 115, 117, 109, 61, 37, 100, 37, 115, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_subprog_iters.____fmt"]
static iter_subprog_iters_____fmt: [i8; 33] = [73, 84, 69, 82, 95, 83, 85, 66, 80, 82, 79, 71, 95, 73, 84, 69, 82, 83, 58, 32, 116, 111, 116, 97, 108, 32, 115, 117, 109, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_subprog_iters.____fmt.17"]
static iter_subprog_iters_____fmt_17: [i8; 35] = [73, 84, 69, 82, 95, 83, 85, 66, 80, 82, 79, 71, 95, 73, 84, 69, 82, 83, 58, 32, 114, 111, 119, 32, 35, 37, 100, 32, 115, 117, 109, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_subprog_iters.____fmt.18"]
static iter_subprog_iters_____fmt_18: [i8; 37] = [73, 84, 69, 82, 95, 83, 85, 66, 80, 82, 79, 71, 95, 73, 84, 69, 82, 83, 58, 32, 99, 111, 108, 32, 35, 37, 100, 32, 115, 117, 109, 61, 37, 100, 37, 115, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "iter_pass_iter_ptr_to_subprog.____fmt"]
static iter_pass_iter_ptr_to_subprog_____fmt: [i8; 17] = [115, 117, 109, 49, 61, 37, 100, 44, 32, 115, 117, 109, 50, 61, 37, 100, 0];

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "clean_live_states.____fmt"]
static clean_live_states_____fmt: [i8; 3] = [37, 115, 0];

extern "C" {
    fn bpf_iter_num_new(a0: *mut c_void, a1: i32, a2: i32) -> i32;
    fn bpf_iter_num_next(a0: *mut c_void) -> *mut c_void;
    fn bpf_iter_num_destroy(a0: *mut c_void);
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: iter_num_new_inlined
extern "C" fn iter_num_new_inlined() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -8;",
            "call 7;",
            "r3 = r0;",
            "r3 &= 0xffff;",
            "r1 = r6;",
            "r2 = 0;",
            "call {bpf_iter_num_new};",
            "1:",
            "r1 = r6;",
            "call {bpf_iter_num_next};",
            "if r0 != 0 goto 1b;",
            "r1 = r6;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: delayed_read_mark
extern "C" fn delayed_read_mark() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r7 = r10;",
            "r7 += -16;",
            "r0 = 0;",
            "*(u64 *)(r7 + 0) = r0;",
            "call 7;",
            "r6 = r0;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "1:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto 2f;",
            "r6 += 1;",
            "if r6 != 42 goto 3f;",
            "r7 = 0xdead;",
            "goto 1b;",
            "3:",
            "r1 = r7;",
            "r2 = 8;",
            "r3 = 0xdeadbeef;",
            "call 112;",
            "goto 1b;",
            "2:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: delayed_precision_mark
extern "C" fn delayed_precision_mark() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r8 = 0;",
            "*(u64 *)(r10 - 16) = r8;",
            "r7 = -16;",
            "call 7;",
            "r6 = r0;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "1:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto 2f;",
            "if r6 != 42 goto 3f;",
            "r7 = -33;",
            "call 7;",
            "r6 = r0;",
            "goto 1b;",
            "3:",
            "r0 = r10;",
            "r0 += r7;",
            "r8 = *(u64 *)(r0 + 0);",
            "call 7;",
            "r6 = r0;",
            "goto 1b;",
            "2:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = r8;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_state_deps1
extern "C" fn loop_state_deps1() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -16;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r6 = 0;",
            "r7 = 0;",
            "r8 = -24;",
            "j_loop_0:",
            "r1 = r10;",
            "r1 += -16;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto j_loop_end_0;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r6 = 0;",
            "r7 = 0;",
            "i_loop_0:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto i_loop_end_0;",
            "check_one_r6_0:",
            "if r6 != 1 goto check_zero_r6_0;",
            "r6 = 0;",
            "r7 = 1;",
            "goto i_loop_0;",
            "check_zero_r6_0:",
            "if r6 != 0 goto i_loop_0;",
            "r6 = 1;",
            "call 7;",
            "if r0 != 42 goto check_one_r7_0;",
            "goto i_loop_0;",
            "check_one_r7_0:",
            "if r7 != 1 goto i_loop_0;",
            "r0 = r10;",
            "r0 += r8;",
            "r1 = 7;",
            "*(u64 *)(r0 + 0) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r1 = r10;",
            "r1 += -16;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            "i_loop_end_0:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r6 = 0;",
            "r7 = 0;",
            "r8 = -25;",
            "goto j_loop_0;",
            "j_loop_end_0:",
            "r1 = r10;",
            "r1 += -16;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_state_deps2
extern "C" fn loop_state_deps2() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -16;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r6 = 0;",
            "r7 = 0;",
            "r8 = -24;",
            "j_loop_1:",
            "r1 = r10;",
            "r1 += -16;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto j_loop_end_1;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r6 = 0;",
            "r7 = 0;",
            "i_loop_1:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto i_loop_end_1;",
            "check_one_r6_1:",
            "if r6 != 1 goto check_zero_r6_1;",
            "r6 = 0;",
            "r7 = 1;",
            "goto i_loop_1;",
            "check_zero_r6_1:",
            "if r6 != 0 goto i_loop_1;",
            "r6 = 1;",
            "call 7;",
            "if r0 != 42 goto check_one_r7_1;",
            "goto i_loop_1;",
            "check_one_r7_1:",
            "if r7 != 1 goto i_loop_1;",
            "r0 = r10;",
            "r0 += r8;",
            "r1 = 7;",
            "*(u64 *)(r0 + 0) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r1 = r10;",
            "r1 += -16;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            "i_loop_end_1:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r6 = 0;",
            "r7 = 0;",
            "i2_loop_1:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto i2_loop_end_1;",
            "check2_one_r6_1:",
            "if r6 != 1 goto check2_zero_r6_1;",
            "r6 = 0;",
            "r7 = 1;",
            "goto i2_loop_1;",
            "check2_zero_r6_1:",
            "if r6 != 0 goto i2_loop_1;",
            "r6 = 1;",
            "call 7;",
            "if r0 != 42 goto check2_one_r7_1;",
            "goto i2_loop_1;",
            "check2_one_r7_1:",
            "if r7 != 1 goto i2_loop_1;",
            "r6 = 0;",
            "r8 = -25;",
            "goto i2_loop_1;",
            "i2_loop_end_1:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r6 = 0;",
            "r7 = 0;",
            "goto j_loop_1;",
            "j_loop_end_1:",
            "r1 = r10;",
            "r1 += -16;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_state_deps3
extern "C" fn loop_state_deps3() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "if r0 == 24 goto 2f;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 5;",
            "call {bpf_iter_num_new};",
            "1:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 != 0 goto 1b;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            "2:",
            "r0 = 10;",
            "3:",
            "r0 -= 1;",
            "if r0 != 0 goto 3b;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r8 = -24;",
            "main_loop_2:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto main_loop_end_2;",
            "call 7;",
            "if r0 == 77 goto unsafe_write_2;",
            "call 7;",
            "if r0 == 42 goto poison_r8_2;",
            "goto main_loop_2;",
            "main_loop_end_2:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            "unsafe_write_2:",
            "r0 = r10;",
            "r0 += r8;",
            "r1 = 7;",
            "*(u64 *)(r0 + 0) = r1;",
            "goto main_loop_end_2;",
            "poison_r8_2:",
            "r8 = -25;",
            "goto main_loop_2;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: triple_continue
extern "C" fn triple_continue() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "loop_3:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto loop_end_3;",
            "call 7;",
            "if r0 != 42 goto loop_3;",
            "call 7;",
            "if r0 != 42 goto loop_3;",
            "call 7;",
            "if r0 != 42 goto loop_3;",
            "r0 += 0;",
            "goto loop_3;",
            "loop_end_3:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: widen_spill
extern "C" fn widen_spill() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 16) = r0;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "loop_4:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto loop_end_4;",
            "r0 = *(u64 *)(r10 - 16);",
            "r0 += 1;",
            "*(u64 *)(r10 - 16) = r0;",
            "goto loop_4;",
            "loop_end_4:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: checkpoint_states_deletion
extern "C" fn checkpoint_states_deletion() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "r7 = 0;",
            "r8 = 0;",
            "*(u64 *)(r10 - 24) = r6;",
            "*(u64 *)(r10 - 32) = r6;",
            "*(u64 *)(r10 - 40) = r6;",
            "r9 = 0;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "loop_5:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto loop_end_5;",
            "*(u64 *)(r10 - 16) = r0;",
            "r1 = {amap} ll;",
            "r2 = r10;",
            "r2 += -16;",
            "call 1;",
            "r6 = r0;",
            "r1 = {amap} ll;",
            "r2 = r10;",
            "r2 += -16;",
            "call 1;",
            "r7 = r0;",
            "r1 = {amap} ll;",
            "r2 = r10;",
            "r2 += -16;",
            "call 1;",
            "r8 = r0;",
            "r1 = {amap} ll;",
            "r2 = r10;",
            "r2 += -16;",
            "call 1;",
            "*(u64 *)(r10 - 24) = r0;",
            "r1 = {amap} ll;",
            "r2 = r10;",
            "r2 += -16;",
            "call 1;",
            "*(u64 *)(r10 - 32) = r0;",
            "r1 = {amap} ll;",
            "r2 = r10;",
            "r2 += -16;",
            "call 1;",
            "*(u64 *)(r10 - 40) = r0;",
            "if r6 == 0 goto +1;",
            "r9 += 1;",
            "if r7 == 0 goto +1;",
            "r9 += 1;",
            "if r8 == 0 goto +1;",
            "r9 += 1;",
            "r0 = *(u64 *)(r10 - 24);",
            "if r0 == 0 goto +1;",
            "r9 += 1;",
            "r0 = *(u64 *)(r10 - 32);",
            "if r0 == 0 goto +1;",
            "r9 += 1;",
            "r0 = *(u64 *)(r10 - 40);",
            "if r0 == 0 goto +1;",
            "r9 += 1;",
            "goto loop_5;",
            "loop_end_5:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            amap = sym amap,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: absent_mark_in_the_middle_state
extern "C" fn absent_mark_in_the_middle_state() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r8 = r0;",
            "r7 = 0;",
            "r6 = -32;",
            "r0 = 0;",
            "*(u64 *)(r10 - 16) = r0;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "call 7;",
            "if r0 == r8 goto change_r6_6;",
            "loop_6:",
            "call {noop};",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto loop_end_6;",
            "call 7;",
            "if r0 == r8 goto use_r6_6;",
            "goto loop_6;",
            "loop_end_6:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            "use_r6_6:",
            "r0 = r10;",
            "r0 += r6;",
            "r1 = 7;",
            "*(u64 *)(r0 + 0) = r1;",
            "goto loop_6;",
            "change_r6_6:",
            "r6 = -31;",
            "goto loop_6;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            noop = sym noop,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: noop
extern "C" fn noop() -> i32 {
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

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: absent_mark_in_the_middle_state2
extern "C" fn absent_mark_in_the_middle_state2() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r8 = r0;",
            "r7 = 0;",
            "r6 = -32;",
            "r0 = 0;",
            "*(u64 *)(r10 - 16) = r0;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "call 7;",
            "if r0 == r8 goto change_r6_7;",
            "call 7;",
            "if r0 == r8 goto jump_into_loop_7;",
            "loop_7:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto loop_end_7;",
            "call 7;",
            "if r0 == r8 goto use_r6_7;",
            "goto loop_7;",
            "loop_end_7:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            "use_r6_7:",
            "r0 = r10;",
            "r0 += r6;",
            "r1 = 7;",
            "*(u64 *)(r0 + 0) = r1;",
            "goto loop_7;",
            "change_r6_7:",
            "r6 = -31;",
            "jump_into_loop_7:",
            "goto +0;",
            "goto loop_7;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "?raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: absent_mark_in_the_middle_state3
extern "C" fn absent_mark_in_the_middle_state3() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r1 = -32;",
            "r2 = r10;",
            "r2 += -8;",
            "call {loop1};",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r1 = r10;",
            "r1 += -8;",
            "call {loop1_wrapper};",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            loop1 = sym loop1,
            loop1_wrapper = sym loop1_wrapper,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop1
extern "C" fn loop1() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = r2;",
            "call 7;",
            "r8 = r0;",
            "loop_8:",
            "r1 = r7;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto loop_end_8;",
            "call 7;",
            "if r0 == r8 goto use_r6_8;",
            "goto loop_8;",
            "loop_end_8:",
            "r0 = 0;",
            "exit;",
            "use_r6_8:",
            "r0 = r10;",
            "r0 += r6;",
            "r1 = 7;",
            "*(u64 *)(r0 + 0) = r1;",
            "goto loop_8;",
            bpf_iter_num_next = sym bpf_iter_num_next,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop1_wrapper
extern "C" fn loop1_wrapper() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = -32;",
            "r7 = r1;",
            "call 7;",
            "r8 = r0;",
            "call 7;",
            "if r0 == r8 goto change_r6_9;",
            "loop_9:",
            "r1 = r6;",
            "r2 = r7;",
            "call {loop1};",
            "r0 = 0;",
            "exit;",
            "change_r6_9:",
            "r6 = -31;",
            "goto loop_9;",
            loop1 = sym loop1,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: absent_mark_in_the_middle_state4
extern "C" fn absent_mark_in_the_middle_state4() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r8 = r0;",
            "*(u64 *)(r10 - 8) = r0;",
            "*(u64 *)(r10 - 16) = -32;",
            "r1 = 7;",
            "r2 = {loop_cb4} ll;",
            "r3 = r10;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            loop_cb4 = sym loop_cb4,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_cb4
extern "C" fn loop_cb4() {
    unsafe {
        core::arch::asm!(
            "r9 = r2;",
            "r8 = *(u64 *)(r9 - 8);",
            "r6 = *(u64 *)(r9 - 16);",
            "call 7;",
            "if r0 > r8 goto use_fp16_10;",
            "1:",
            "call 7;",
            "if r0 > r8 goto update_fp16_10;",
            "2:",
            "r0 = 0;",
            "exit;",
            "use_fp16_10:",
            "r1 = r10;",
            "r1 += r6;",
            "*(u64 *)(r1 + 0) = 42;",
            "goto 1b;",
            "update_fp16_10:",
            "*(u64 *)(r9 - 16) = -31;",
            "goto 2b;",
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_misc_vs_scalar_in_a_loop
extern "C" fn stack_misc_vs_scalar_in_a_loop() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "*(u8 *)(r10 - 15) = 1;",
            "*(u8 *)(r10 - 23) = 1;",
            "*(u8 *)(r10 - 31) = 1;",
            "*(u8 *)(r10 - 39) = 1;",
            "*(u8 *)(r10 - 47) = 1;",
            "*(u8 *)(r10 - 55) = 1;",
            "*(u8 *)(r10 - 63) = 1;",
            "*(u8 *)(r10 - 71) = 1;",
            "*(u8 *)(r10 - 79) = 1;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "loop_11:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto loop_end_11;",
            "call 7;",
            "if r0 == 42 goto +1;",
            "goto +1;",
            "*(u64 *)(r10 -16) = r0;",
            "call 7;",
            "if r0 == 42 goto +1;",
            "goto +1;",
            "*(u64 *)(r10 -24) = r0;",
            "call 7;",
            "if r0 == 42 goto +1;",
            "goto +1;",
            "*(u64 *)(r10 -32) = r0;",
            "call 7;",
            "if r0 == 42 goto +1;",
            "goto +1;",
            "*(u64 *)(r10 -40) = r0;",
            "call 7;",
            "if r0 == 42 goto +1;",
            "goto +1;",
            "*(u64 *)(r10 -48) = r0;",
            "call 7;",
            "if r0 == 42 goto +1;",
            "goto +1;",
            "*(u64 *)(r10 -56) = r0;",
            "call 7;",
            "if r0 == 42 goto +1;",
            "goto +1;",
            "*(u64 *)(r10 -64) = r0;",
            "call 7;",
            "if r0 == 42 goto +1;",
            "goto +1;",
            "*(u64 *)(r10 -72) = r0;",
            "call 7;",
            "if r0 == 42 goto +1;",
            "goto +1;",
            "*(u64 *)(r10 -80) = r0;",
            "goto loop_11;",
            "loop_end_11:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: loop_counter_precision_2nd_iter
extern "C" fn loop_counter_precision_2nd_iter() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = 2;",
            "if r0 == 42 goto +1;",
            "r1 = 1;",
            "r2 = {loop_cb5} ll;",
            "r3 = r10;",
            "r3 += -8;",
            "r4 = 0;",
            "call 181;",
            "r0 = 0;",
            "exit;",
            loop_cb5 = sym loop_cb5,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: iter_remake_jmp
extern "C" fn iter_remake_jmp() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "1:",
            "call 5;",
            "if r0 != 0 goto 3f;",
            "r1 = r10;",
            "r1 += -8;",
            "2:",
            "call {bpf_iter_num_next};",
            "if r0 != 0 goto 1b;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            "3:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r1 = r10;",
            "r1 += -8;",
            "goto 2b;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: iter_remake
extern "C" fn iter_remake() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "call {bpf_iter_num_destroy};",
            "r1 = r6;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: iter_remake_callee_jmp
extern "C" fn iter_remake_callee_jmp() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "1:",
            "call 5;",
            "if r0 != 0 goto 3f;",
            "r1 = r10;",
            "r1 += -8;",
            "2:",
            "call {bpf_iter_num_next};",
            "if r0 != 0 goto 1b;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            "3:",
            "r1 = r10;",
            "r1 += -8;",
            "call {iter_remake};",
            "r1 = r10;",
            "r1 += -8;",
            "goto 2b;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            iter_remake = sym iter_remake,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: iter_remake_after_next_jmp
extern "C" fn iter_remake_after_next_jmp() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r1 = r10;",
            "r1 += -8;",
            "1:",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto 2f;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r1 = r10;",
            "r1 += -8;",
            "goto 1b;",
            "2:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: iter_remake_two_jmp
extern "C" fn iter_remake_two_jmp() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r1 = r10;",
            "r1 += -16;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r1 = r10;",
            "r1 += -8;",
            "1:",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto 2f;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r1 = r10;",
            "r1 += -16;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto 2f;",
            "r1 = r10;",
            "r1 += -16;",
            "call {bpf_iter_num_destroy};",
            "r1 = r10;",
            "r1 += -16;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "r1 = r10;",
            "r1 += -8;",
            "goto 1b;",
            "2:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r1 = r10;",
            "r1 += -16;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: iter_remake_inline
extern "C" fn iter_remake_inline() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "1:",
            "call 5;",
            "if r0 == 0 goto 2f;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "2:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 != 0 goto 1b;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: iter_remake_callee
extern "C" fn iter_remake_callee() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "1:",
            "call 5;",
            "if r0 == 0 goto 2f;",
            "r1 = r10;",
            "r1 += -8;",
            "call {iter_remake};",
            "2:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 != 0 goto 1b;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            iter_remake = sym iter_remake,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: iter_remake_after_next
extern "C" fn iter_remake_after_next() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "1:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 == 0 goto 2f;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "goto 1b;",
            "2:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: iter_remake_drained
extern "C" fn iter_remake_drained() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "1:",
            "call 5;",
            "if r0 == 119 goto 2f;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_next};",
            "if r0 != 0 goto 1b;",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 10;",
            "call {bpf_iter_num_new};",
            "goto 1b;",
            "2:",
            "r1 = r10;",
            "r1 += -8;",
            "call {bpf_iter_num_destroy};",
            "r0 = 0;",
            "exit;",
            bpf_iter_num_new = sym bpf_iter_num_new,
            bpf_iter_num_next = sym bpf_iter_num_next,
            bpf_iter_num_destroy = sym bpf_iter_num_destroy,
            options(nostack)
        );
    }
}

include!("hand/iters.rs");

bpf_object!("GPL");
