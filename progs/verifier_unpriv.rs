// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_unpriv.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_unpriv.rs
// (include!d below): pseudo_func_callback, unpriv_pseudo_func_policy, nospec_global_func.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_unpriv` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: dummy_prog_42_socket dummy_prog_24_socket dummy_prog_loop1_socket pseudo_btf_id_log_masks_address pseudo_func_callback unpriv_pseudo_func_policy unpriv_return_pointer unpriv_add_const_to_pointer unpriv_add_pointer_to_pointer unpriv_neg_pointer unpriv_cmp_pointer_with_const unpriv_cmp_pointer_with_pointer check_that_printk_is_disallowed pass_pointer_to_helper_function on_stack_to_helper_function mangle_pointer_on_stack_1 mangle_pointer_on_stack_2 from_stack_in_small_chunks unpriv_write_pointer_into_ctx unpriv_spill_fill_of_ctx spill_fill_of_ctx_2 spill_fill_of_ctx_3 spill_fill_of_ctx_4 fill_of_different_pointers_stx fill_of_different_pointers_st pointers_stx_ctx_and_sock different_pointers_stx_leak_sock stx_sock_and_ctx_read stx_sock_and_ctx_write pointer_into_map_elem_value alu32_mov_u32_const unpriv_partial_copy_of_pointer pass_pointer_to_tail_call cmp_map_pointer_with_zero cmp_map_pointer_with_const unpriv_write_into_frame_pointer unpriv_spill_fill_frame_pointer unpriv_cmp_of_frame_pointer unpriv_adding_of_fp_reg unpriv_adding_of_fp_imm unpriv_cmp_of_stack_pointer unpriv_spec_v1_type_confusion unpriv_ldimm64_spectre_v4 unpriv_spectre_v1_and_v4 unpriv_spectre_v1_and_v4_simple unpriv_ldimm64_spectre_v1_and_v4_simple unpriv_dead_helper_stack_write_nospec_result stack_write_nospec_slot_index nospec_global_func nospec_call_subprog nospec_backward_call

// BTF_KSYM: bpf_prog_active

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
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
    pseudo_btf_id_log_masks_address:
        __description("unpriv: pseudo btf id log masks address"),
        __success_unpriv,
        __msg_unpriv("0: (18) r1 = 0x0"),
        __not_msg_unpriv("0: (18) r1 = 0x{{[1-9a-f][0-9a-f]*}}"),
        __retval_unpriv("0"),
        __log_level("2");
    unpriv_pseudo_func_policy:
        __description("unpriv: pseudo function policy diagnostic"),
        __success,
        __failure_unpriv,
        __msg_unpriv("loading/calling other bpf or kernel functions"),
        __not_msg_unpriv("BPF-to-BPF function call"),
        __msg_unpriv("policy check failed for BPF function reference"),
        __msg_unpriv("avoid BPF function references in unprivileged");
    unpriv_return_pointer:
        __description("unpriv: return pointer"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0xbadcafe");
    unpriv_add_const_to_pointer:
        __description("unpriv: add const to pointer"),
        __success,
        __success_unpriv,
        __retval("0");
    unpriv_add_pointer_to_pointer:
        __description("unpriv: add pointer to pointer"),
        __failure,
        __msg("R1 pointer += pointer"),
        __failure_unpriv;
    unpriv_neg_pointer:
        __description("unpriv: neg pointer"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 pointer arithmetic"),
        __retval("0");
    unpriv_cmp_pointer_with_const:
        __description("unpriv: cmp pointer with const"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 pointer comparison"),
        __retval("0");
    unpriv_cmp_pointer_with_pointer:
        __description("unpriv: cmp pointer with pointer"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R10 pointer comparison"),
        __retval("0");
    check_that_printk_is_disallowed:
        __description("unpriv: check that printk is disallowed"),
        __success;
    pass_pointer_to_helper_function:
        __description("unpriv: pass pointer to helper function"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R4 leaks addr"),
        __retval("0");
    on_stack_to_helper_function:
        __description("unpriv: indirectly pass pointer on stack to helper function"),
        __success,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack R2 off -8+0 size 8"),
        __retval("0");
    mangle_pointer_on_stack_1:
        __description("unpriv: mangle pointer on stack 1"),
        __success,
        __failure_unpriv,
        __msg_unpriv("attempt to corrupt spilled"),
        __retval("0");
    mangle_pointer_on_stack_2:
        __description("unpriv: mangle pointer on stack 2"),
        __success,
        __failure_unpriv,
        __msg_unpriv("attempt to corrupt spilled"),
        __retval("0");
    from_stack_in_small_chunks:
        __description("unpriv: read pointer from stack in small chunks"),
        __failure,
        __msg("invalid size"),
        __failure_unpriv;
    unpriv_write_pointer_into_ctx:
        __description("unpriv: write pointer into ctx"),
        __failure,
        __msg("invalid bpf_context access"),
        __failure_unpriv,
        __msg_unpriv("R1 leaks addr");
    unpriv_spill_fill_of_ctx:
        __description("unpriv: spill/fill of ctx"),
        __success,
        __success_unpriv,
        __retval("0");
    spill_fill_of_ctx_2:
        __description("unpriv: spill/fill of ctx 2"),
        __success,
        __retval("0");
    spill_fill_of_ctx_3:
        __description("unpriv: spill/fill of ctx 3"),
        __failure,
        __msg("R1 type=fp expected=ctx");
    spill_fill_of_ctx_4:
        __description("unpriv: spill/fill of ctx 4"),
        __failure,
        __msg("R1 type=scalar expected=ctx");
    fill_of_different_pointers_stx:
        __description("unpriv: spill/fill of different pointers stx"),
        __failure,
        __msg("same insn cannot be used with different pointers");
    fill_of_different_pointers_st:
        __description("unpriv: spill/fill of different pointers st"),
        __failure,
        __msg("same insn cannot be used with different pointers");
    pointers_stx_ctx_and_sock:
        __description("unpriv: spill/fill of different pointers stx - ctx and sock"),
        __failure,
        __msg("type=ctx expected=sock");
    different_pointers_stx_leak_sock:
        __description("unpriv: spill/fill of different pointers stx - leak sock"),
        __failure,
        __msg("Unreleased reference");
    stx_sock_and_ctx_read:
        __description("unpriv: spill/fill of different pointers stx - sock and ctx (read)"),
        __failure,
        __msg("same insn cannot be used with different pointers");
    stx_sock_and_ctx_write:
        __description("unpriv: spill/fill of different pointers stx - sock and ctx (write)"),
        __failure,
        __msg("cannot write into sock");
    pointer_into_map_elem_value:
        __description("unpriv: write pointer into map elem value"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R0 leaks addr"),
        __retval("0");
    alu32_mov_u32_const:
        __description("alu32: mov u32 const"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("if r0 == 0x0 goto pc+2"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("exit");
    unpriv_partial_copy_of_pointer:
        __description("unpriv: partial copy of pointer"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R10 partial copy"),
        __retval("0");
    pass_pointer_to_tail_call:
        __description("unpriv: pass pointer to tail_call"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R3 leaks addr into helper"),
        __retval("0");
    cmp_map_pointer_with_zero:
        __description("unpriv: cmp map pointer with zero"),
        __success,
        __success_unpriv,
        __retval("0");
    cmp_map_pointer_with_const:
        __description("unpriv: cmp map pointer with const"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 pointer comparison prohibited"),
        __retval("0");
    unpriv_write_into_frame_pointer:
        __description("unpriv: write into frame pointer"),
        __failure,
        __msg("frame pointer is read only"),
        __failure_unpriv;
    unpriv_spill_fill_frame_pointer:
        __description("unpriv: spill/fill frame pointer"),
        __failure,
        __msg("frame pointer is read only"),
        __failure_unpriv;
    unpriv_cmp_of_frame_pointer:
        __description("unpriv: cmp of frame pointer"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R10 pointer comparison"),
        __retval("0");
    unpriv_adding_of_fp_reg:
        __description("unpriv: adding of fp, reg"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 stack pointer arithmetic goes out of range"),
        __retval("0");
    unpriv_adding_of_fp_imm:
        __description("unpriv: adding of fp, imm"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 stack pointer arithmetic goes out of range"),
        __retval("0");
    unpriv_cmp_of_stack_pointer:
        __description("unpriv: cmp of stack pointer"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R2 pointer comparison"),
        __retval("0");
    unpriv_spec_v1_type_confusion:
        __description("unpriv: Spectre v1 path-based type confusion of scalar as stack-ptr"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("if r0 != 0x1 goto pc+2"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("r9 = *(u8 *)(r6 +0)");
    unpriv_ldimm64_spectre_v4:
        __description("unpriv: ldimm64 before Spectre v4 barrier"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("r1 = 0x2020200005642020"),
        __xlated_unpriv("*(u64 *)(r10 -8) = r1"),
        __xlated_unpriv("nospec");
    unpriv_spectre_v1_and_v4:
        __description("unpriv: Spectre v1 and v4 barrier"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("if r8 != 0x0 goto pc+1"),
        __xlated_unpriv("goto pc+2"),
        __xlated_unpriv("if r9 == 0x0 goto pc+4"),
        __xlated_unpriv("r2 = r0"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("*(u64 *)(r2 -64) = r1"),
        __xlated_unpriv("nospec");
    unpriv_spectre_v1_and_v4_simple:
        __description("unpriv: Spectre v1 and v4 barrier (simple)"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("if r8 != 0x0 goto pc+1"),
        __xlated_unpriv("goto pc+2"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("*(u64 *)(r2 -64) = r1"),
        __xlated_unpriv("nospec");
    unpriv_ldimm64_spectre_v1_and_v4_simple:
        __description("unpriv: ldimm64 before Spectre v1 and v4 barrier (simple)"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("if r8 != 0x0 goto pc+1"),
        __xlated_unpriv("goto pc+4"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("goto pc-1"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("*(u64 *)(r2 -64) = r1"),
        __xlated_unpriv("nospec");
    unpriv_dead_helper_stack_write_nospec_result:
        __description("unpriv: nospec after dead stack write in helper"),
        __success,
        __success_unpriv,
        __retval("0");
    stack_write_nospec_slot_index:
        __description("unpriv: Spectre v4 stack write slot index"),
        __success,
        __success_unpriv,
        __retval("0"),
        __xlated_unpriv("r0 = 0"),
        __xlated_unpriv("*(u32 *)(r10 -4) = r0"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("*(u32 *)(r10 -8) = r0"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("exit");
    nospec_backward_call:
        __description("unpriv: nospec in front of a call"),
        __success,
        __success_unpriv,
        __caps_unpriv("39"),
        __retval("1");
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

bpf_map! {
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
}

extern "C" {
    static bpf_prog_active: i32;
}

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
// BPF_NAKED: pseudo_btf_id_log_masks_address
extern "C" fn pseudo_btf_id_log_masks_address() {
    unsafe {
        core::arch::asm!(
            "r1 = {bpf_prog_active} ll;",
            "r0 = 0;",
            "exit;",
            bpf_prog_active = sym bpf_prog_active,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_return_pointer
extern "C" fn unpriv_return_pointer() {
    unsafe {
        core::arch::asm!(
            "r0 = r10;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_add_const_to_pointer
extern "C" fn unpriv_add_const_to_pointer() {
    unsafe {
        core::arch::asm!(
            "r1 += 8;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_add_pointer_to_pointer
extern "C" fn unpriv_add_pointer_to_pointer() {
    unsafe {
        core::arch::asm!(
            "r1 += r10;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_neg_pointer
extern "C" fn unpriv_neg_pointer() {
    unsafe {
        core::arch::asm!(
            "r1 = -r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_cmp_pointer_with_const
extern "C" fn unpriv_cmp_pointer_with_const() {
    unsafe {
        core::arch::asm!(
            "if r1 == 0 goto l0_0;",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_cmp_pointer_with_pointer
extern "C" fn unpriv_cmp_pointer_with_pointer() {
    unsafe {
        core::arch::asm!(
            "if r1 == r10 goto l0_1;",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_that_printk_is_disallowed
extern "C" fn check_that_printk_is_disallowed() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 8;",
            "r3 = r1;",
            "call 6;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pass_pointer_to_helper_function
extern "C" fn pass_pointer_to_helper_function() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "r3 = r2;",
            "r4 = r2;",
            "call 2;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: on_stack_to_helper_function
extern "C" fn on_stack_to_helper_function() {
    unsafe {
        core::arch::asm!(
            "*(u64*)(r10 - 8) = r10;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mangle_pointer_on_stack_1
extern "C" fn mangle_pointer_on_stack_1() {
    unsafe {
        core::arch::asm!(
            "*(u64*)(r10 - 8) = r10;",
            "r0 = 0;",
            "*(u32*)(r10 - 8) = r0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mangle_pointer_on_stack_2
extern "C" fn mangle_pointer_on_stack_2() {
    unsafe {
        core::arch::asm!(
            "*(u64*)(r10 - 8) = r10;",
            "r0 = 0;",
            "*(u8*)(r10 - 1) = r0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: from_stack_in_small_chunks
extern "C" fn from_stack_in_small_chunks() {
    unsafe {
        core::arch::asm!(
            "*(u64*)(r10 - 8) = r10;",
            "r0 = *(u32*)(r10 - 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_write_pointer_into_ctx
extern "C" fn unpriv_write_pointer_into_ctx() {
    unsafe {
        core::arch::asm!(
            "*(u64*)(r1 + 0) = r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_spill_fill_of_ctx
extern "C" fn unpriv_spill_fill_of_ctx() {
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -8;",
            "*(u64*)(r6 + 0) = r1;",
            "r1 = *(u64*)(r6 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_fill_of_ctx_2
extern "C" fn spill_fill_of_ctx_2() {
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -8;",
            "*(u64*)(r6 + 0) = r1;",
            "r1 = *(u64*)(r6 + 0);",
            "call 34;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_fill_of_ctx_3
extern "C" fn spill_fill_of_ctx_3() {
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -8;",
            "*(u64*)(r6 + 0) = r1;",
            "*(u64*)(r6 + 0) = r10;",
            "r1 = *(u64*)(r6 + 0);",
            "call 34;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: spill_fill_of_ctx_4
extern "C" fn spill_fill_of_ctx_4() {
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -8;",
            "*(u64*)(r6 + 0) = r1;",
            "r0 = 1;",
            "lock *(u64 *)(r10 - 8) += r0;",
            "r1 = *(u64*)(r6 + 0);",
            "call 34;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fill_of_different_pointers_stx
extern "C" fn fill_of_different_pointers_stx() {
    unsafe {
        core::arch::asm!(
            "r3 = 42;",
            "r6 = r10;",
            "r6 += -8;",
            "if r1 == 0 goto l0_2;",
            "r2 = r10;",
            "r2 += -16;",
            "*(u64*)(r6 + 0) = r2;",
            "l0_2:",
            "if r1 != 0 goto l1_2;",
            "*(u64*)(r6 + 0) = r1;",
            "l1_2:",
            "r1 = *(u64*)(r6 + 0);",
            "*(u32*)(r1 + 8) = r3;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fill_of_different_pointers_st
extern "C" fn fill_of_different_pointers_st() {
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -8;",
            "if r1 == 0 goto l0_3;",
            "r2 = r10;",
            "r2 += -16;",
            "*(u64*)(r6 + 0) = r2;",
            "l0_3:",
            "if r1 != 0 goto l1_3;",
            "*(u64*)(r6 + 0) = r1;",
            "l1_3:",
            "r1 = *(u64*)(r6 + 0);",
            ".8byte 180389151074;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pointers_stx_ctx_and_sock
extern "C" fn pointers_stx_ctx_and_sock() {
    unsafe {
        core::arch::asm!(
            "r8 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r2 = r0;",
            "r6 = r10;",
            "r6 += -8;",
            "r1 = r8;",
            "if r1 == 0 goto l0_4;",
            "*(u64*)(r6 + 0) = r2;",
            "l0_4:",
            "if r1 != 0 goto l1_4;",
            "*(u64*)(r6 + 0) = r1;",
            "l1_4:",
            "r1 = *(u64*)(r6 + 0);",
            "r3 = 42;",
            "*(u32*)(r1 + 8) = r3;",
            "if r1 == 0 goto l2_4;",
            "call 86;",
            "l2_4:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: different_pointers_stx_leak_sock
extern "C" fn different_pointers_stx_leak_sock() {
    unsafe {
        core::arch::asm!(
            "r8 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r2 = r0;",
            "r6 = r10;",
            "r6 += -8;",
            "r1 = r8;",
            "if r1 == 0 goto l0_5;",
            "*(u64*)(r6 + 0) = r2;",
            "l0_5:",
            "if r1 != 0 goto l1_5;",
            "*(u64*)(r6 + 0) = r1;",
            "l1_5:",
            "r1 = *(u64*)(r6 + 0);",
            "r3 = 42;",
            "*(u32*)(r1 + 8) = r3;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stx_sock_and_ctx_read
extern "C" fn stx_sock_and_ctx_read() {
    unsafe {
        core::arch::asm!(
            "r8 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r2 = r0;",
            "r6 = r10;",
            "r6 += -8;",
            "r1 = r8;",
            "if r1 == 0 goto l0_6;",
            "*(u64*)(r6 + 0) = r1;",
            "l0_6:",
            "if r1 != 0 goto l1_6;",
            "*(u64*)(r6 + 0) = r2;",
            "l1_6:",
            "r1 = *(u64*)(r6 + 0);",
            "if r1 == 0 goto l2_6;",
            "r3 = *(u32*)(r1 + 16);",
            "call 86;",
            "l2_6:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stx_sock_and_ctx_write
extern "C" fn stx_sock_and_ctx_write() {
    unsafe {
        core::arch::asm!(
            "r8 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r2 = r0;",
            "r6 = r10;",
            "r6 += -8;",
            "r1 = r8;",
            "if r1 == 0 goto l0_7;",
            "*(u64*)(r6 + 0) = r1;",
            "l0_7:",
            "if r1 != 0 goto l1_7;",
            "*(u64*)(r6 + 0) = r2;",
            "l1_7:",
            "r1 = *(u64*)(r6 + 0);",
            "if r1 == 0 goto l2_7;",
            "r3 = 42;",
            "*(u32*)(r1 + 16) = r3;",
            "call 86;",
            "l2_7:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pointer_into_map_elem_value
extern "C" fn pointer_into_map_elem_value() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_8;",
            "*(u64*)(r0 + 0) = r0;",
            "l0_8:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: alu32_mov_u32_const
extern "C" fn alu32_mov_u32_const() {
    unsafe {
        core::arch::asm!(
            "w7 = 0;",
            "w7 ^= w7;",
            "w0 = w7;",
            "if r0 == 0 goto l0_9;",
            "r0 = *(u64*)(r7 + 0);",
            "l0_9:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_partial_copy_of_pointer
extern "C" fn unpriv_partial_copy_of_pointer() {
    unsafe {
        core::arch::asm!(
            "w1 = w10;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pass_pointer_to_tail_call
extern "C" fn pass_pointer_to_tail_call() {
    unsafe {
        core::arch::asm!(
            "r3 = r1;",
            "r2 = {map_prog1_socket} ll;",
            "call 12;",
            "r0 = 0;",
            "exit;",
            map_prog1_socket = sym map_prog1_socket,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: cmp_map_pointer_with_zero
extern "C" fn cmp_map_pointer_with_zero() {
    unsafe {
        core::arch::asm!(
            "r1 = {map_hash_8b} ll;",
            "if r1 == 0 goto l0_10;",
            "l0_10:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: cmp_map_pointer_with_const
extern "C" fn cmp_map_pointer_with_const() {
    unsafe {
        core::arch::asm!(
            "r1 = {map_hash_8b} ll;",
            "if r1 == 0x0000beef goto l0_11;",
            "l0_11:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_write_into_frame_pointer
extern "C" fn unpriv_write_into_frame_pointer() {
    unsafe {
        core::arch::asm!(
            "r10 = r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_spill_fill_frame_pointer
extern "C" fn unpriv_spill_fill_frame_pointer() {
    unsafe {
        core::arch::asm!(
            "r6 = r10;",
            "r6 += -8;",
            "*(u64*)(r6 + 0) = r10;",
            "r10 = *(u64*)(r6 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_cmp_of_frame_pointer
extern "C" fn unpriv_cmp_of_frame_pointer() {
    unsafe {
        core::arch::asm!(
            "if r10 == 0 goto l0_12;",
            "l0_12:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_adding_of_fp_reg
extern "C" fn unpriv_adding_of_fp_reg() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = 0;",
            "r1 += r10;",
            "*(u64*)(r1 - 8) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_adding_of_fp_imm
extern "C" fn unpriv_adding_of_fp_imm() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = r10;",
            "r1 += 0;",
            "*(u64*)(r1 - 8) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_cmp_of_stack_pointer
extern "C" fn unpriv_cmp_of_stack_pointer() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "if r2 == 0 goto l0_13;",
            "l0_13:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_spec_v1_type_confusion
extern "C" fn unpriv_spec_v1_type_confusion() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l2_14;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "r6 = r10;",
            "r6 += -8;",
            "r9 = 0xffffc900;",
            "r9 <<= 32;",
            "r0 = *(u64 *)(r0 + 0);",
            "if r0 != 0x0 goto l0_14;",
            "r6 = r9;",
            "l0_14:",
            "if r0 != 0x1 goto l1_14;",
            "r9 = *(u8 *)(r6 + 0);",
            "l1_14:",
            "r9 &= 1;",
            "r9 <<= 9;",
            "*(u64*)(r10 - 8) = r9;",
            "call 1;",
            "if r0 == 0 goto l2_14;",
            "r0 = *(u64 *)(r0 + 0);",
            "l2_14:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_ldimm64_spectre_v4
extern "C" fn unpriv_ldimm64_spectre_v4() {
    unsafe {
        core::arch::asm!(
            "r1 = 0x2020200005642020 ll;",
            "*(u64 *)(r10 -8) = r1;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_spectre_v1_and_v4
extern "C" fn unpriv_spectre_v1_and_v4() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r8 = r0;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r9 = r0;",
            "r0 = r10;",
            "r1 = 0;",
            "r2 = r10;",
            "if r8 != 0 goto l0_15;",
            "if r9 != 0 goto l0_15;",
            "r0 = 0;",
            "l0_15:",
            "if r8 != 0 goto l1_15;",
            "goto l2_15;",
            "l1_15:",
            "if r9 == 0 goto l3_15;",
            "r2 = r0;",
            "l2_15:",
            "*(u64 *)(r2 -64) = r1;",
            "l3_15:",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_spectre_v1_and_v4_simple
extern "C" fn unpriv_spectre_v1_and_v4_simple() {
    unsafe {
        core::arch::asm!(
            "r8 = 0;",
            "r8 ^= r8;",
            "r9 = 0;",
            "r9 ^= r9;",
            "r0 = r10;",
            "r1 = 0;",
            "r2 = r10;",
            "if r8 != 0 goto l0_16;",
            "if r9 != 0 goto l0_16;",
            "r0 = 0;",
            "l0_16:",
            "if r8 != 0 goto l1_16;",
            "goto l2_16;",
            "l1_16:",
            "if r9 == 0 goto l3_16;",
            "r2 = r0;",
            "l2_16:",
            "*(u64 *)(r2 -64) = r1;",
            "l3_16:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_ldimm64_spectre_v1_and_v4_simple
extern "C" fn unpriv_ldimm64_spectre_v1_and_v4_simple() {
    unsafe {
        core::arch::asm!(
            "r8 = 0;",
            "r8 ^= r8;",
            "r9 = 0;",
            "r9 ^= r9;",
            "r0 = r10;",
            "r1 = 0;",
            "r2 = r10;",
            "if r8 != 0 goto l0_17;",
            "if r9 != 0 goto l0_17;",
            "r0 = 0;",
            "l0_17:",
            "if r8 != 0 goto l1_17;",
            "goto l2_17;",
            "l1_17:",
            "if r9 == 0 goto l3_17;",
            "r2 = r0;",
            "r1 = 0x2020200005642020 ll;",
            "l2_17:",
            "*(u64 *)(r2 -64) = r1;",
            "l3_17:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unpriv_dead_helper_stack_write_nospec_result
extern "C" fn unpriv_dead_helper_stack_write_nospec_result() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r0 != 1 goto l0_18;",
            "r2 = 0;",
            "r3 = r10;",
            "r3 += -16;",
            "r4 = 4;",
            "r5 = 0;",
            "call 68;",
            "l0_18:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_write_nospec_slot_index
extern "C" fn stack_write_nospec_slot_index() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u32 *)(r10 - 4) = r0;",
            "*(u32 *)(r10 - 8) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: nospec_call_subprog
extern "C" fn nospec_call_subprog() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0xff;",
            "r1 = 0;",
            "if r0 < 0x100 goto l0_19;",
            "r1 = r10;",
            "l0_19:",
            "call {nospec_global_func};",
            "exit;",
            nospec_global_func = sym nospec_global_func,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: nospec_backward_call
extern "C" fn nospec_backward_call() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "call {nospec_global_func};",
            "call {nospec_call_subprog};",
            "exit;",
            nospec_global_func = sym nospec_global_func,
            nospec_call_subprog = sym nospec_call_subprog,
            options(nostack)
        );
    }
}

include!("hand/verifier_unpriv.rs");

bpf_object!("GPL");
