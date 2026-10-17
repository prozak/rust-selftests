// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_stack_ptr.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_stack_ptr` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: ptr_to_stack_store_load load_bad_alignment_on_off load_bad_alignment_on_reg load_out_of_bounds_low load_out_of_bounds_high to_stack_check_high_1 to_stack_check_high_2 to_stack_check_high_3 to_stack_check_high_4 to_stack_check_high_5 to_stack_check_high_6 to_stack_check_high_7 to_stack_check_low_1 to_stack_check_low_2 to_stack_check_low_2_large to_stack_check_low_3 to_stack_check_low_3_large to_stack_check_low_4 to_stack_check_low_5 to_stack_check_low_6 to_stack_check_low_7 stack_mixed_reg_k_1 stack_mixed_reg_k_2 stack_mixed_reg_k_3 ptr_to_stack_reg stack_pointer_arithmetic array_map_using_bpf_b stack_check_size_gt_512 stack_check_size_gt_2048 stack_check_size_512_with_may_goto_jit stack_check_size_512_with_may_goto stack_ptr_subrange_in_loop

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    ptr_to_stack_store_load:
        __description("PTR_TO_STACK store/load"),
        __success,
        __success_unpriv,
        __retval("0xfaceb00c");
    load_bad_alignment_on_off:
        __description("PTR_TO_STACK store/load - bad alignment on off"),
        __failure,
        __msg("misaligned stack access off -8+2 size 8"),
        __failure_unpriv;
    load_bad_alignment_on_reg:
        __description("PTR_TO_STACK store/load - bad alignment on reg"),
        __failure,
        __msg("misaligned stack access off -10+8 size 8"),
        __failure_unpriv;
    load_out_of_bounds_low:
        __description("PTR_TO_STACK store/load - out of bounds low"),
        __failure,
        __msg("invalid write to stack R1 off=-79992 size=8"),
        __msg_unpriv("R1 stack pointer arithmetic goes out of range");
    load_out_of_bounds_high:
        __description("PTR_TO_STACK store/load - out of bounds high"),
        __failure,
        __msg("invalid write to stack R1 off=0 size=8"),
        __failure_unpriv;
    to_stack_check_high_1:
        __description("PTR_TO_STACK check high 1"),
        __success,
        __success_unpriv,
        __retval("42");
    to_stack_check_high_2:
        __description("PTR_TO_STACK check high 2"),
        __success,
        __success_unpriv,
        __retval("42");
    to_stack_check_high_3:
        __description("PTR_TO_STACK check high 3"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 stack pointer arithmetic goes out of range"),
        __retval("42");
    to_stack_check_high_4:
        __description("PTR_TO_STACK check high 4"),
        __failure,
        __msg("invalid write to stack R1 off=0 size=1"),
        __msg_unpriv("R1 stack pointer arithmetic goes out of range");
    to_stack_check_high_5:
        __description("PTR_TO_STACK check high 5"),
        __failure,
        __msg("invalid write to stack R1"),
        __msg_unpriv("R1 stack pointer arithmetic goes out of range");
    to_stack_check_high_6:
        __description("PTR_TO_STACK check high 6"),
        __failure,
        __msg("invalid write to stack"),
        __msg_unpriv("R1 stack pointer arithmetic goes out of range");
    to_stack_check_high_7:
        __description("PTR_TO_STACK check high 7"),
        __failure,
        __msg("fp pointer offset"),
        __msg_unpriv("R1 stack pointer arithmetic goes out of range");
    to_stack_check_low_1:
        __description("PTR_TO_STACK check low 1"),
        __success,
        __success_unpriv,
        __retval("42");
    to_stack_check_low_2:
        __description("PTR_TO_STACK check low 2"),
        __load_if_no_large_stack,
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 stack pointer arithmetic goes out of range"),
        __retval("42");
    to_stack_check_low_2_large:
        __description("PTR_TO_STACK check low 2, large stack"),
        __load_if_large_stack,
        __success,
        __failure_unpriv,
        __msg_unpriv("R1 stack pointer arithmetic goes out of range"),
        __retval("42");
    to_stack_check_low_3:
        __description("PTR_TO_STACK check low 3"),
        __load_if_no_large_stack,
        __failure,
        __msg("invalid write to stack R1 off=-513 size=1"),
        __msg_unpriv("R1 stack pointer arithmetic goes out of range");
    to_stack_check_low_3_large:
        __description("PTR_TO_STACK check low 3, large stack"),
        __load_if_large_stack,
        __failure,
        __msg("invalid write to stack R1 off=-2049 size=1"),
        __msg_unpriv("R1 stack pointer arithmetic goes out of range");
    to_stack_check_low_4:
        __description("PTR_TO_STACK check low 4"),
        __failure,
        __msg("math between fp pointer"),
        __failure_unpriv;
    to_stack_check_low_5:
        __description("PTR_TO_STACK check low 5"),
        __failure,
        __msg("invalid write to stack"),
        __msg_unpriv("R1 stack pointer arithmetic goes out of range");
    to_stack_check_low_6:
        __description("PTR_TO_STACK check low 6"),
        __failure,
        __msg("invalid write to stack"),
        __msg_unpriv("R1 stack pointer arithmetic goes out of range");
    to_stack_check_low_7:
        __description("PTR_TO_STACK check low 7"),
        __failure,
        __msg("fp pointer offset"),
        __msg_unpriv("R1 stack pointer arithmetic goes out of range");
    stack_mixed_reg_k_1:
        __description("PTR_TO_STACK mixed reg/k, 1"),
        __success,
        __success_unpriv,
        __retval("42");
    stack_mixed_reg_k_2:
        __description("PTR_TO_STACK mixed reg/k, 2"),
        __success,
        __success_unpriv,
        __retval("42");
    stack_mixed_reg_k_3:
        __description("PTR_TO_STACK mixed reg/k, 3"),
        __success,
        __success_unpriv,
        __retval("-3");
    ptr_to_stack_reg:
        __description("PTR_TO_STACK reg"),
        __success,
        __success_unpriv,
        __retval("42");
    stack_pointer_arithmetic:
        __description("stack pointer arithmetic"),
        __success,
        __success_unpriv,
        __retval("0");
    array_map_using_bpf_b:
        __description("store PTR_TO_STACK in R10 to array map using BPF_B"),
        __success,
        __retval("42");
    stack_check_size_gt_512:
        __description("PTR_TO_STACK stack size > 512"),
        __load_if_no_large_stack,
        __failure,
        __msg("invalid write to stack R1 off=-520 size=8");
    stack_check_size_gt_2048:
        __description("PTR_TO_STACK stack size > 2048"),
        __load_if_large_stack,
        __failure,
        __msg("invalid write to stack R1 off=-2056 size=8");
    stack_check_size_512_with_may_goto_jit:
        __description("PTR_TO_STACK stack size 512 with may_goto with jit"),
        __load_if_JITed,
        __success,
        __retval("42");
    stack_check_size_512_with_may_goto:
        __description("PTR_TO_STACK stack size 512 with may_goto without jit"),
        __load_if_no_JITed,
        __failure,
        __msg("stack size 520(extra 8) is too large");
    stack_ptr_subrange_in_loop:
        __success,
        __log_level("2"),
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("loop header at 3, widening r7 to -72..-16 step 8"),
        __msg("R7=fp(smin=smin32=-64,smax=smax32=-8"),
        __msg("loop header at 3, clamping r7 to -64..-16 step 8"),
        __msg("from 5 to 3: safe"),
        __msg("processed 9 insns");
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

bpf_map! {
    map_array_48b {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const test_val,
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_stack_store_load
extern "C" fn ptr_to_stack_store_load() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -10;",
            "r0 = 0xfaceb00c;",
            "*(u64*)(r1 + 2) = r0;",
            "r0 = *(u64*)(r1 + 2);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_bad_alignment_on_off
extern "C" fn load_bad_alignment_on_off() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r0 = 0xfaceb00c;",
            "*(u64*)(r1 + 2) = r0;",
            "r0 = *(u64*)(r1 + 2);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_bad_alignment_on_reg
extern "C" fn load_bad_alignment_on_reg() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -10;",
            "r0 = 0xfaceb00c;",
            "*(u64*)(r1 + 8) = r0;",
            "r0 = *(u64*)(r1 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_out_of_bounds_low
extern "C" fn load_out_of_bounds_low() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -80000;",
            "r0 = 0xfaceb00c;",
            "*(u64*)(r1 + 8) = r0;",
            "r0 = *(u64*)(r1 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_out_of_bounds_high
extern "C" fn load_out_of_bounds_high() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r0 = 0xfaceb00c;",
            "*(u64*)(r1 + 8) = r0;",
            "r0 = *(u64*)(r1 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_high_1
extern "C" fn to_stack_check_high_1() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -1;",
            "r0 = 42;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = *(u8*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_high_2
extern "C" fn to_stack_check_high_2() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r0 = 42;",
            "*(u8*)(r1 - 1) = r0;",
            "r0 = *(u8*)(r1 - 1);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_high_3
extern "C" fn to_stack_check_high_3() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += 0;",
            "r0 = 42;",
            "*(u8*)(r1 - 1) = r0;",
            "r0 = *(u8*)(r1 - 1);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_high_4
extern "C" fn to_stack_check_high_4() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += 0;",
            "r0 = 42;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = *(u8*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_high_5
extern "C" fn to_stack_check_high_5() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += 536870911;",
            "r0 = 42;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = *(u8*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_high_6
extern "C" fn to_stack_check_high_6() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += 536870911;",
            "r0 = 42;",
            "*(u8*)(r1 + 32767) = r0;",
            "r0 = *(u8*)(r1 + 32767);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_high_7
extern "C" fn to_stack_check_high_7() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += 536870911;",
            "r1 += 536870911;",
            "r0 = 42;",
            "*(u8*)(r1 + 32767) = r0;",
            "r0 = *(u8*)(r1 + 32767);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_low_1
extern "C" fn to_stack_check_low_1() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -512;",
            "r0 = 42;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = *(u8*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_low_2
extern "C" fn to_stack_check_low_2() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -513;",
            "r0 = 42;",
            "*(u8*)(r1 + 1) = r0;",
            "r0 = *(u8*)(r1 + 1);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_low_2_large
extern "C" fn to_stack_check_low_2_large() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -2049;",
            "r0 = 42;",
            "*(u8*)(r1 + 1) = r0;",
            "r0 = *(u8*)(r1 + 1);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_low_3
extern "C" fn to_stack_check_low_3() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -513;",
            "r0 = 42;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = *(u8*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_low_3_large
extern "C" fn to_stack_check_low_3_large() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -2049;",
            "r0 = 42;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = *(u8*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_low_4
extern "C" fn to_stack_check_low_4() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -2147483648;",
            "r0 = 42;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = *(u8*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_low_5
extern "C" fn to_stack_check_low_5() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -536870911;",
            "r0 = 42;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = *(u8*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_low_6
extern "C" fn to_stack_check_low_6() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -536870911;",
            "r0 = 42;",
            "*(u8*)(r1 -32768) = r0;",
            "r0 = *(u8*)(r1 -32768);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_stack_check_low_7
extern "C" fn to_stack_check_low_7() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -536870911;",
            "r1 += -536870911;",
            "r0 = 42;",
            "*(u8*)(r1 -32768) = r0;",
            "r0 = *(u8*)(r1 -32768);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_mixed_reg_k_1
extern "C" fn stack_mixed_reg_k_1() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -3;",
            "r2 = -3;",
            "r1 += r2;",
            "r0 = 42;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = *(u8*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_mixed_reg_k_2
extern "C" fn stack_mixed_reg_k_2() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r10 - 8) = r0;",
            "r0 = 0;",
            "*(u64*)(r10 - 16) = r0;",
            "r1 = r10;",
            "r1 += -3;",
            "r2 = -3;",
            "r1 += r2;",
            "r0 = 42;",
            "*(u8*)(r1 + 0) = r0;",
            "r5 = r10;",
            "r0 = *(u8*)(r5 - 6);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_mixed_reg_k_3
extern "C" fn stack_mixed_reg_k_3() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -3;",
            "r2 = -3;",
            "r1 += r2;",
            "r0 = 42;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_stack_reg
extern "C" fn ptr_to_stack_reg() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r2 = -3;",
            "r1 += r2;",
            "r0 = 42;",
            "*(u8*)(r1 + 0) = r0;",
            "r0 = *(u8*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_pointer_arithmetic
extern "C" fn stack_pointer_arithmetic() {
    unsafe {
        core::arch::asm!(
            "r1 = 4;",
            "goto l0_0;",
            "l0_0:",
            "r7 = r10;",
            "r7 += -10;",
            "r7 += -10;",
            "r2 = r7;",
            "r2 += r1;",
            "r0 = 0;",
            "*(u32*)(r2 + 4) = r0;",
            "r2 = r7;",
            "r2 += 8;",
            "r0 = 0;",
            "*(u32*)(r2 + 4) = r0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: array_map_using_bpf_b
extern "C" fn array_map_using_bpf_b() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_1;",
            "r0 = 2;",
            "exit;",
            "l0_1:",
            "r1 = r0;",
            "r9 = r10;",
            "r2 = -1;",
            "r3 = -1;",
            "r4 = -1;",
            "r5 = -1;",
            "r6 = -1;",
            "r7 = -1;",
            "r8 = -1;",
            "*(u8*)(r1 + 0) = r10;",
            "r2 = *(u8*)(r1 + 0);",
            "*(u8*)(r1 + 0) = r9;",
            "r3 = *(u8*)(r1 + 0);",
            "if r2 == r3 goto l1_1;",
            "r0 = 1;",
            "exit;",
            "l1_1:",
            "r0 = 42;",
            "exit;",
            map_array_48b = sym map_array_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_check_size_gt_512
extern "C" fn stack_check_size_gt_512() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -520;",
            "r0 = 42;",
            "*(u64*)(r1 + 0) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_check_size_gt_2048
extern "C" fn stack_check_size_gt_2048() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -2056;",
            "r0 = 42;",
            "*(u64*)(r1 + 0) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_check_size_512_with_may_goto_jit
extern "C" fn stack_check_size_512_with_may_goto_jit() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -512;",
            "r0 = 42;",
            "*(u32*)(r1 + 0) = r0;",
            "may_goto l0_2;",
            "r2 = 100;",
            "l0_2:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_check_size_512_with_may_goto
extern "C" fn stack_check_size_512_with_may_goto() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -512;",
            "r0 = 42;",
            "*(u32*)(r1 + 0) = r0;",
            "may_goto l0_3;",
            "r2 = 100;",
            "l0_3:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_ptr_subrange_in_loop
extern "C" fn stack_ptr_subrange_in_loop() {
    unsafe {
        core::arch::asm!(
            "r7 = r10;",
            "r7 += -72;",
            "r6 = 0;",
            "r7 += 8;",
            "r6 += 1;",
            "if r6 < 8 goto -3;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
