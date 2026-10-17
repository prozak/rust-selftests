// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_value_illegal_alu.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_value_illegal_alu` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: value_illegal_alu_op_1 value_illegal_alu_op_2 value_illegal_alu_op_3 value_illegal_alu_op_4 value_illegal_alu_op_5 map_ptr_illegal_alu_op ptr_tag_and_shift ptr_tag_cap_bpf number_mul_ptr ptr_tag_cleared_deref ptr_or_null_shift map_ptr_and ptr_and32 flow_keys_illegal_variable_offset_alu bad_offset_divx bad_offset_modk bad_offset_addx bad_offset_divx2 bad_offset_modk2 bad_offset_addx2

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    value_illegal_alu_op_1:
        __description("map element value illegal alu op, 1"),
        __failure,
        __msg("R0 invalid mem access 'scalar'"),
        __failure_unpriv,
        __msg_unpriv("R0 bitwise operator &= on pointer");
    value_illegal_alu_op_2:
        __description("map element value illegal alu op, 2"),
        __failure,
        __msg("R0 32-bit pointer arithmetic prohibited"),
        __failure_unpriv;
    value_illegal_alu_op_3:
        __description("map element value illegal alu op, 3"),
        __failure,
        __msg("R0 invalid mem access 'scalar'"),
        __failure_unpriv,
        __msg_unpriv("R0 pointer arithmetic with /= operator");
    value_illegal_alu_op_4:
        __description("map element value illegal alu op, 4"),
        __failure,
        __msg("invalid mem access 'scalar'"),
        __failure_unpriv,
        __msg_unpriv("R0 pointer arithmetic prohibited"),
        __flag("BPF_F_ANY_ALIGNMENT");
    value_illegal_alu_op_5:
        __description("map element value illegal alu op, 5"),
        __failure,
        __msg("R0 invalid mem access 'scalar'"),
        __msg_unpriv("leaking pointer from stack off -8"),
        __flag("BPF_F_ANY_ALIGNMENT");
    map_ptr_illegal_alu_op:
        __description("map_ptr illegal alu op, map_ptr = -map_ptr"),
        __failure,
        __msg("R0 invalid mem access 'scalar'"),
        __failure_unpriv,
        __msg_unpriv("R0 pointer arithmetic prohibited"),
        __flag("BPF_F_ANY_ALIGNMENT");
    ptr_tag_and_shift:
        __description("tag in the low bit of a pointer, and, shift"),
        __success,
        __retval("0"),
        __failure_unpriv,
        __msg_unpriv("R1 bitwise operator &= on pointer");
    ptr_tag_cap_bpf:
        __description("tag in the low bit of a pointer, CAP_BPF without CAP_PERFMON"),
        __success,
        __retval("0"),
        __failure_unpriv,
        __msg_unpriv("R1 bitwise operator &= on pointer"),
        __caps_unpriv("39");
    number_mul_ptr:
        __description("number op= pointer"),
        __success,
        __retval("0"),
        __failure_unpriv,
        __msg_unpriv("R1 pointer arithmetic with *= operator");
    ptr_tag_cleared_deref:
        __description("pointer with the tag cleared is a number"),
        __failure,
        __msg("R0 invalid mem access 'scalar'"),
        __failure_unpriv,
        __msg_unpriv("R0 bitwise operator |= on pointer");
    ptr_or_null_shift:
        __description("shift of a pointer that may be NULL"),
        __failure,
        __msg("R0 pointer arithmetic on map_value_or_null prohibited, null-check it first"),
        __failure_unpriv;
    map_ptr_and:
        __description("and of a pointer to map"),
        __failure,
        __msg("R0 pointer arithmetic on map_ptr prohibited"),
        __failure_unpriv;
    ptr_and32:
        __description("32-bit and of a pointer"),
        __success,
        __retval("0"),
        __failure_unpriv,
        __msg_unpriv("R0 32-bit pointer arithmetic prohibited");
    flow_keys_illegal_variable_offset_alu:
        __description("flow_keys illegal alu op with variable offset"),
        __failure,
        __msg("R7 pointer arithmetic on flow_keys prohibited");
    bad_offset_divx:
        __failure,
        __msg("BPF_ALU uses reserved fields");
    bad_offset_modk:
        __failure,
        __msg("BPF_ALU uses reserved fields");
    bad_offset_addx:
        __failure,
        __msg("BPF_ALU uses reserved fields");
    bad_offset_divx2:
        __failure,
        __msg("BPF_ALU uses reserved fields");
    bad_offset_modk2:
        __failure,
        __msg("BPF_ALU uses reserved fields");
    bad_offset_addx2:
        __failure,
        __msg("BPF_ALU uses reserved fields");
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
    map_hash_48b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const test_val,
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_illegal_alu_op_1
extern "C" fn value_illegal_alu_op_1() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_0;",
            "r0 &= 8;",
            "r1 = 22;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_0:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_illegal_alu_op_2
extern "C" fn value_illegal_alu_op_2() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            "w0 += 0;",
            "r1 = 22;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_1:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_illegal_alu_op_3
extern "C" fn value_illegal_alu_op_3() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_2;",
            "r0 /= 42;",
            "r1 = 22;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_2:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_illegal_alu_op_4
extern "C" fn value_illegal_alu_op_4() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_3;",
            "r0 = be64 r0;",
            "r1 = 22;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_3:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: value_illegal_alu_op_5
extern "C" fn value_illegal_alu_op_5() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_4;",
            "r3 = 4096;",
            "r2 = r10;",
            "r2 += -8;",
            "*(u64*)(r2 + 0) = r0;",
            "lock *(u64 *)(r2 + 0) += r3;",
            "r0 = *(u64*)(r2 + 0);",
            "r1 = 22;",
            "*(u64*)(r0 + 0) = r1;",
            "l0_4:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_ptr_illegal_alu_op
extern "C" fn map_ptr_illegal_alu_op() {
    unsafe {
        core::arch::asm!(
            "r0 = {map_hash_48b} ll;",
            "r0 = -r0;",
            "r1 = 22;",
            "*(u64*)(r0 + 0) = r1;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_tag_and_shift
extern "C" fn ptr_tag_and_shift() {
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
            "r1 &= 1;",
            "r2 = r0;",
            "r2 >>= 1;",
            "r3 = r0;",
            "r3 |= 1;",
            "r3 ^= 1;",
            "r0 = *(u32*)(r0 + 0);",
            "r0 = 0;",
            "l0_5:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_tag_cap_bpf
extern "C" fn ptr_tag_cap_bpf() {
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
            "r1 &= 1;",
            "r0 = 0;",
            "l0_6:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: number_mul_ptr
extern "C" fn number_mul_ptr() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_7;",
            "r1 = 7;",
            "r1 *= r0;",
            "r0 = 0;",
            "l0_7:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_tag_cleared_deref
extern "C" fn ptr_tag_cleared_deref() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_8;",
            "r0 |= 1;",
            "r0 ^= 1;",
            "r0 = *(u32*)(r0 + 0);",
            "l0_8:",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_or_null_shift
extern "C" fn ptr_or_null_shift() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "r0 >>= 1;",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_ptr_and
extern "C" fn map_ptr_and() {
    unsafe {
        core::arch::asm!(
            "r0 = {map_hash_48b} ll;",
            "r0 &= 1;",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_and32
extern "C" fn ptr_and32() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_9;",
            "w0 &= 1;",
            "l0_9:",
            "r0 = 0;",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "flow_dissector"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: flow_keys_illegal_variable_offset_alu
extern "C" fn flow_keys_illegal_variable_offset_alu() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = *(u64*)(r6 + 144);",
            "call 7;",
            "r8 = r0;",
            "r8 &= 8;",
            "r7 += r8;",
            "r0 = *(u64*)(r7 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_offset_divx
extern "C" fn bad_offset_divx() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            ".8byte 4294901823;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_offset_modk
extern "C" fn bad_offset_modk() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            ".8byte 8589869207;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_offset_addx
extern "C" fn bad_offset_addx() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            ".8byte 4294901775;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_offset_divx2
extern "C" fn bad_offset_divx2() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            ".8byte 131135;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_offset_modk2
extern "C" fn bad_offset_modk2() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            ".8byte 4295098519;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bad_offset_addx2
extern "C" fn bad_offset_addx2() {
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            ".8byte 65551;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
