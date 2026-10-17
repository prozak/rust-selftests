// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_jeq_infer_not_null.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_jeq_infer_not_null` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: socket_for_jne_false_branch unchanged_for_jne_true_branch socket_for_jeq_true_branch unchanged_for_jeq_false_branch null_ptr_to_map_value jeq_reg_reg_null_check jne_reg_reg_null_check untrusted_mem_does_not_infer_map_value_non_null unbounded_offset_does_not_infer_map_value_non_null bounded_offset_infers_map_value_non_null jmp32_ptr_vs_zero_jne imprecise_zero_does_not_infer_map_value_non_null kfunc_root

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    socket_for_jne_false_branch:
        __description("jne/jeq infer not null, PTR_TO_SOCKET_OR_NULL -> PTR_TO_SOCKET for JNE false branch"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R7 pointer comparison"),
        __retval("0");
    unchanged_for_jne_true_branch:
        __description("jne/jeq infer not null, PTR_TO_SOCKET_OR_NULL unchanged for JNE true branch"),
        __failure,
        __msg("R7 invalid mem access 'sock_or_null'"),
        __failure_unpriv,
        __msg_unpriv("R7 pointer comparison");
    socket_for_jeq_true_branch:
        __description("jne/jeq infer not null, PTR_TO_SOCKET_OR_NULL -> PTR_TO_SOCKET for JEQ true branch"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R7 pointer comparison"),
        __retval("0");
    unchanged_for_jeq_false_branch:
        __description("jne/jeq infer not null, PTR_TO_SOCKET_OR_NULL unchanged for JEQ false branch"),
        __failure,
        __msg("R7 invalid mem access 'sock_or_null'"),
        __failure_unpriv,
        __msg_unpriv("R7 pointer comparison");
    null_ptr_to_map_value:
        __description("jne/jeq infer not null, PTR_TO_MAP_VALUE_OR_NULL -> PTR_TO_MAP_VALUE"),
        __success,
        __retval("0");
    jeq_reg_reg_null_check:
        __success,
        __log_level("2"),
        __msg("r0 = *(u32 *)(r0 +0)"),
        __msg("from 7 to 9");
    jne_reg_reg_null_check:
        __success,
        __log_level("2"),
        __msg("r0 = *(u32 *)(r0 +0)"),
        __msg("from 7 to 9");
    untrusted_mem_does_not_infer_map_value_non_null:
        __failure,
        __msg("error: invalid dereference of R0 (a nullable map value pointer)"),
        __msg(">>> 11 | (61) r0 = *(u32 *)(r0 +0)");
    unbounded_offset_does_not_infer_map_value_non_null:
        __failure,
        __msg("error: invalid dereference of R7 (a nullable map value pointer)");
    bounded_offset_infers_map_value_non_null:
        __success;
    jmp32_ptr_vs_zero_jne:
        __failure,
        __msg("invalid access to map value, value_size=4 off=32 size=4");
    imprecise_zero_does_not_infer_map_value_non_null:
        __failure,
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("error: invalid dereference of R0 (a nullable map value pointer)");
}

bpf_map! {
    map_xskmap {
        r#type: *const [i32; 17],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i32,
    }
}

bpf_map! {
    map_hash {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i32,
    }
}

extern "C" {
    fn bpf_rdonly_cast(a0: *mut c_void, a1: u32) -> *mut c_void;
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: socket_for_jne_false_branch
extern "C" fn socket_for_jne_false_branch() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64*)(r1 + 168);",
            "if r6 == 0 goto l0_0;",
            "r1 = r6;",
            "call 95;",
            "r7 = r0;",
            "r1 = r6;",
            "call 95;",
            "if r0 == 0 goto l0_0;",
            "if r0 != r7 goto l0_0;",
            "r0 = *(u32*)(r7 + 8);",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unchanged_for_jne_true_branch
extern "C" fn unchanged_for_jne_true_branch() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64*)(r1 + 168);",
            "if r6 == 0 goto l0_1;",
            "r1 = r6;",
            "call 95;",
            "r7 = r0;",
            "r1 = r6;",
            "call 95;",
            "if r0 != 0 goto l0_1;",
            "if r0 != r7 goto l1_1;",
            "goto l0_1;",
            "l1_1:",
            "r0 = *(u32*)(r7 + 8);",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: socket_for_jeq_true_branch
extern "C" fn socket_for_jeq_true_branch() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64*)(r1 + 168);",
            "if r6 == 0 goto l0_2;",
            "r1 = r6;",
            "call 95;",
            "r7 = r0;",
            "r1 = r6;",
            "call 95;",
            "if r0 == 0 goto l0_2;",
            "if r0 == r7 goto l1_2;",
            "goto l0_2;",
            "l1_2:",
            "r0 = *(u32*)(r7 + 8);",
            "l0_2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unchanged_for_jeq_false_branch
extern "C" fn unchanged_for_jeq_false_branch() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64*)(r1 + 168);",
            "if r6 == 0 goto l0_3;",
            "r1 = r6;",
            "call 95;",
            "r7 = r0;",
            "r1 = r6;",
            "call 95;",
            "if r0 == 0 goto l0_3;",
            "if r0 == r7 goto l0_3;",
            "r0 = *(u32*)(r7 + 8);",
            "l0_3:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: null_ptr_to_map_value
extern "C" fn null_ptr_to_map_value() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 8) = r1;",
            "r9 = r10;",
            "r9 += -8;",
            "r8 = {map_xskmap} ll;",
            "r1 = r8;",
            "r2 = r9;",
            "call 1;",
            "r6 = r0;",
            "r1 = r8;",
            "r2 = r9;",
            "call 1;",
            "r7 = r0;",
            "if r6 == 0 goto l0_4;",
            "if r6 != r7 goto l0_4;",
            "r0 = *(u32*)(r7 + 0);",
            "l0_4:",
            "r0 = 0;",
            "exit;",
            map_xskmap = sym map_xskmap,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jeq_reg_reg_null_check
extern "C" fn jeq_reg_reg_null_check() {
    unsafe {
        core::arch::asm!(
            "*(u32*)(r10 - 8) = 0;",
            "r1 = {map_xskmap} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "r1 = 0;",
            "if r0 == r1 goto 1f;",
            "r0 = *(u32*)(r0 +0);",
            "1:",
            "r0 = 0;",
            "exit;",
            map_xskmap = sym map_xskmap,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jne_reg_reg_null_check
extern "C" fn jne_reg_reg_null_check() {
    unsafe {
        core::arch::asm!(
            "*(u32*)(r10 - 8) = 0;",
            "r1 = {map_xskmap} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "r1 = 0;",
            "if r0 != r1 goto 1f;",
            "goto 2f;",
            "1:",
            "r0 = *(u32*)(r0 +0);",
            "2:",
            "r0 = 0;",
            "exit;",
            map_xskmap = sym map_xskmap,
            options(nostack)
        );
    }
}

#[link_section = "raw_tp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: untrusted_mem_does_not_infer_map_value_non_null
extern "C" fn untrusted_mem_does_not_infer_map_value_non_null() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "r2 = 0;",
            "call {bpf_rdonly_cast};",
            "r6 = r0;",
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = {map_hash} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "if r6 != r0 goto 1f;",
            "r0 = *(u32 *)(r0 + 0);",
            "1:",
            "r0 = 0;",
            "exit;",
            bpf_rdonly_cast = sym bpf_rdonly_cast,
            map_hash = sym map_hash,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: unbounded_offset_does_not_infer_map_value_non_null
extern "C" fn unbounded_offset_does_not_infer_map_value_non_null() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = {map_hash} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "if r0 == 0 goto 1f;",
            "r6 = r0;",
            "*(u64 *)(r10 - 8) = 1;",
            "r1 = {map_hash} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "r7 = r0;",
            "r8 = r7;",
            "r8 -= r6;",
            "r8 <<= 1;",
            "r8 >>= 1;",
            "r6 += r8;",
            "if r7 != r6 goto 1f;",
            "r0 = *(u8 *)(r7 + 0);",
            "1:",
            "r0 = 0;",
            "exit;",
            map_hash = sym map_hash,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bounded_offset_infers_map_value_non_null
extern "C" fn bounded_offset_infers_map_value_non_null() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = {map_hash} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "if r0 == 0 goto 1f;",
            "r6 = r0;",
            "*(u64 *)(r10 - 8) = 1;",
            "r1 = {map_hash} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "r7 = r0;",
            "r8 = r7;",
            "r8 -= r6;",
            "r8 &= 3;",
            "r6 += r8;",
            "if r7 != r6 goto 1f;",
            "r0 = *(u8 *)(r7 + 0);",
            "1:",
            "r0 = 0;",
            "exit;",
            map_hash = sym map_hash,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jmp32_ptr_vs_zero_jne
extern "C" fn jmp32_ptr_vs_zero_jne() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = {map_hash} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "if r0 == 0 goto 1f;",
            "if w0 != 0 goto 1f;",
            "r0 = *(u32 *)(r0 + 32);",
            "1:",
            "r0 = 0;",
            "exit;",
            map_hash = sym map_hash,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: imprecise_zero_does_not_infer_map_value_non_null
extern "C" fn imprecise_zero_does_not_infer_map_value_non_null() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = 1;",
            "if r0 == 0 goto 1f;",
            "r6 = 0;",
            "1:",
            "*(u64 *)(r10 - 8) = 0;",
            "r1 = {map_hash} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "if r0 == r6 goto 2f;",
            "r0 = *(u8 *)(r0 + 0);",
            "2:",
            "r0 = 0;",
            "exit;",
            map_hash = sym map_hash,
            options(nostack)
        );
    }
}

// kfunc_root: the C's reference to each kfunc the asm calls, for its
// BTF prototype (llc emits one only for a real call or address load).
#[no_mangle]
#[inline(never)]
extern "C" fn kfunc_root() {
    unsafe {
        bpf_rdonly_cast(core::ptr::null_mut(), 0);
    }
}

bpf_object!("GPL");
