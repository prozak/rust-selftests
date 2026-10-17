// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_var_off.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_var_off` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: variable_offset_ctx_access stack_read_priv_vs_unpriv stack_read_var_off_preserves_spilled_zero stack_read_var_off_preserves_spilled_zero_across_slots stack_read_var_off_preserves_partial_spilled_zero stack_read_var_off_partial_spill_with_misc_data variable_offset_stack_read_uninitialized stack_write_priv_vs_unpriv stack_write_followed_by_read stack_write_clobbers_spilled_regs variable_offset_stack_access_unbounded access_max_out_of_bound zero_sized_access_max_out_of_bound access_min_out_of_bound access_min_out_of_bound_large access_min_off_min_initialized stack_access_priv_vs_unpriv variable_offset_stack_access_ok

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    variable_offset_ctx_access:
        __description("variable-offset ctx access"),
        __failure,
        __msg("variable ctx access var_off=(0x0; 0x4)");
    stack_read_priv_vs_unpriv:
        __description("variable-offset stack read, priv vs unpriv"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R2 variable stack access prohibited for !root"),
        __retval("0");
    stack_read_var_off_preserves_spilled_zero:
        __description("variable-offset stack read preserves spilled zero"),
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs= stack=-8"),
        __msg("R3=0"),
        __retval("0");
    stack_read_var_off_preserves_spilled_zero_across_slots:
        __description("variable-offset stack read preserves spilled zero across slots"),
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs= stack=-8,-16"),
        __msg("R3=0"),
        __retval("0");
    stack_read_var_off_preserves_partial_spilled_zero:
        __description("variable-offset stack read preserves partial spilled zero"),
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs= stack=-8"),
        __msg("R3=0"),
        __retval("0");
    stack_read_var_off_partial_spill_with_misc_data:
        __description("variable-offset stack read partial spill with misc data"),
        __failure,
        __msg("invalid variable-offset write to stack R1");
    variable_offset_stack_read_uninitialized:
        __description("variable-offset stack read, uninitialized"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R2 variable stack access prohibited for !root");
    stack_write_priv_vs_unpriv:
        __description("variable-offset stack write, priv vs unpriv"),
        __success,
        __log_level("4"),
        __msg("subprog 0 (stack_write_priv_vs_unpriv) main {{.*}} stack 16"),
        __failure_unpriv,
        __msg_unpriv("R2 variable stack access prohibited for !root"),
        __retval("0");
    stack_write_followed_by_read:
        __description("variable-offset stack write followed by read"),
        __success,
        __log_level("4"),
        __msg("subprog 0 (stack_write_followed_by_read) main {{.*}} stack 16"),
        __failure_unpriv,
        __msg_unpriv("R2 variable stack access prohibited for !root"),
        __retval("0");
    stack_write_clobbers_spilled_regs:
        __description("variable-offset stack write clobbers spilled regs"),
        __failure,
        __msg("R2 invalid mem access 'scalar'"),
        __failure_unpriv,
        __msg_unpriv("R2 variable stack access prohibited for !root");
    variable_offset_stack_access_unbounded:
        __description("indirect variable-offset stack access, unbounded"),
        __failure,
        __msg("invalid unbounded variable-offset write to stack R4");
    access_max_out_of_bound:
        __description("indirect variable-offset stack access, max out of bound"),
        __failure,
        __msg("invalid variable-offset read from stack R2");
    zero_sized_access_max_out_of_bound:
        __description("indirect variable-offset stack access, zero-sized, max out of bound"),
        __failure,
        __msg("invalid variable-offset write to stack R1");
    access_min_out_of_bound:
        __description("indirect variable-offset stack access, min out of bound"),
        __load_if_no_large_stack,
        __failure,
        __msg("invalid variable-offset read from stack R2");
    access_min_out_of_bound_large:
        __description("indirect variable-offset stack access, min out of bound, large stack"),
        __load_if_large_stack,
        __failure,
        __msg("invalid variable-offset read from stack R2");
    access_min_off_min_initialized:
        __description("indirect variable-offset stack access, min_off < min_initialized"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R2 variable stack access prohibited for !root");
    stack_access_priv_vs_unpriv:
        __description("indirect variable-offset stack access, priv vs unpriv"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R2 variable stack access prohibited for !root"),
        __retval("0");
    variable_offset_stack_access_ok:
        __description("indirect variable-offset stack access, ok"),
        __success,
        __retval("0");
}

bpf_map! {
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
}

#[link_section = "lwt_in"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: variable_offset_ctx_access
extern "C" fn variable_offset_ctx_access() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 4;",
            "r1 += r2;",
            "r0 = *(u32*)(r1 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_read_priv_vs_unpriv
extern "C" fn stack_read_priv_vs_unpriv() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r10 - 8) = r0;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 4;",
            "r2 -= 8;",
            "r2 += r10;",
            "r0 = *(u32*)(r2 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_read_var_off_preserves_spilled_zero
extern "C" fn stack_read_var_off_preserves_spilled_zero() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r10 - 8) = r0;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 7;",
            "r2 -= 8;",
            "r2 += r10;",
            "r3 = *(u8*)(r2 + 0);",
            "r1 = r10;",
            "r1 += -1;",
            "r1 += r3;",
            "*(u8*)(r1 + 0) = r3;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_read_var_off_preserves_spilled_zero_across_slots
extern "C" fn stack_read_var_off_preserves_spilled_zero_across_slots() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r10 - 8) = r0;",
            "*(u64*)(r10 - 16) = r0;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 15;",
            "r2 -= 16;",
            "r2 += r10;",
            "r3 = *(u8*)(r2 + 0);",
            "r1 = r10;",
            "r1 += -1;",
            "r1 += r3;",
            "*(u8*)(r1 + 0) = r3;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_read_var_off_preserves_partial_spilled_zero
extern "C" fn stack_read_var_off_preserves_partial_spilled_zero() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u8*)(r10 - 9) = r0;",
            "*(u8*)(r10 - 10) = r0;",
            "*(u8*)(r10 - 11) = r0;",
            "*(u8*)(r10 - 12) = r0;",
            "*(u8*)(r10 - 13) = r0;",
            "*(u8*)(r10 - 14) = r0;",
            "*(u8*)(r10 - 15) = r0;",
            "*(u32*)(r10 - 8) = r0;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 15;",
            "if r2 > 10 goto l0_0;",
            "r2 -= 15;",
            "r2 += r10;",
            "r3 = *(u8*)(r2 + 0);",
            "r1 = r10;",
            "r1 += -1;",
            "r1 += r3;",
            "*(u8*)(r1 + 0) = r3;",
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
// BPF_NAKED: stack_read_var_off_partial_spill_with_misc_data
extern "C" fn stack_read_var_off_partial_spill_with_misc_data() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u32*)(r10 - 8) = r0;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 7;",
            "r2 -= 8;",
            "r2 += r10;",
            "r3 = *(u8*)(r2 + 0);",
            "r1 = r10;",
            "r1 += -1;",
            "r1 += r3;",
            "*(u8*)(r1 + 0) = 0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: variable_offset_stack_read_uninitialized
extern "C" fn variable_offset_stack_read_uninitialized() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 4;",
            "r2 -= 8;",
            "r2 += r10;",
            "r0 = *(u32*)(r2 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_write_priv_vs_unpriv
extern "C" fn stack_write_priv_vs_unpriv() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 8;",
            "r2 -= 16;",
            "r2 += r10;",
            "r0 = 0;",
            "*(u64*)(r2 + 0) = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_write_followed_by_read
extern "C" fn stack_write_followed_by_read() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 8;",
            "r2 -= 16;",
            "r2 += r10;",
            "r0 = 0;",
            "*(u64*)(r2 + 0) = r0;",
            "r3 = *(u64*)(r2 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_write_clobbers_spilled_regs
extern "C" fn stack_write_clobbers_spilled_regs() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "r0 = {map_hash_8b} ll;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 8;",
            "r2 -= 16;",
            "r2 += r10;",
            "*(u64*)(r10 - 8) = r0;",
            "r0 = 0;",
            "*(u64*)(r2 + 0) = r0;",
            "r2 = *(u64*)(r10 - 8);",
            "r0 = *(u64*)(r2 + 8);",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "sockops"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: variable_offset_stack_access_unbounded
extern "C" fn variable_offset_stack_access_unbounded() {
    unsafe {
        core::arch::asm!(
            "r2 = 6;",
            "r3 = 28;",
            "r4 = 0;",
            "*(u64*)(r10 - 16) = r4;",
            "r4 = 0;",
            "*(u64*)(r10 - 8) = r4;",
            "r4 = *(u64*)(r1 + 168);",
            "if r4 s< 0 goto l0_1;",
            "r4 -= 16;",
            "r4 += r10;",
            "r5 = 8;",
            "call 57;",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "lwt_in"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_max_out_of_bound
extern "C" fn access_max_out_of_bound() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u64*)(r10 - 8) = r2;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 4;",
            "r2 -= 8;",
            "r2 += r10;",
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
// BPF_NAKED: zero_sized_access_max_out_of_bound
extern "C" fn zero_sized_access_max_out_of_bound() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r10 - 16) = r0;",
            "*(u64*)(r10 - 8) = r0;",
            "r1 = *(u32*)(r1 + 0);",
            "r1 &= 63;",
            "r1 += -16;",
            "r1 += r10;",
            "r2 = 0;",
            "r3 = 0;",
            "call 113;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "lwt_in"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_min_out_of_bound
extern "C" fn access_min_out_of_bound() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u64*)(r10 - 8) = r2;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 4;",
            "r2 -= 516;",
            "r2 += r10;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "lwt_in"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_min_out_of_bound_large
extern "C" fn access_min_out_of_bound_large() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u64*)(r10 - 8) = r2;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 4;",
            "r2 -= 2052;",
            "r2 += r10;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_min_off_min_initialized
extern "C" fn access_min_off_min_initialized() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u64*)(r10 - 8) = r2;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 4;",
            "r2 -= 16;",
            "r2 += r10;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_access_priv_vs_unpriv
extern "C" fn stack_access_priv_vs_unpriv() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u64*)(r10 - 16) = r2;",
            "r2 = 0;",
            "*(u64*)(r10 - 8) = r2;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 4;",
            "r2 -= 16;",
            "r2 += r10;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "lwt_in"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: variable_offset_stack_access_ok
extern "C" fn variable_offset_stack_access_ok() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u64*)(r10 - 16) = r2;",
            "r2 = 0;",
            "*(u64*)(r10 - 8) = r2;",
            "r2 = *(u32*)(r1 + 0);",
            "r2 &= 4;",
            "r2 -= 16;",
            "r2 += r10;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
