// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_raw_stack.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_raw_stack` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: stack_no_skb_load_bytes skb_load_bytes_negative_len load_bytes_negative_len_2 skb_load_bytes_zero_len skb_load_bytes_no_init stack_skb_load_bytes_init bytes_spilled_regs_around_bounds load_bytes_spilled_regs_corruption bytes_spilled_regs_corruption_2 load_bytes_spilled_regs_data load_bytes_invalid_access_1 load_bytes_invalid_access_1_large load_bytes_invalid_access_2 load_bytes_invalid_access_3 load_bytes_invalid_access_4 load_bytes_invalid_access_5 load_bytes_invalid_access_6 skb_load_bytes_large_access

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    stack_no_skb_load_bytes:
        __description("raw_stack: no skb_load_bytes"),
        __success,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack R6 off=-8 size=8");
    skb_load_bytes_negative_len:
        __description("raw_stack: skb_load_bytes, negative len"),
        __failure,
        __msg("R4 min value is negative");
    load_bytes_negative_len_2:
        __description("raw_stack: skb_load_bytes, negative len 2"),
        __failure,
        __msg("R4 min value is negative");
    skb_load_bytes_zero_len:
        __description("raw_stack: skb_load_bytes, zero len"),
        __failure,
        __msg("R4 invalid zero-sized read: u64=[0,0]");
    skb_load_bytes_no_init:
        __description("raw_stack: skb_load_bytes, no init"),
        __success,
        __retval("0"),
        __caps_unpriv("39 | 12"),
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -8+0 size 8");
    stack_skb_load_bytes_init:
        __description("raw_stack: skb_load_bytes, init"),
        __success,
        __retval("0"),
        __caps_unpriv("39 | 12"),
        __success_unpriv;
    bytes_spilled_regs_around_bounds:
        __description("raw_stack: skb_load_bytes, spilled regs around bounds"),
        __success,
        __retval("0");
    load_bytes_spilled_regs_corruption:
        __description("raw_stack: skb_load_bytes, spilled regs corruption"),
        __failure,
        __msg("R0 invalid mem access 'scalar'"),
        __flag("BPF_F_ANY_ALIGNMENT");
    bytes_spilled_regs_corruption_2:
        __description("raw_stack: skb_load_bytes, spilled regs corruption 2"),
        __failure,
        __msg("R3 invalid mem access 'scalar'"),
        __flag("BPF_F_ANY_ALIGNMENT");
    load_bytes_spilled_regs_data:
        __description("raw_stack: skb_load_bytes, spilled regs + data"),
        __success,
        __retval("0");
    load_bytes_invalid_access_1:
        __description("raw_stack: skb_load_bytes, invalid access 1"),
        __load_if_no_large_stack,
        __failure,
        __msg("invalid write to stack R3 off=-513 size=8");
    load_bytes_invalid_access_1_large:
        __description("raw_stack: skb_load_bytes, invalid access 1, large stack"),
        __load_if_large_stack,
        __failure,
        __msg("invalid write to stack R3 off=-2049 size=8");
    load_bytes_invalid_access_2:
        __description("raw_stack: skb_load_bytes, invalid access 2"),
        __failure,
        __msg("invalid write to stack R3 off=-1 size=8");
    load_bytes_invalid_access_3:
        __description("raw_stack: skb_load_bytes, invalid access 3"),
        __failure,
        __msg("R4 min value is negative");
    load_bytes_invalid_access_4:
        __description("raw_stack: skb_load_bytes, invalid access 4"),
        __failure,
        __msg("R4 unbounded memory access, use 'var &= const' or 'if (var < const)'");
    load_bytes_invalid_access_5:
        __description("raw_stack: skb_load_bytes, invalid access 5"),
        __failure,
        __msg("R4 unbounded memory access, use 'var &= const' or 'if (var < const)'");
    load_bytes_invalid_access_6:
        __description("raw_stack: skb_load_bytes, invalid access 6"),
        __failure,
        __msg("invalid zero-sized read");
    skb_load_bytes_large_access:
        __description("raw_stack: skb_load_bytes, large access"),
        __success,
        __retval("0");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_no_skb_load_bytes
extern "C" fn stack_no_skb_load_bytes() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -8;",
            "r3 = r6;",
            "r4 = 8;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: skb_load_bytes_negative_len
extern "C" fn skb_load_bytes_negative_len() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -8;",
            "r3 = r6;",
            "r4 = -8;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_bytes_negative_len_2
extern "C" fn load_bytes_negative_len_2() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -8;",
            "r3 = r6;",
            "r4 = -1;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: skb_load_bytes_zero_len
extern "C" fn skb_load_bytes_zero_len() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -8;",
            "r3 = r6;",
            "r4 = 0;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: skb_load_bytes_no_init
extern "C" fn skb_load_bytes_no_init() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -8;",
            "r3 = r6;",
            "r4 = 8;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_skb_load_bytes_init
extern "C" fn stack_skb_load_bytes_init() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -8;",
            "r3 = 0xcafe;",
            "*(u64*)(r6 + 0) = r3;",
            "r3 = r6;",
            "r4 = 8;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bytes_spilled_regs_around_bounds
extern "C" fn bytes_spilled_regs_around_bounds() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -16;",
            "*(u64*)(r6 - 8) = r1;",
            "*(u64*)(r6 + 8) = r1;",
            "r3 = r6;",
            "r4 = 8;",
            "call 26;",
            "r0 = *(u64*)(r6 - 8);",
            "r2 = *(u64*)(r6 + 8);",
            "r0 = *(u32*)(r0 + 8);",
            "r2 = *(u32*)(r2 + 32);",
            "r0 += r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_bytes_spilled_regs_corruption
extern "C" fn load_bytes_spilled_regs_corruption() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -8;",
            "*(u64*)(r6 + 0) = r1;",
            "r3 = r6;",
            "r4 = 8;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "r0 = *(u32*)(r0 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bytes_spilled_regs_corruption_2
extern "C" fn bytes_spilled_regs_corruption_2() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -16;",
            "*(u64*)(r6 - 8) = r1;",
            "*(u64*)(r6 + 0) = r1;",
            "*(u64*)(r6 + 8) = r1;",
            "r3 = r6;",
            "r4 = 8;",
            "call 26;",
            "r0 = *(u64*)(r6 - 8);",
            "r2 = *(u64*)(r6 + 8);",
            "r3 = *(u64*)(r6 + 0);",
            "r0 = *(u32*)(r0 + 8);",
            "r2 = *(u32*)(r2 + 32);",
            "r0 += r2;",
            "r3 = *(u32*)(r3 + 4);",
            "r0 += r3;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_bytes_spilled_regs_data
extern "C" fn load_bytes_spilled_regs_data() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -16;",
            "*(u64*)(r6 - 8) = r1;",
            "*(u64*)(r6 + 0) = r1;",
            "*(u64*)(r6 + 8) = r1;",
            "r3 = r6;",
            "r4 = 8;",
            "call 26;",
            "r0 = *(u64*)(r6 - 8);",
            "r2 = *(u64*)(r6 + 8);",
            "r3 = *(u64*)(r6 + 0);",
            "r0 = *(u32*)(r0 + 8);",
            "r2 = *(u32*)(r2 + 32);",
            "r0 += r2;",
            "r0 += r3;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_bytes_invalid_access_1
extern "C" fn load_bytes_invalid_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -513;",
            "r3 = r6;",
            "r4 = 8;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_bytes_invalid_access_1_large
extern "C" fn load_bytes_invalid_access_1_large() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -2049;",
            "r3 = r6;",
            "r4 = 8;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_bytes_invalid_access_2
extern "C" fn load_bytes_invalid_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -1;",
            "r3 = r6;",
            "r4 = 8;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_bytes_invalid_access_3
extern "C" fn load_bytes_invalid_access_3() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += 0xffffffff;",
            "r3 = r6;",
            "r4 = 0xffffffff;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_bytes_invalid_access_4
extern "C" fn load_bytes_invalid_access_4() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -1;",
            "r3 = r6;",
            "r4 = 0x7fffffff;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_bytes_invalid_access_5
extern "C" fn load_bytes_invalid_access_5() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -512;",
            "r3 = r6;",
            "r4 = 0x7fffffff;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_bytes_invalid_access_6
extern "C" fn load_bytes_invalid_access_6() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -512;",
            "r3 = r6;",
            "r4 = 0;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: skb_load_bytes_large_access
extern "C" fn skb_load_bytes_large_access() {
    unsafe {
        core::arch::asm!(
            "r2 = 4;",
            "r6 = r10;",
            "r6 += -512;",
            "r3 = r6;",
            "r4 = 512;",
            "call 26;",
            "r0 = *(u64*)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
