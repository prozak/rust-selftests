// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_movsx.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_movsx` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: mov32sx_s8 mov32sx_s16 mov64sx_s8 mov64sx_s16 mov64sx_s32 mov32sx_s8_range mov32sx_s16_range mov32sx_s16_range_2 mov64sx_s8_range mov64sx_s16_range mov64sx_s32_range mov64sx_s16_r10 mov64sx_s32_varoff_1 mov64sx_s32_varoff_2 mov64sx_s32_varoff_3 mov64sx_s8_range_check mov32sx_s8_range_check

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    mov32sx_s8:
        __description("MOV32SX, S8"),
        __success,
        __success_unpriv,
        __retval("0x23");
    mov32sx_s16:
        __description("MOV32SX, S16"),
        __success,
        __success_unpriv,
        __retval("0xFFFFff23");
    mov64sx_s8:
        __description("MOV64SX, S8"),
        __success,
        __success_unpriv,
        __retval("-2");
    mov64sx_s16:
        __description("MOV64SX, S16"),
        __success,
        __success_unpriv,
        __retval("0xf23");
    mov64sx_s32:
        __description("MOV64SX, S32"),
        __success,
        __success_unpriv,
        __retval("-1");
    mov32sx_s8_range:
        __description("MOV32SX, S8, range_check"),
        __success,
        __success_unpriv,
        __retval("1");
    mov32sx_s16_range:
        __description("MOV32SX, S16, range_check"),
        __success,
        __success_unpriv,
        __retval("1");
    mov32sx_s16_range_2:
        __description("MOV32SX, S16, range_check 2"),
        __success,
        __success_unpriv,
        __retval("1");
    mov64sx_s8_range:
        __description("MOV64SX, S8, range_check"),
        __success,
        __success_unpriv,
        __retval("1");
    mov64sx_s16_range:
        __description("MOV64SX, S16, range_check"),
        __success,
        __success_unpriv,
        __retval("1");
    mov64sx_s32_range:
        __description("MOV64SX, S32, range_check"),
        __success,
        __success_unpriv,
        __retval("1");
    mov64sx_s16_r10:
        __description("MOV64SX, S16, R10 Sign Extension"),
        __failure,
        __msg("R1 type=scalar expected=fp, pkt, pkt_meta, map_key, map_value, mem, ringbuf_mem, buf, trusted_ptr_"),
        __failure_unpriv,
        __msg_unpriv("R10 sign-extension part of pointer");
    mov64sx_s32_varoff_1:
        __description("MOV32SX, S8, var_off u32_max"),
        __failure,
        __msg("infinite loop detected"),
        __failure_unpriv,
        __msg_unpriv("back-edge from insn 2 to 0");
    mov64sx_s32_varoff_2:
        __description("MOV32SX, S8, var_off not u32_max, positive after s8 extension"),
        __success,
        __retval("0"),
        __success_unpriv,
        __xlated_unpriv("w0 = 0"),
        __xlated_unpriv("exit"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("goto pc-1");
    mov64sx_s32_varoff_3:
        __description("MOV32SX, S8, var_off not u32_max, negative after s8 extension"),
        __success,
        __retval("0"),
        __success_unpriv,
        __xlated_unpriv("w0 = 0"),
        __xlated_unpriv("exit"),
        __xlated_unpriv("nospec"),
        __xlated_unpriv("goto pc-1");
    mov64sx_s8_range_check:
        __description("MOV64SX, S8, unsigned range_check"),
        __success,
        __retval("0");
    mov32sx_s8_range_check:
        __description("MOV32SX, S8, unsigned range_check"),
        __success,
        __retval("0");
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov32sx_s8
extern "C" fn mov32sx_s8() {
    unsafe {
        core::arch::asm!(
            "w0 = 0xff23;",
            "w0 = (s8)w0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov32sx_s16
extern "C" fn mov32sx_s16() {
    unsafe {
        core::arch::asm!(
            "w0 = 0xff23;",
            "w0 = (s16)w0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov64sx_s8
extern "C" fn mov64sx_s8() {
    unsafe {
        core::arch::asm!(
            "r0 = 0x1fe;",
            "r0 = (s8)r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov64sx_s16
extern "C" fn mov64sx_s16() {
    unsafe {
        core::arch::asm!(
            "r0 = 0xf0f23;",
            "r0 = (s16)r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov64sx_s32
extern "C" fn mov64sx_s32() {
    unsafe {
        core::arch::asm!(
            "r0 = 0xfffffffe;",
            "r0 = (s32)r0;",
            "r0 >>= 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov32sx_s8_range
extern "C" fn mov32sx_s8_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = (s8)w0;",
            "if w1 s> 0x7f goto l0_0;",
            "if w1 s< -0x80 goto l0_0;",
            "r0 = 1;",
            "l1_0:",
            "exit;",
            "l0_0:",
            "r0 = 2;",
            "goto l1_0;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov32sx_s16_range
extern "C" fn mov32sx_s16_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = (s16)w0;",
            "if w1 s> 0x7fff goto l0_1;",
            "if w1 s< -0x80ff goto l0_1;",
            "r0 = 1;",
            "l1_1:",
            "exit;",
            "l0_1:",
            "r0 = 2;",
            "goto l1_1;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov32sx_s16_range_2
extern "C" fn mov32sx_s16_range_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 65535;",
            "w2 = (s16)w1;",
            "r2 >>= 1;",
            "if r2 != 0x7fffFFFF goto l0_2;",
            "r0 = 1;",
            "l1_2:",
            "exit;",
            "l0_2:",
            "r0 = 0;",
            "goto l1_2;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov64sx_s8_range
extern "C" fn mov64sx_s8_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = (s8)r0;",
            "if r1 s> 0x7f goto l0_3;",
            "if r1 s< -0x80 goto l0_3;",
            "r0 = 1;",
            "l1_3:",
            "exit;",
            "l0_3:",
            "r0 = 2;",
            "goto l1_3;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov64sx_s16_range
extern "C" fn mov64sx_s16_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = (s16)r0;",
            "if r1 s> 0x7fff goto l0_4;",
            "if r1 s< -0x8000 goto l0_4;",
            "r0 = 1;",
            "l1_4:",
            "exit;",
            "l0_4:",
            "r0 = 2;",
            "goto l1_4;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov64sx_s32_range
extern "C" fn mov64sx_s32_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = (s32)r0;",
            "if r1 s> 0x7fffffff goto l0_5;",
            "if r1 s< -0x80000000 goto l0_5;",
            "r0 = 1;",
            "l1_5:",
            "exit;",
            "l0_5:",
            "r0 = 2;",
            "goto l1_5;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov64sx_s16_r10
extern "C" fn mov64sx_s16_r10() {
    unsafe {
        core::arch::asm!(
            "r1 = 553656332;",
            "*(u32 *)(r10 - 8) = r1;",
            "r1 = (s16)r10;",
            "r1 += -8;",
            "r2 = 3;",
            "if r2 <= r1 goto l0_6;",
            "l0_6:",
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
// BPF_NAKED: mov64sx_s32_varoff_1
extern "C" fn mov64sx_s32_varoff_1() {
    unsafe {
        core::arch::asm!(
            "l0_7:",
            "r3 = *(u8 *)(r10 -387);",
            "w7 = (s8)w3;",
            "if w7 >= 0x2533823b goto l0_7;",
            "w0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov64sx_s32_varoff_2
extern "C" fn mov64sx_s32_varoff_2() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r3 = r0;",
            "r3 &= 0xf;",
            "w7 = (s8)w3;",
            "if w7 s>= 16 goto l0_8;",
            "w0 = 0;",
            "exit;",
            "l0_8:",
            "r10 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov64sx_s32_varoff_3
extern "C" fn mov64sx_s32_varoff_3() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r3 = r0;",
            "r3 &= 0xf;",
            "r3 |= 0x80;",
            "w7 = (s8)w3;",
            "if w7 s>= -5 goto l0_9;",
            "w0 = 0;",
            "exit;",
            "l0_9:",
            "r10 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov64sx_s8_range_check
extern "C" fn mov64sx_s8_range_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 0x1;",
            "r0 += 0xfe;",
            "r0 = (s8)r0;",
            "if r0 < 0xfffffffffffffffe goto label_10;",
            "r0 = 0;",
            "exit;",
            "label_10:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mov32sx_s8_range_check
extern "C" fn mov32sx_s8_range_check() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w0 &= 0x1;",
            "w0 += 0xfe;",
            "w0 = (s8)w0;",
            "if w0 < 0xfffffffe goto label_11;",
            "r0 = 0;",
            "exit;",
            "label_11:",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
