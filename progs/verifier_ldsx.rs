// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_ldsx.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_ldsx` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: ldsx_s8 ldsx_s16 ldsx_s32 ldsx_s8_range_priv ldsx_s16_range ldsx_s32_range ldsx_ctx_1 ldsx_ctx_2 ldsx_ctx_3 ldsx_ctx_4 ldsx_ctx_5 ldsx_ctx_6 ldsx_ctx_7 ldsx_ctx_8 arena_ldsx_disasm arena_ldsx_exception arena_ldsx_s8 arena_ldsx_s16 arena_ldsx_s32 kfunc_root

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    ldsx_s8:
        __description("LDSX, S8"),
        __success,
        __success_unpriv,
        __retval("-2");
    ldsx_s16:
        __description("LDSX, S16"),
        __success,
        __success_unpriv,
        __retval("-2");
    ldsx_s32:
        __description("LDSX, S32"),
        __success,
        __success_unpriv,
        __retval("-1");
    ldsx_s8_range_priv:
        __description("LDSX, S8 range checking, privileged"),
        __log_level("2"),
        __success,
        __retval("1"),
        __msg("R1=scalar(smin=smin32=-128,smax=smax32=127)");
    ldsx_s16_range:
        __description("LDSX, S16 range checking"),
        __success,
        __success_unpriv,
        __retval("1");
    ldsx_s32_range:
        __description("LDSX, S32 range checking"),
        __success,
        __success_unpriv,
        __retval("1");
    ldsx_ctx_1:
        __description("LDSX, xdp s32 xdp_md->data"),
        __failure,
        __msg("invalid bpf_context access");
    ldsx_ctx_2:
        __description("LDSX, xdp s32 xdp_md->data_end"),
        __failure,
        __msg("invalid bpf_context access");
    ldsx_ctx_3:
        __description("LDSX, xdp s32 xdp_md->data_meta"),
        __failure,
        __msg("invalid bpf_context access");
    ldsx_ctx_4:
        __description("LDSX, tcx s32 __sk_buff->data"),
        __failure,
        __msg("invalid bpf_context access");
    ldsx_ctx_5:
        __description("LDSX, tcx s32 __sk_buff->data_end"),
        __failure,
        __msg("invalid bpf_context access");
    ldsx_ctx_6:
        __description("LDSX, tcx s32 __sk_buff->data_meta"),
        __failure,
        __msg("invalid bpf_context access");
    ldsx_ctx_7:
        __description("LDSX, flow_dissector s32 __sk_buff->data"),
        __failure,
        __msg("invalid bpf_context access");
    ldsx_ctx_8:
        __description("LDSX, flow_dissector s32 __sk_buff->data_end"),
        __failure,
        __msg("invalid bpf_context access");
    arena_ldsx_disasm:
        __description("Arena LDSX Disasm"),
        __success,
        __arch_x86_64,
        __jited("movslq\t0x10(%rax,%r12), %r14"),
        __jited("movswq\t0x18(%rax,%r12), %r14"),
        __jited("movsbq\t0x20(%rax,%r12), %r14"),
        __jited("movslq\t0x10(%rdi,%r12), %r15"),
        __jited("movswq\t0x18(%rdi,%r12), %r15"),
        __jited("movsbq\t0x20(%rdi,%r12), %r15"),
        __arch_arm64,
        __jited("add\tx11, x8, x28"),
        __jited("ldrsw\tx21, [x11, #0x10]"),
        __jited("add\tx11, x8, x28"),
        __jited("ldrsh\tx21, [x11, #0x18]"),
        __jited("add\tx11, x8, x28"),
        __jited("ldrsb\tx21, [x11, #0x20]"),
        __jited("add\tx11, x0, x28"),
        __jited("ldrsw\tx22, [x11, #0x10]"),
        __jited("add\tx11, x0, x28"),
        __jited("ldrsh\tx22, [x11, #0x18]"),
        __jited("add\tx11, x0, x28"),
        __jited("ldrsb\tx22, [x11, #0x20]"),
        __arch_riscv64,
        __jited("add\tt2, t6, s7"),
        __jited("lw\ts3, 0x10(t2)"),
        __jited("add\tt2, t6, s7"),
        __jited("lh\ts3, 0x18(t2)"),
        __jited("add\tt2, t6, s7"),
        __jited("lb\ts3, 0x20(t2)"),
        __jited("add\tt2, a0, s7"),
        __jited("lw\ts4, 0x10(t2)"),
        __jited("add\tt2, a0, s7"),
        __jited("lh\ts4, 0x18(t2)"),
        __jited("add\tt2, a0, s7"),
        __jited("lb\ts4, 0x20(t2)");
    arena_ldsx_exception:
        __description("Arena LDSX Exception"),
        __success,
        __retval("0"),
        __arch_x86_64,
        __arch_arm64,
        __arch_riscv64;
    arena_ldsx_s8:
        __description("Arena LDSX, S8"),
        __success,
        __retval("-1"),
        __arch_x86_64,
        __arch_arm64,
        __arch_riscv64;
    arena_ldsx_s16:
        __description("Arena LDSX, S16"),
        __success,
        __retval("-1"),
        __arch_x86_64,
        __arch_arm64,
        __arch_riscv64;
    arena_ldsx_s32:
        __description("Arena LDSX, S32"),
        __success,
        __retval("-1"),
        __arch_x86_64,
        __arch_arm64,
        __arch_riscv64;
}

bpf_map! {
    arena {
        r#type: *const [i32; 33],
        map_flags: *const [i32; 1024],
        max_entries: *const [i32; 1],
    }
}

extern "C" {
    fn bpf_arena_alloc_pages(a0: *mut c_void, a1: *mut c_void, a2: u32, a3: i32, a4: u64) -> *mut c_void;
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_s8
extern "C" fn ldsx_s8() {
    unsafe {
        core::arch::asm!(
            "r1 = 0x3fe;",
            "*(u64 *)(r10 - 8) = r1;",
            "r0 = *(s8 *)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_s16
extern "C" fn ldsx_s16() {
    unsafe {
        core::arch::asm!(
            "r1 = 0x3fffe;",
            "*(u64 *)(r10 - 8) = r1;",
            "r0 = *(s16 *)(r10 - 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_s32
extern "C" fn ldsx_s32() {
    unsafe {
        core::arch::asm!(
            "r1 = 0xfffffffe;",
            "*(u64 *)(r10 - 8) = r1;",
            "r0 = *(s32 *)(r10 - 8);",
            "r0 >>= 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_s8_range_priv
extern "C" fn ldsx_s8_range_priv() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "*(u64 *)(r10 - 8) = r0;",
            "r1 = *(s8 *)(r10 - 8);",
            "if r1 s> 0x7f goto l0_0;",
            "if r1 s< -0x80 goto l0_0;",
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
// BPF_NAKED: ldsx_s16_range
extern "C" fn ldsx_s16_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "*(u64 *)(r10 - 8) = r0;",
            "r1 = *(s16 *)(r10 - 8);",
            "if r1 s> 0x7fff goto l0_1;",
            "if r1 s< -0x8000 goto l0_1;",
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
// BPF_NAKED: ldsx_s32_range
extern "C" fn ldsx_s32_range() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "*(u64 *)(r10 - 8) = r0;",
            "r1 = *(s32 *)(r10 - 8);",
            "if r1 s> 0x7fffFFFF goto l0_2;",
            "if r1 s< -0x80000000 goto l0_2;",
            "r0 = 1;",
            "l1_2:",
            "exit;",
            "l0_2:",
            "r0 = 2;",
            "goto l1_2;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_ctx_1
extern "C" fn ldsx_ctx_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(s32 *)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_ctx_2
extern "C" fn ldsx_ctx_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(s32 *)(r1 + 4);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_ctx_3
extern "C" fn ldsx_ctx_3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(s32 *)(r1 + 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tcx/ingress"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_ctx_4
extern "C" fn ldsx_ctx_4() {
    unsafe {
        core::arch::asm!(
            "r2 = *(s32 *)(r1 + 76);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tcx/ingress"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_ctx_5
extern "C" fn ldsx_ctx_5() {
    unsafe {
        core::arch::asm!(
            "r2 = *(s32 *)(r1 + 80);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tcx/ingress"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_ctx_6
extern "C" fn ldsx_ctx_6() {
    unsafe {
        core::arch::asm!(
            "r2 = *(s32 *)(r1 + 140);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "flow_dissector"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_ctx_7
extern "C" fn ldsx_ctx_7() {
    unsafe {
        core::arch::asm!(
            "r2 = *(s32 *)(r1 + 76);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "flow_dissector"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx_ctx_8
extern "C" fn ldsx_ctx_8() {
    unsafe {
        core::arch::asm!(
            "r2 = *(s32 *)(r1 + 80);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arena_ldsx_disasm
extern "C" fn arena_ldsx_disasm(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r0 = addr_space_cast(r0, 0x0, 0x1);",
            "r1 = r0;",
            "r8 = *(s32 *)(r0 + 16);",
            "r8 = *(s16 *)(r0 + 24);",
            "r8 = *(s8 *)(r0 + 32);",
            "r9 = *(s32 *)(r1 + 16);",
            "r9 = *(s16 *)(r1 + 24);",
            "r9 = *(s8 *)(r1 + 32);",
            "r0 = 0;",
            "exit;",
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            arena = sym arena,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arena_ldsx_exception
extern "C" fn arena_ldsx_exception(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r0 = 0xdeadbeef;",
            "r0 = addr_space_cast(r0, 0x0, 0x1);",
            "r1 = 0x3fe;",
            "*(u64 *)(r0 + 0) = r1;",
            "r0 = *(s8 *)(r0 + 0);",
            "exit;",
            arena = sym arena,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arena_ldsx_s8
extern "C" fn arena_ldsx_s8(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r0 = addr_space_cast(r0, 0x0, 0x1);",
            "r1 = 0x3fe;",
            "*(u64 *)(r0 + 0) = r1;",
            "r0 = *(s8 *)(r0 + 0);",
            "r0 >>= 1;",
            "exit;",
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            arena = sym arena,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arena_ldsx_s16
extern "C" fn arena_ldsx_s16(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r0 = addr_space_cast(r0, 0x0, 0x1);",
            "r1 = 0x3fffe;",
            "*(u64 *)(r0 + 0) = r1;",
            "r0 = *(s16 *)(r0 + 0);",
            "r0 >>= 1;",
            "exit;",
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            arena = sym arena,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arena_ldsx_s32
extern "C" fn arena_ldsx_s32(_ctx: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r0 = addr_space_cast(r0, 0x0, 0x1);",
            "r1 = 0xfffffffe;",
            "*(u64 *)(r0 + 0) = r1;",
            "r0 = *(s32 *)(r0 + 0);",
            "r0 >>= 1;",
            "exit;",
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            arena = sym arena,
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
        bpf_arena_alloc_pages(core::ptr::null_mut(), core::ptr::null_mut(), 0, 0, 0);
    }
}

bpf_object!("GPL");
