// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_tailcall_jit.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_tailcall_jit` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: sub main

use bpf_rs_core::{test_tags};
use core::ffi::c_void;

test_tags! {
    sub:
        __auxiliary;
    main:
        __success,
        __arch_x86_64,
        __jited("\tendbr64"),
        __jited("\tnopl\t(%rax,%rax)"),
        __jited("\txorq\t%rax, %rax"),
        __jited("\tpushq\t%rbp"),
        __jited("\tmovq\t%rsp, %rbp"),
        __jited("\tendbr64"),
        __jited("\tcmpq\t$0x21, %rax"),
        __jited("\tja\tL0"),
        __jited("\tpushq\t%rax"),
        __jited("\tmovq\t%rsp, %rax"),
        __jited("\tjmp\tL1"),
        __jited("L0:\tpushq\t%rax"),
        __jited("L1:\tpushq\t%rax"),
        __jited("\tmovq\t-0x10(%rbp), %rax"),
        __jited("..."),
        __jited("\tcallq\t0x{{.*}}"),
        __jited("\txorl\t%eax, %eax"),
        __jited("\tleave"),
        __jited("\t{{(retq|jmp\t0x)}}"),
        __jited("..."),
        __jited("\tendbr64"),
        __jited("\tnopl\t(%rax,%rax)"),
        __jited("\tnopl\t(%rax)"),
        __jited("\tpushq\t%rbp"),
        __jited("\tmovq\t%rsp, %rbp"),
        __jited("\tendbr64"),
        __jited("\tpushq\t%rax"),
        __jited("\tpushq\t%rax"),
        __jited("\tmovabsq\t${{.*}}, %rsi"),
        __jited("\txorl\t%edx, %edx"),
        __jited("\tmovq\t-0x10(%rbp), %rax"),
        __jited("\tcmpq\t$0x21, (%rax)"),
        __jited("\tjae\tL0"),
        __jited("\tnopl\t(%rax,%rax)"),
        __jited("\taddq\t$0x1, (%rax)"),
        __jited("\tpopq\t%rax"),
        __jited("\tpopq\t%rax"),
        __jited("\tjmp\t{{.*}}"),
        __jited("L0:\tleave"),
        __jited("\t{{(retq|jmp\t0x)}}");
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct jmp_table {
    r#type: *const [i32; 3],
    max_entries: *const [i32; 1],
    key_size: *const [i32; 4],
    values: [*const c_void; 1],
}
unsafe impl Sync for jmp_table {}

#[link_section = ".maps"]
#[no_mangle]
static jmp_table: jmp_table = jmp_table {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [main as extern "C" fn() -> i32 as *const c_void],
};

#[no_mangle]
#[inline(never)]
// BPF_NAKED: sub
extern "C" fn sub() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r2 = {jmp_table} ll;",
            "r3 = 0;",
            "call 12;",
            "exit;",
            jmp_table = sym jmp_table,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: main
extern "C" fn main() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "call {sub};",
            "r0 = 0;",
            "exit;",
            sub = sym sub,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

// The C source names its license global `__license`; the symbol
// name must match for the keep-list, so bpf_object! is written out.
#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
