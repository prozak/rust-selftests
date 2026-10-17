// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/verifier_jit_inline.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_jit_inline.rs
// (include!d below): inline_bpf_get_current_task, inline_bpf_get_smp_processor_id.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_jit_inline` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: inline_bpf_get_current_task inline_bpf_get_smp_processor_id

use bpf_rs_core::{bpf_object, test_tags};
#[allow(unused_imports)]
use core::ffi::c_void;

test_tags! {
    inline_bpf_get_current_task:
        __success,
        __retval("0"),
        __arch_x86_64,
        __jited("\taddq\t%gs:{{.*}}, %rax"),
        __arch_arm64,
        __jited("\tmrs\tx8, SP_EL0"),
        __arch_riscv64,
        __jited("\tmv\tt6, tp"),
        __arch_loongarch,
        __jited("\tmove\t$a5, $tp");
    inline_bpf_get_smp_processor_id:
        __success,
        __retval("0"),
        __arch_loongarch,
        __jited("\tld.wu\t$a5, $tp, 16");
}

include!("hand/verifier_jit_inline.rs");

bpf_object!("GPL");
