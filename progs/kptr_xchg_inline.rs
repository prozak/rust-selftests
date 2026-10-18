// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/kptr_xchg_inline.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py kptr_xchg_inline` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: kptr_xchg_inline __btf_root

use bpf_rs_core::{bpf_object, btf_type_tags};
use core::ffi::c_void;

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
btf_type_tags! {
    ptr: kptr;
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bin_data {
    blob: [i8; 32],
}

#[link_section = ".bss.kptr"]
#[no_mangle]
#[allow(non_upper_case_globals)]
static mut ptr: *mut bin_data = core::ptr::null_mut();
core::arch::global_asm!(".hidden ptr");

extern "C" {
    fn bpf_obj_drop(a0: *mut c_void);
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: kptr_xchg_inline
extern "C" fn kptr_xchg_inline() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {ptr} ll;",
            "r2 = 0;",
            "call 194;",
            "if r0 == 0 goto 1f;",
            "r1 = r0;",
            "r2 = 0;",
            "call {bpf_obj_drop};",
            "1:",
            "r0 = 0;",
            "exit;",
            ptr = sym ptr,
            bpf_obj_drop = sym bpf_obj_drop,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

// __btf_root: the C's reference to each kfunc the asm calls, for its
// BTF prototype (llc emits one only for a real call or address load).
#[no_mangle]
#[inline(never)]
extern "C" fn __btf_root() {
    unsafe {
        bpf_obj_drop(core::ptr::null_mut());
    }
}

bpf_object!("GPL");
