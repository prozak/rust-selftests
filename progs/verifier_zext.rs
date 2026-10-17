// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_zext.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_zext` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: __kfunc_btf_root zext_lost_across_checkpoint zext_alu32_hi_used no_zext_alu32_hi_unused no_zext_mov64 zext_narrow_load_hi_used zext_atomic_fetch32_hi_used zext_cmpxchg32_hi_used zext_cfg_hi_used_one_branch no_zext_other_reg_hi_used zext_ld_abs_hi_used helper_param_read_as_64bit subprog_reads_arg_as_64bit subprog_param_read_as_64bit kfunc_param_read_per_btf alu32_and_32bit_conditional alu32_and_64bit_conditional alu64_and_conditionals arena_ptr zext_arena_cmpxchg32 probe_mem

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    zext_lost_across_checkpoint:
        __flag("BPF_F_TEST_STATE_FREQ"),
        __flag("BPF_F_TEST_RND_HI32"),
        __success,
        __retval("0");
    zext_alu32_hi_used:
        __success,
        __log_level("2"),
        __msg("w1 = w0{{ +}}; zext");
    no_zext_alu32_hi_unused:
        __success,
        __log_level("2"),
        __not_msg("; zext");
    no_zext_mov64:
        __success,
        __log_level("2"),
        __not_msg("r1 = r0{{.*}}; zext");
    zext_narrow_load_hi_used:
        __success,
        __log_level("2"),
        __msg("r1 = *(u32 *)(r10 -8){{ +}}; zext");
    zext_atomic_fetch32_hi_used:
        __success,
        __log_level("2"),
        __msg("r1 = atomic_fetch_add((u32 *)(r10 -8), r1){{ +}}; zext");
    zext_cmpxchg32_hi_used:
        __success,
        __log_level("2"),
        __msg("r0 = atomic_cmpxchg((u32 *)(r10 -8), r0, r1){{ +}}; zext");
    zext_cfg_hi_used_one_branch:
        __success,
        __log_level("2"),
        __msg("w6 = 32{{ +}}; zext");
    no_zext_other_reg_hi_used:
        __success,
        __log_level("2"),
        __not_msg("w1 = 1{{.*}}; zext");
    zext_ld_abs_hi_used:
        __success,
        __log_level("2"),
        __msg("r0 = *(u8 *)skb[0]{{.*}}; zext");
    helper_param_read_as_64bit:
        __success,
        __log_level("2"),
        __msg("w2 = 1{{ +}}; zext");
    subprog_param_read_as_64bit:
        __success,
        __log_level("2"),
        __msg("w1 = w0{{ +}}; zext");
    kfunc_param_read_per_btf:
        __success,
        __log_level("2"),
        __msg("w1 = 1{{ +}}; zext"),
        __msg("w2 = 1{{ +}}; zext"),
        __msg("w3 = 1{{ +}}; zext"),
        __msg("w4 = 1{{ +}}; zext");
    alu32_and_32bit_conditional:
        __success,
        __log_level("2"),
        __not_msg("; zext");
    alu32_and_64bit_conditional:
        __success,
        __log_level("2"),
        __msg("w1 = w0{{ +}}; zext");
    alu64_and_conditionals:
        __success,
        __log_level("2"),
        __not_msg("; zext");
    arena_ptr:
        __arch_s390x,
        __xlated("7: w1 = w0"),
        __xlated("8: w1 = w1"),
        __xlated("9: w1 += 8"),
        __xlated("10: w1 = w1"),
        __xlated("11: w2 = w1"),
        __xlated("12: w2 = w2"),
        __xlated("13: *(u64 *)(r1 +0) = r2");
    zext_arena_cmpxchg32:
        __success,
        __xlated("probe r0 = atomic_cmpxchg((u32 *)(r1 +0), r0, r2)"),
        __xlated("w0 = w0");
    probe_mem:
        __success,
        __log_level("2"),
        __arch_s390x,
        __xlated("3: r1 = *(u64 *)(r0 +0)"),
        __xlated("4: r2 = *(u32 *)(r0 +0)"),
        __xlated("5: w2 = w2"),
        __xlated("6: r3 = *(u16 *)(r0 +0)"),
        __xlated("7: w3 = w3"),
        __xlated("8: r4 = *(u8 *)(r0 +0)"),
        __xlated("9: w4 = w4");
}

bpf_map! {
    arena {
        r#type: *const [i32; 33],
        map_flags: *const [i32; 263168],
        max_entries: *const [i32; 1],
    }
}

extern "C" {
    fn bpf_kfunc_call_test4(a0: i8, a1: i16, a2: i32, a3: i64) -> i64;
    fn bpf_arena_alloc_pages(a0: *mut c_void, a1: *mut c_void, a2: u32, a3: i32, a4: u64) -> *mut c_void;
    fn bpf_rdonly_cast(a0: *mut c_void, a1: u32) -> *mut c_void;
}

// __kfunc_btf_root: the C's reference to each kfunc the asm calls, for its
// BTF prototype (llc emits one only for a real call or address load).
#[no_mangle]
#[inline(never)]
extern "C" fn __kfunc_btf_root() {
    unsafe {
        bpf_kfunc_call_test4(0, 0, 0, 0);
        bpf_arena_alloc_pages(core::ptr::null_mut(), core::ptr::null_mut(), 0, 0, 0);
        bpf_rdonly_cast(core::ptr::null_mut(), 0);
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: zext_lost_across_checkpoint
extern "C" fn zext_lost_across_checkpoint() {
    unsafe {
        core::arch::asm!(
            "call 5;",
            "r8 = r0;",
            "r6 = 0xdeadbeefcafebabe ll;",
            "if r8 != 0 goto 1f;",
            "r6 = 32;",
            "goto 2f;",
            "1:",
            "w6 = 32;",
            "2:",
            "r0 = r6;",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: zext_alu32_hi_used
extern "C" fn zext_alu32_hi_used() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_zext_alu32_hi_unused
extern "C" fn no_zext_alu32_hi_unused() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "w2 = w1;",
            "w2 += w1;",
            "w2 += 1;",
            "w2 = w2;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_zext_mov64
extern "C" fn no_zext_mov64() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: zext_narrow_load_hi_used
extern "C" fn zext_narrow_load_hi_used() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 8) = r0;",
            "r1 = *(u32 *)(r10 - 8);",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: zext_atomic_fetch32_hi_used
extern "C" fn zext_atomic_fetch32_hi_used() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "w1 = 1;",
            ".8byte 8589417155;",
            "r0 = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: zext_cmpxchg32_hi_used
extern "C" fn zext_cmpxchg32_hi_used() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "w0 = 0;",
            "w1 = 1;",
            ".8byte 1039381568195;",
            "r2 = r0;",
            "r0 = r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: zext_cfg_hi_used_one_branch
extern "C" fn zext_cfg_hi_used_one_branch() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w6 = 32;",
            "if r0 == 0 goto 1f;",
            "r0 = r6;",
            "exit;",
            "1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_zext_other_reg_hi_used
extern "C" fn no_zext_other_reg_hi_used() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r6 <<= 32;",
            "w1 = 1;",
            "r0 = r6;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: zext_ld_abs_hi_used
extern "C" fn zext_ld_abs_hi_used() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r0 = *(u8 *)skb[0];",
            "r7 = r0;",
            "r0 = r7;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_param_read_as_64bit
extern "C" fn helper_param_read_as_64bit() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "w2 = 1;",
            "call 6;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_reads_arg_as_64bit
extern "C" fn subprog_reads_arg_as_64bit() -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = r1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: subprog_param_read_as_64bit
extern "C" fn subprog_param_read_as_64bit() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "call {subprog_reads_arg_as_64bit};",
            "r0 = 0;",
            "exit;",
            subprog_reads_arg_as_64bit = sym subprog_reads_arg_as_64bit,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: kfunc_param_read_per_btf
extern "C" fn kfunc_param_read_per_btf() {
    unsafe {
        core::arch::asm!(
            "w1 = 1;",
            "w2 = 1;",
            "w3 = 1;",
            "w4 = 1;",
            "call bpf_kfunc_call_test4;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: alu32_and_32bit_conditional
extern "C" fn alu32_and_32bit_conditional() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if w1 > 42 goto 1f;",
            "w2 = 28;",
            "if w2 > w1 goto 1f;",
            "r0 = 0;",
            "1:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: alu32_and_64bit_conditional
extern "C" fn alu32_and_64bit_conditional() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "w1 = w0;",
            "if r1 > 42 goto 1f;",
            "r2 = 28;",
            "if r2 > r1 goto 1f;",
            "r0 = 0;",
            "1:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: alu64_and_conditionals
extern "C" fn alu64_and_conditionals() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = r0;",
            "if w1 > 42 goto 1f;",
            "if r1 > 42 goto 1f;",
            "r2 = 28;",
            "if w2 > w1 goto 1f;",
            "if r2 > r1 goto 1f;",
            "r0 = 0;",
            "1:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arena_ptr
extern "C" fn arena_ptr() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = 0;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r1 = addr_space_cast(r0, 0, 1);",
            "r1 += 8;",
            "r2 = addr_space_cast(r1, 1, 0);",
            "*(u64 *)(r1 +0) = r2;",
            "r0 = 0;",
            "exit;",
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            arena = sym arena,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: zext_arena_cmpxchg32
extern "C" fn zext_arena_cmpxchg32() {
    unsafe {
        core::arch::asm!(
            "r9 = {arena} ll;",
            "r1 = 0;",
            "r1 = addr_space_cast(r1, 0, 1);",
            "r0 = 0;",
            "r2 = 0;",
            ".8byte 1035087126979;",
            "r0 >>= 32;",
            "exit;",
            arena = sym arena,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: probe_mem
extern "C" fn probe_mem() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "r2 = 0;",
            "call {bpf_rdonly_cast};",
            "r1 = *(u64 *)(r0 + 0);",
            "r2 = *(u32 *)(r0 + 0);",
            "r3 = *(u16 *)(r0 + 0);",
            "r4 = *(u8 *)(r0 + 0);",
            "r0 = r1;",
            "r0 += r2;",
            "r0 += r3;",
            "r0 += r4;",
            "1:",
            "exit;",
            bpf_rdonly_cast = sym bpf_rdonly_cast,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
