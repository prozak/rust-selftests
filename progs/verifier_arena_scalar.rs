// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_arena_scalar.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_arena_scalar.rs
// (include!d below): st_cb, st_in_callback.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_arena_scalar` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: __kfunc_btf_root ld_st_sizes ld_into_base ldsx ptr_chase atomics fetch_and_or_xor fetch_and_or_xor_r0 fetch_or_freed_page fetch_or_r0_freed_page cmpxchg_r0 xchg_into_base xchg_into_stack_ptr load_acq_store_rel not_in_arena stack_addr_as_number alu64_after_access st_keeps_regs st_value_garbage st_value_small atomic_value mixed_number_arena no_flag no_arena null_ptr null_ptr_off small_number helper_arg mixed_number_stack st_cb st_in_callback

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    ld_st_sizes:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: load and store of every size"),
        __success,
        __retval("0"),
        __load_if_JITed;
    ld_into_base:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: load into the register that holds the address"),
        __success,
        __retval("0"),
        __load_if_JITed;
    ldsx:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: sign extending load"),
        __success,
        __retval("0"),
        __load_if_JITed;
    ptr_chase:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: address loaded from arena"),
        __success,
        __retval("0"),
        __load_if_JITed;
    atomics:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: atomics"),
        __success,
        __retval("0"),
        __load_if_JITed;
    fetch_and_or_xor:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: fetching and/or/xor"),
        __success,
        __retval("0"),
        __load_if_JITed;
    fetch_and_or_xor_r0:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: fetching and/or/xor with the operand in r0"),
        __success,
        __retval("0"),
        __load_if_JITed;
    fetch_or_freed_page:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: fetching or through a number to a freed page"),
        __success,
        __retval("0"),
        __load_if_JITed;
    fetch_or_r0_freed_page:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: fetching or with the operand in r0 to a freed page"),
        __success,
        __retval("0"),
        __load_if_JITed;
    cmpxchg_r0:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: cmpxchg through r0"),
        __success,
        __retval("0"),
        __load_if_JITed;
    xchg_into_base:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: xchg into the register that holds the address"),
        __success,
        __retval("0"),
        __load_if_JITed;
    xchg_into_stack_ptr:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: xchg into the register that holds a pointer to stack"),
        __failure,
        __msg("misaligned access off (0x0; 0xffffffffffffffff)+0 size 8");
    load_acq_store_rel:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: load-acquire and store-release"),
        __success,
        __retval("0"),
        __load_if_JITed;
    not_in_arena:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: number that is not an address in arena"),
        __success,
        __retval("0"),
        __load_if_JITed;
    stack_addr_as_number:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: store through the address of the stack as a number"),
        __success,
        __retval("0"),
        __load_if_JITed;
    alu64_after_access:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: 64-bit math on the address stays 64-bit"),
        __success,
        __retval("0"),
        __load_if_JITed;
    st_keeps_regs:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: st of an immediate changes no register"),
        __success,
        __retval("0"),
        __load_if_JITed;
    st_value_garbage:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: access through a number with garbage in the upper half"),
        __success,
        __retval("0"),
        __load_if_JITed;
    st_value_small:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: access through a number without the upper half"),
        __success,
        __retval("0"),
        __load_if_JITed;
    atomic_value:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: atomics through a number that is not an address in arena"),
        __success,
        __retval("0"),
        __load_if_JITed;
    mixed_number_arena:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: number and pointer to arena at the same insn"),
        __success,
        __retval("0"),
        __load_if_JITed;
    no_flag:
        __description("arena_scalar: no flag, no access through a number"),
        __failure,
        __msg("R6 invalid mem access 'scalar'");
    no_arena:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: no arena, no access through a number"),
        __failure,
        __msg("R6 invalid mem access 'scalar'");
    null_ptr:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: pointer that is NULL is an address in arena"),
        __success,
        __retval("0"),
        __load_if_JITed;
    null_ptr_off:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: pointer that is NULL with an offset is an address in arena"),
        __success,
        __retval("0"),
        __load_if_JITed;
    small_number:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: number that is less than a page is an address in arena"),
        __success,
        __retval("0"),
        __load_if_JITed;
    helper_arg:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: number is not a pointer for a helper"),
        __failure,
        __msg("R2 type=scalar expected=");
    mixed_number_stack:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: number and pointer to stack at the same insn"),
        __failure,
        __msg("same insn cannot be used with different pointers"),
        __load_if_JITed;
    st_in_callback:
        __flag("BPF_F_ARENA_SCALAR"),
        __arch_x86_64,
        __arch_arm64,
        __description("arena_scalar: store through a number in a callback"),
        __success,
        __retval("0"),
        __load_if_JITed;
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(u64)]
enum arena__map_extra {
    __unique_value = 0x100000000000,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct arena {
    r#type: *const [i32; 33],
    map_flags: *const [i32; 1024],
    max_entries: *const [i32; 4],
    map_extra: arena__map_extra,
}
unsafe impl Sync for arena {}

#[link_section = ".maps"]
#[no_mangle]
static arena: arena = arena {
    r#type: core::ptr::null(),
    map_flags: core::ptr::null(),
    max_entries: core::ptr::null(),
    map_extra: arena__map_extra::__unique_value,
};

bpf_map! {
    hash {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i64,
    }
}

extern "C" {
    fn bpf_arena_alloc_pages(a0: *mut c_void, a1: *mut c_void, a2: u32, a3: i32, a4: u64) -> *mut c_void;
    fn bpf_arena_free_pages(a0: *mut c_void, a1: *mut c_void, a2: u32);
}

// __kfunc_btf_root: the C's reference to each kfunc the asm calls, for its
// BTF prototype (llc emits one only for a real call or address load).
#[no_mangle]
#[inline(never)]
extern "C" fn __kfunc_btf_root() {
    unsafe {
        bpf_arena_alloc_pages(core::ptr::null_mut(), core::ptr::null_mut(), 0, 0, 0);
        bpf_arena_free_pages(core::ptr::null_mut(), core::ptr::null_mut(), 0);
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_st_sizes
extern "C" fn ld_st_sizes() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r7 = r6;",
            "r1 = 0x1122334455667788 ll;",
            "*(u64 *)(r6 + 0) = r1;",
            "*(u32 *)(r6 + 8) = r1;",
            "*(u16 *)(r6 + 12) = r1;",
            "*(u8 *)(r6 + 14) = r1;",
            "*(u64 *)(r6 + 16) = 0x1234;",
            "*(u32 *)(r6 + 24) = 0x5678;",
            "*(u16 *)(r6 + 28) = 0x9a;",
            "*(u8 *)(r6 + 30) = 0xbc;",
            "r0 = 1;",
            "r2 = *(u64 *)(r6 + 0);",
            "if r2 != r1 goto 9f;",
            "r0 = 2;",
            "r2 = *(u32 *)(r6 + 8);",
            "if r2 != 0x55667788 goto 9f;",
            "r0 = 3;",
            "r2 = *(u16 *)(r6 + 12);",
            "if r2 != 0x7788 goto 9f;",
            "r0 = 4;",
            "r2 = *(u8 *)(r6 + 14);",
            "if r2 != 0x88 goto 9f;",
            "r0 = 5;",
            "r2 = *(u64 *)(r6 + 16);",
            "if r2 != 0x1234 goto 9f;",
            "r0 = 6;",
            "r2 = *(u32 *)(r6 + 24);",
            "if r2 != 0x5678 goto 9f;",
            "r0 = 7;",
            "r2 = *(u16 *)(r6 + 28);",
            "if r2 != 0x9a goto 9f;",
            "r0 = 8;",
            "r2 = *(u8 *)(r6 + 30);",
            "if r2 != 0xbc goto 9f;",
            "r0 = 9;",
            "if r6 != r7 goto 9f;",
            "r0 = 10;",
            "r7 >>= 32;",
            "if r7 == 0 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_into_base
extern "C" fn ld_into_base() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r1 = 77;",
            "*(u64 *)(r6 + 0) = r1;",
            "r6 = *(u64 *)(r6 + 0);",
            "r0 = 1;",
            "if r6 != 77 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ldsx
extern "C" fn ldsx() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r7 = r6;",
            "*(u64 *)(r6 + 0) = 0x80;",
            ".8byte 25233;",
            "r0 = 1;",
            "if r2 != -128 goto 9f;",
            "r0 = 2;",
            "if r6 != r7 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_chase
extern "C" fn ptr_chase() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r1 = r6;",
            "r1 += 64;",
            "*(u64 *)(r6 + 0) = r1;",
            "*(u64 *)(r1 + 0) = 5;",
            "r2 = *(u64 *)(r6 + 0);",
            "r0 = 1;",
            "if r2 != r1 goto 9f;",
            "r3 = *(u64 *)(r2 + 0);",
            "r0 = 2;",
            "if r3 != 5 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: atomics
extern "C" fn atomics() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r7 = r6;",
            "*(u64 *)(r6 + 8) = 1;",
            "r1 = 2;",
            "lock *(u64 *)(r6 + 8) += r1;",
            "r1 = 4;",
            ".8byte 4295497435;",
            "r0 = 1;",
            "if r1 != 3 goto 9f;",
            "r1 = 8;",
            ".8byte 966368171739;",
            "r0 = 2;",
            "if r1 != 7 goto 9f;",
            "r0 = 8;",
            "r1 = 16;",
            ".8byte 1035087648475;",
            "r2 = r0;",
            "r0 = 3;",
            "if r2 != 8 goto 9f;",
            "r2 = *(u64 *)(r6 + 8);",
            "r0 = 4;",
            "if r2 != 16 goto 9f;",
            "r0 = 5;",
            "if r6 != r7 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fetch_and_or_xor
extern "C" fn fetch_and_or_xor() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r7 = 0x11000000110 ll;",
            "*(u64 *)(r6 + 8) = r7;",
            "r0 = r6;",
            "r0 ^= 0x55;",
            "r1 = 0x1100000011 ll;",
            ".8byte 279173404379;",
            "r2 = r6;",
            "r2 ^= 0x55;",
            "if r0 == r2 goto 1f;",
            "r0 = 99;",
            "goto 9f;",
            "1:",
            "r0 = 1;",
            "if r1 != r7 goto 9f;",
            "r7 = 0x11100000111 ll;",
            "r1 = 0x11000000111 ll;",
            ".8byte 347892881115;",
            "r0 = 2;",
            "if r1 != r7 goto 9f;",
            "r7 = 0x11000000111 ll;",
            "r1 = 0x101 ll;",
            ".8byte 691490264795;",
            "r0 = 3;",
            "if r1 != r7 goto 9f;",
            "r7 = 0x11000000010 ll;",
            "r2 = *(u64 *)(r6 + 8);",
            "r0 = 4;",
            "if r2 != r7 goto 9f;",
            "*(u32 *)(r6 + 16) = 0x110;",
            "r1 = 0xdead000000000011 ll;",
            ".8byte 279173928643;",
            "r0 = 5;",
            "if r1 != 0x110 goto 9f;",
            "r1 = 0xdead000000000101 ll;",
            ".8byte 347893405379;",
            "r0 = 6;",
            "if r1 != 0x111 goto 9f;",
            "r1 = 0xdead000000000011 ll;",
            ".8byte 691490789059;",
            "r0 = 7;",
            "if r1 != 0x101 goto 9f;",
            "r2 = *(u32 *)(r6 + 16);",
            "r0 = 8;",
            "if r2 != 0x110 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fetch_and_or_xor_r0
extern "C" fn fetch_and_or_xor_r0() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r7 = 0x11000000110 ll;",
            "*(u64 *)(r6 + 8) = r7;",
            "r0 = 0x1100000011 ll;",
            ".8byte 279173400283;",
            "r2 = r0;",
            "r0 = 1;",
            "if r2 != r7 goto 9f;",
            "r7 = 0x11100000111 ll;",
            "r0 = 0x11000000111 ll;",
            ".8byte 347892877019;",
            "r2 = r0;",
            "r0 = 2;",
            "if r2 != r7 goto 9f;",
            "r7 = 0x11000000111 ll;",
            "r0 = 0x101 ll;",
            ".8byte 691490260699;",
            "r2 = r0;",
            "r0 = 3;",
            "if r2 != r7 goto 9f;",
            "r7 = 0x11000000010 ll;",
            "r2 = *(u64 *)(r6 + 8);",
            "r0 = 4;",
            "if r2 != r7 goto 9f;",
            "*(u32 *)(r6 + 16) = 0x110;",
            "r0 = 0xdead000000000011 ll;",
            ".8byte 279173924547;",
            "r2 = r0;",
            "r0 = 5;",
            "if r2 != 0x110 goto 9f;",
            "r0 = 0xdead000000000101 ll;",
            ".8byte 347893401283;",
            "r2 = r0;",
            "r0 = 6;",
            "if r2 != 0x111 goto 9f;",
            "r0 = 0xdead000000000011 ll;",
            ".8byte 691490784963;",
            "r2 = r0;",
            "r0 = 7;",
            "if r2 != 0x101 goto 9f;",
            "r2 = *(u32 *)(r6 + 16);",
            "r0 = 8;",
            "if r2 != 0x110 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fetch_or_freed_page
extern "C" fn fetch_or_freed_page() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "*(u64 *)(r6 + 8) = 0x55;",
            "r1 = {arena} ll;",
            "r2 = r6;",
            "r3 = 1;",
            "call {bpf_arena_free_pages};",
            "r0 = r6;",
            "r0 ^= 0x55;",
            "r1 = 1;",
            ".8byte 279173404379;",
            "r2 = r6;",
            "r2 ^= 0x55;",
            "if r0 == r2 goto 1f;",
            "r0 = 1;",
            "goto 9f;",
            "1:",
            "r0 = 2;",
            "if r1 != 0 goto 9f;",
            "r3 = *(u64 *)(r6 + 8);",
            "r0 = 3;",
            "if r3 != 0 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            bpf_arena_free_pages = sym bpf_arena_free_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: fetch_or_r0_freed_page
extern "C" fn fetch_or_r0_freed_page() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "*(u64 *)(r6 + 8) = 0x55;",
            "r1 = {arena} ll;",
            "r2 = r6;",
            "r3 = 1;",
            "call {bpf_arena_free_pages};",
            "r0 = 1;",
            ".8byte 279173400283;",
            "r2 = r0;",
            "r0 = 1;",
            "if r2 != 0 goto 9f;",
            "r3 = *(u64 *)(r6 + 8);",
            "r0 = 2;",
            "if r3 != 0 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            bpf_arena_free_pages = sym bpf_arena_free_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: cmpxchg_r0
extern "C" fn cmpxchg_r0() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "*(u64 *)(r6 + 0) = 3;",
            "r0 = r6;",
            "r1 = 5;",
            ".8byte 1035087122651;",
            "r2 = r0;",
            "r0 = 1;",
            "if r2 != 3 goto 9f;",
            "r2 = *(u64 *)(r6 + 0);",
            "r0 = 2;",
            "if r2 != 3 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: xchg_into_base
extern "C" fn xchg_into_base() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "*(u64 *)(r6 + 0) = 3;",
            "r1 = r6;",
            ".8byte 966367646171;",
            "r0 = 1;",
            "if r1 != 3 goto 9f;",
            "r2 = *(u64 *)(r6 + 0);",
            "r0 = 2;",
            "if r2 != r6 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: xchg_into_stack_ptr
extern "C" fn xchg_into_stack_ptr() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            ".8byte 966367646171;",
            "r0 = 0;",
            "exit;",
            arena = sym arena,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acq_store_rel
extern "C" fn load_acq_store_rel() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r7 = r6;",
            "r1 = 0x1234;",
            ".8byte 1168231634651;",
            ".8byte 1099512177371;",
            "r0 = 1;",
            "if r2 != 0x1234 goto 9f;",
            ".8byte 1099512177363;",
            "r0 = 2;",
            "if r2 != 0x34 goto 9f;",
            "r0 = 3;",
            "if r6 != r7 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: not_in_arena
extern "C" fn not_in_arena() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r6 = 0xdeadbeef00000000 ll;",
            "r0 = 1;",
            "r2 = *(u64 *)(r6 + 0);",
            "if r2 != 0 goto 9f;",
            "r0 = 2;",
            "r2 = *(u8 *)(r6 - 32768);",
            "if r2 != 0 goto 9f;",
            "r6 = 0x12345678ffffffff ll;",
            "r0 = 3;",
            "r2 = *(u64 *)(r6 + 32760);",
            "if r2 != 0 goto 9f;",
            "*(u64 *)(r6 + 32760) = 1;",
            "*(u8 *)(r6 + 32767) = r2;",
            "r1 = 1;",
            "lock *(u64 *)(r6 + 32760) += r1;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_addr_as_number
extern "C" fn stack_addr_as_number() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "*(u64 *)(r10 - 8) = 5;",
            "r6 = r10;",
            "r6 |= 0;",
            "*(u64 *)(r6 - 8) = 7;",
            "r1 = 9;",
            "*(u64 *)(r6 - 8) = r1;",
            "lock *(u64 *)(r6 - 8) += r1;",
            "r2 = *(u64 *)(r10 - 8);",
            "r0 = 1;",
            "if r2 != 5 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: alu64_after_access
extern "C" fn alu64_after_access() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r2 = *(u64 *)(r6 + 0);",
            "r7 = r6;",
            "r7 += 8;",
            "r7 -= r6;",
            "r0 = 1;",
            "if r7 != 8 goto 9f;",
            "r7 = r6;",
            "r7 >>= 32;",
            "r0 = 2;",
            "if r7 == 0 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: st_keeps_regs
extern "C" fn st_keeps_regs() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r0 = r6;",
            "r1 = 0x1111;",
            "r2 = 0x2222;",
            "*(u64 *)(r0 + 0) = 5;",
            "r3 = r0;",
            "r0 = 1;",
            "if r3 != r6 goto 9f;",
            "r0 = 2;",
            "if r1 != 0x1111 goto 9f;",
            "r0 = 3;",
            "if r2 != 0x2222 goto 9f;",
            "r0 = 0x3333;",
            "r1 = r6;",
            "*(u32 *)(r1 + 8) = -7;",
            "r3 = r0;",
            "r0 = 4;",
            "if r3 != 0x3333 goto 9f;",
            "r0 = 5;",
            "if r1 != r6 goto 9f;",
            "r0 = 6;",
            "r3 = *(u64 *)(r6 + 0);",
            "if r3 != 5 goto 9f;",
            "r0 = 7;",
            "r3 = *(u64 *)(r6 + 8);",
            "r4 = 0xfffffff9 ll;",
            "if r3 != r4 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: st_value_garbage
extern "C" fn st_value_garbage() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r1 = 0xdeadbeef00001000 ll;",
            "*(u64 *)(r6 + 2048) = r1;",
            "r7 = *(u64 *)(r6 + 2048);",
            "r8 = *(u64 *)(r6 + 2048);",
            "r1 = 3;",
            "*(u64 *)(r8 + 0) = 1;",
            "r0 = 1;",
            "if r8 != r7 goto 9f;",
            "*(u8 *)(r8 + 1) = 1;",
            "r0 = 2;",
            "if r8 != r7 goto 9f;",
            "*(u32 *)(r8 + 4) = r1;",
            "r0 = 3;",
            "if r8 != r7 goto 9f;",
            "r2 = *(u16 *)(r8 + 2);",
            "r0 = 4;",
            "if r8 != r7 goto 9f;",
            "r0 = 5;",
            "if r1 != 3 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: st_value_small
extern "C" fn st_value_small() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r1 = 0x1000 ll;",
            "*(u64 *)(r6 + 2048) = r1;",
            "r7 = *(u64 *)(r6 + 2048);",
            "r8 = *(u64 *)(r6 + 2048);",
            "r1 = 3;",
            "*(u64 *)(r8 + 0) = 1;",
            "r0 = 1;",
            "if r8 != r7 goto 9f;",
            "*(u8 *)(r8 + 1) = 1;",
            "r0 = 2;",
            "if r8 != r7 goto 9f;",
            "*(u32 *)(r8 + 4) = r1;",
            "r0 = 3;",
            "if r8 != r7 goto 9f;",
            "r2 = *(u16 *)(r8 + 2);",
            "r0 = 4;",
            "if r8 != r7 goto 9f;",
            "r0 = 5;",
            "if r1 != 3 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: atomic_value
extern "C" fn atomic_value() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r1 = 0xdeadbeef00001000 ll;",
            "*(u64 *)(r6 + 2048) = r1;",
            "r7 = *(u64 *)(r6 + 2048);",
            "r8 = *(u64 *)(r6 + 2048);",
            "r1 = 3;",
            "lock *(u64 *)(r8 + 0) += r1;",
            "r0 = 1;",
            "if r8 != r7 goto 9f;",
            ".8byte 4294973659;",
            "r0 = 2;",
            "if r8 != r7 goto 9f;",
            ".8byte 966367647963;",
            "r0 = 3;",
            "if r8 != r7 goto 9f;",
            "r0 = 0;",
            ".8byte 1035087124699;",
            "r0 = 4;",
            "if r8 != r7 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mixed_number_arena
extern "C" fn mixed_number_arena() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "*(u64 *)(r6 + 8) = 0x1234;",
            "r7 = *(u64 *)(r6 + 16);",
            "r8 = r6;",
            "if r7 != 0 goto 1f;",
            ".8byte 4295067839;",
            "1:",
            "*(u8 *)(r8 + 0) = 1;",
            "*(u8 *)(r8 + 1) = r7;",
            "r2 = *(u8 *)(r8 + 1);",
            "lock *(u64 *)(r8 + 24) += r7;",
            "r0 = 0;",
            "if r7 != 0 goto 9f;",
            "r0 = 2;",
            "r2 = *(u64 *)(r8 + 8);",
            "if r2 != 0x1234 goto 9f;",
            "r0 = 3;",
            "r2 = *(u8 *)(r6 + 0);",
            "if r2 != 1 goto 9f;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_flag
extern "C" fn no_flag() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r6 = 0x100000000000 ll;",
            "r0 = *(u64 *)(r6 + 0);",
            "exit;",
            arena = sym arena,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_arena
extern "C" fn no_arena() {
    unsafe {
        core::arch::asm!(
            "r6 = 0x100000000000 ll;",
            "r0 = *(u64 *)(r6 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: null_ptr
extern "C" fn null_ptr() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r1 = 0;",
            "*(u32 *)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {hash} ll;",
            "call 1;",
            "r1 = r0;",
            "r0 = 1;",
            "if r1 != 0 goto 9f;",
            "r0 = *(u64 *)(r1 + 0);",
            "9:",
            "exit;",
            arena = sym arena,
            hash = sym hash,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: null_ptr_off
extern "C" fn null_ptr_off() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r1 = 0;",
            "*(u32 *)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {hash} ll;",
            "call 1;",
            "r1 = r0;",
            "r0 = 1;",
            "if r1 != 0 goto 9f;",
            "r1 += 8;",
            "*(u64 *)(r1 + 0) = 5;",
            "r0 = *(u64 *)(r1 + 0);",
            "9:",
            "exit;",
            arena = sym arena,
            hash = sym hash,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: small_number
extern "C" fn small_number() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "call 7;",
            "r1 = r0;",
            "r1 &= 0xfff;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            arena = sym arena,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: helper_arg
extern "C" fn helper_arg() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "r1 = {hash} ll;",
            "r2 = r6;",
            "call 1;",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            hash = sym hash,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

#[link_section = "syscall"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mixed_number_stack
extern "C" fn mixed_number_stack() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r2 = 0;",
            "r3 = 1;",
            "r4 = -1;",
            "r5 = 0;",
            "call {bpf_arena_alloc_pages};",
            "r6 = r0;",
            "r0 = 100;",
            "if r6 == 0 goto 9f;",
            "*(u64 *)(r10 - 8) = 0;",
            "call 7;",
            "if w0 != 0 goto 1f;",
            "r6 = r10;",
            "r6 += -8;",
            "1:",
            "r0 = *(u64 *)(r6 + 0);",
            "r0 = 0;",
            "9:",
            "exit;",
            arena = sym arena,
            bpf_arena_alloc_pages = sym bpf_arena_alloc_pages,
            options(nostack)
        );
    }
}

include!("hand/verifier_arena_scalar.rs");

bpf_object!("GPL");
