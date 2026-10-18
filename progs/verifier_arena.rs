// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]
#![feature(linkage)]

// Translation of tools/testing/selftests/bpf/progs/verifier_arena.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_arena.rs
// (include!d below): basic_alloc1_nosleep, basic_alloc1, free_scalar_below_arena, basic_alloc2_nosleep, basic_alloc2, basic_alloc3_nosleep, basic_alloc3, basic_reserve1_nosleep, basic_reserve1, basic_reserve2_nosleep, basic_reserve2, reserve_twice_nosleep, reserve_twice, reserve_invalid_region_nosleep, reserve_invalid_region, iter_maps1, iter_maps2, iter_maps3, arena_kfuncs_under_bpf_lock, scalar_add_arena_ptr, arena_ptr_add_arena_ptr, mixed_arena_scalar_alu64_scalar_first, mixed_arena_scalar_alu64_arena_first, scalar_xor_arena_ptr, arena_ptr_add_to_non_arena_ptr, non_arena_ptr_add_to_arena_ptr, check_arena_arg_nonglobal, check_arena_arg_global, check_arena_arg_quals1, check_arena_arg_quals2, check_arena_arg_ret, arena_word_pair, check_arena_struct_ret.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_arena` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: basic_alloc1_nosleep basic_alloc1 free_scalar_below_arena basic_alloc2_nosleep basic_alloc2 basic_alloc3_nosleep basic_alloc3 basic_reserve1_nosleep basic_reserve1 basic_reserve2_nosleep basic_reserve2 reserve_twice_nosleep reserve_twice reserve_invalid_region_nosleep reserve_invalid_region iter_maps1 iter_maps2 iter_maps3 arena_kfuncs_under_bpf_lock scalar_add_arena_ptr arena_ptr_add_arena_ptr mixed_arena_scalar_alu64_scalar_first mixed_arena_scalar_alu64_arena_first scalar_xor_arena_ptr arena_ptr_add_to_non_arena_ptr non_arena_ptr_add_to_arena_ptr mixed_arena_stack_atomic check_arena_arg_nonglobal check_arena_arg_global check_arena_arg_quals1 check_arena_arg_quals2 check_arena_arg_ret arena_word_pair check_arena_struct_ret

// the C's anonymous types, named here; scripts/btf_anon.py clears
// the names in the object's BTF
// BTF_ANON

// a `*mut c_void` is the C's `void *` in BTF (scripts/btf_rename.py)
// BTF_C_VOID: c_void

// (from the hand file)
// BPF_NAKED: arena_word_pair

use bpf_rs_core::{bpf_object, btf_type_tags, test_tags};
use core::ffi::c_void;

test_tags! {
    basic_alloc1_nosleep:
        __success,
        __retval("0");
    basic_alloc1:
        __success,
        __retval("0");
    free_scalar_below_arena:
        __success,
        __retval("0");
    basic_alloc2_nosleep:
        __success,
        __retval("0");
    basic_alloc2:
        __success,
        __retval("0");
    basic_alloc3_nosleep:
        __success,
        __retval("0"),
        __log_level("2");
    basic_alloc3:
        __success,
        __retval("0"),
        __log_level("2");
    basic_reserve1_nosleep:
        __success,
        __retval("0");
    basic_reserve1:
        __success,
        __retval("0");
    basic_reserve2_nosleep:
        __success,
        __retval("0");
    basic_reserve2:
        __success,
        __retval("0");
    reserve_twice_nosleep:
        __success,
        __retval("0");
    reserve_twice:
        __success,
        __retval("0");
    reserve_invalid_region_nosleep:
        __success,
        __retval("0");
    reserve_invalid_region:
        __success,
        __retval("0");
    iter_maps1:
        __success,
        __log_level("2");
    iter_maps2:
        __failure,
        __msg("expected pointer to STRUCT bpf_map");
    iter_maps3:
        __failure,
        __msg("untrusted_ptr_bpf_map");
    arena_kfuncs_under_bpf_lock:
        __success,
        __retval("0");
    scalar_add_arena_ptr:
        __success,
        __retval("0");
    arena_ptr_add_arena_ptr:
        __success,
        __retval("0");
    mixed_arena_scalar_alu64_scalar_first:
        __failure,
        __msg("same insn cannot be used with and without arena pointer");
    mixed_arena_scalar_alu64_arena_first:
        __failure,
        __msg("same insn cannot be used with and without arena pointer");
    scalar_xor_arena_ptr:
        __success,
        __retval("0");
    arena_ptr_add_to_non_arena_ptr:
        __success,
        __retval("0");
    non_arena_ptr_add_to_arena_ptr:
        __success,
        __retval("0");
    mixed_arena_stack_atomic:
        __description("arena and stack atomic at the same instruction"),
        __failure,
        __msg("same insn cannot be used with different pointers"),
        __arch_x86_64,
        __load_if_JITed;
    check_arena_arg_ret:
        __success,
        __retval("0");
    check_arena_struct_ret:
        __load_if_JITed,
        __success,
        __retval("0");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
btf_type_tags! {
    check_arena_arg_global.0: arena;
    check_arena_arg_global.ret: arena;
    check_arena_arg_quals1.0: arena;
    check_arena_arg_quals1.1: arena;
    check_arena_arg_quals1.ret: arena;
    check_arena_arg_quals2.0: arena;
    check_arena_arg_quals2.1: arena;
    check_arena_arg_quals2.ret: arena;
    check_arena_arg_nonglobal.0: arena;
    check_arena_arg_nonglobal.ret: arena;
    arena_word_pair.first: arena;
    arena_word_pair.second: arena;
    arena_word_pair.0: arena;
}

#[allow(non_camel_case_types)]
#[repr(u64)]
enum arena__map_extra {
    __unique_value = 0x1000ffffe000,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct arena {
    r#type: *const [i32; 33],
    map_flags: *const [i32; 1024],
    max_entries: *const [i32; 2],
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

#[link_section = ".bss.ARENA_TESTS"]
#[no_mangle]
#[allow(non_upper_case_globals)]
static mut arena_bpf_test_lock: bpf_spin_lock = bpf_spin_lock { val: 0 };
core::arch::global_asm!(".hidden arena_bpf_test_lock");

extern "C" {
    fn bpf_arena_alloc_pages(a0: *mut c_void, a1: *mut c_void, a2: u32, a3: i32, a4: u64) -> *mut c_void;
    fn bpf_arena_free_pages(a0: *mut c_void, a1: *mut c_void, a2: u32);
    fn bpf_arena_reserve_pages(a0: *mut c_void, a1: *mut c_void, a2: u32) -> i32;
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: mixed_arena_stack_atomic
extern "C" fn mixed_arena_stack_atomic() {
    unsafe {
        core::arch::asm!(
            "r1 = {arena} ll;",
            "r6 = r10;",
            "r6 += -8;",
            "r9 = 0;",
            "*(u64 *)(r6 + 0) = r9;",
            "r7 = 8192;",
            "r7 = addr_space_cast(r7, 0, 1);",
            "call 7;",
            "if w0 != 0 goto 1f;",
            "r8 = r6;",
            "goto 2f;",
            "1:",
            "r8 = r7;",
            "2:",
            "r9 = 1;",
            "lock *(u64 *)(r8 + 0) += r9;",
            "r0 = 0;",
            "exit;",
            arena = sym arena,
            options(nostack)
        );
    }
}

include!("hand/verifier_arena.rs");

bpf_object!("GPL");
