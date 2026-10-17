// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_store_release.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_store_release` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: store_release_8 store_release_16 store_release_32 store_release_64 store_release_with_uninitialized_src_reg store_release_with_uninitialized_dst_reg store_release_with_non_pointer_dst_reg store_release_misaligned store_release_to_ctx_pointer store_release_to_pkt_pointer store_release_to_flow_keys_pointer store_release_to_sock_pointer store_release_leak_pointer_to_stack store_release_leak_pointer_to_map store_release_with_invalid_reg

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    store_release_8:
        __description("store-release, 8-bit"),
        __success,
        __success_unpriv,
        __retval("0");
    store_release_16:
        __description("store-release, 16-bit"),
        __success,
        __success_unpriv,
        __retval("0");
    store_release_32:
        __description("store-release, 32-bit"),
        __success,
        __success_unpriv,
        __retval("0");
    store_release_64:
        __description("store-release, 64-bit"),
        __success,
        __success_unpriv,
        __retval("0");
    store_release_with_uninitialized_src_reg:
        __description("store-release with uninitialized src_reg"),
        __failure,
        __failure_unpriv,
        __msg("R2 !read_ok");
    store_release_with_uninitialized_dst_reg:
        __description("store-release with uninitialized dst_reg"),
        __failure,
        __failure_unpriv,
        __msg("R2 !read_ok");
    store_release_with_non_pointer_dst_reg:
        __description("store-release with non-pointer dst_reg"),
        __failure,
        __failure_unpriv,
        __msg("R1 invalid mem access 'scalar'");
    store_release_misaligned:
        __description("misaligned store-release"),
        __failure,
        __failure_unpriv,
        __msg("misaligned stack access off"),
        __flag("BPF_F_ANY_ALIGNMENT");
    store_release_to_ctx_pointer:
        __description("store-release to ctx pointer"),
        __failure,
        __failure_unpriv,
        __msg("BPF_ATOMIC stores into R1 ctx is not allowed");
    store_release_to_pkt_pointer:
        __description("store-release to pkt pointer"),
        __failure,
        __msg("BPF_ATOMIC stores into R2 pkt is not allowed");
    store_release_to_flow_keys_pointer:
        __description("store-release to flow_keys pointer"),
        __failure,
        __msg("BPF_ATOMIC stores into R2 flow_keys is not allowed");
    store_release_to_sock_pointer:
        __description("store-release to sock pointer"),
        __failure,
        __msg("R2 cannot write into sock");
    store_release_leak_pointer_to_stack:
        __description("store-release, leak pointer to stack"),
        __success,
        __success_unpriv,
        __retval("0");
    store_release_leak_pointer_to_map:
        __description("store-release, leak pointer to map"),
        __success,
        __retval("0"),
        __failure_unpriv,
        __msg_unpriv("R6 leaks addr into map");
    store_release_with_invalid_reg:
        __description("store-release with invalid register R15"),
        __failure,
        __failure_unpriv,
        __msg("R15 is invalid");
}

bpf_map! {
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_8
extern "C" fn store_release_8() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "w1 = 0x12;",
            ".8byte 1172526013139;",
            "w2 = *(u8 *)(r10 - 1);",
            "if r2 == r1 goto 1f;",
            "r0 = 1;",
            "1:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_16
extern "C" fn store_release_16() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "w1 = 0x1234;",
            ".8byte 1172525947595;",
            "w2 = *(u16 *)(r10 - 2);",
            "if r2 == r1 goto 1f;",
            "r0 = 1;",
            "1:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_32
extern "C" fn store_release_32() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "w1 = 0x12345678;",
            ".8byte 1172525816515;",
            "w2 = *(u32 *)(r10 - 4);",
            "if r2 == r1 goto 1f;",
            "r0 = 1;",
            "1:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_64
extern "C" fn store_release_64() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = 0x1234567890abcdef ll;",
            ".8byte 1172525554395;",
            "r2 = *(u64 *)(r10 - 8);",
            "if r2 == r1 goto 1f;",
            "r0 = 1;",
            "1:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_with_uninitialized_src_reg
extern "C" fn store_release_with_uninitialized_src_reg() {
    unsafe {
        core::arch::asm!(
            ".8byte 1172525558491;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_with_uninitialized_dst_reg
extern "C" fn store_release_with_uninitialized_dst_reg() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            ".8byte 1172525552347;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_with_non_pointer_dst_reg
extern "C" fn store_release_with_non_pointer_dst_reg() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            ".8byte 1168231109083;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_misaligned
extern "C" fn store_release_misaligned() {
    unsafe {
        core::arch::asm!(
            "w0 = 0;",
            ".8byte 1172525746883;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_to_ctx_pointer
extern "C" fn store_release_to_ctx_pointer() {
    unsafe {
        core::arch::asm!(
            "w0 = 0;",
            ".8byte 1168234250707;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_to_pkt_pointer
extern "C" fn store_release_to_pkt_pointer() {
    unsafe {
        core::arch::asm!(
            "w0 = 0;",
            "r2 = *(u32 *)(r1 + 0);",
            "r3 = *(u32 *)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 >= r3 goto l0_0;",
            ".8byte 1168231105235;",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "flow_dissector"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_to_flow_keys_pointer
extern "C" fn store_release_to_flow_keys_pointer() {
    unsafe {
        core::arch::asm!(
            "w0 = 0;",
            "r2 = *(u64 *)(r1 + 144);",
            ".8byte 1168231105235;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_reuseport"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_to_sock_pointer
extern "C" fn store_release_to_sock_pointer() {
    unsafe {
        core::arch::asm!(
            "w0 = 0;",
            "r2 = *(u64 *)(r1 + 40);",
            ".8byte 1168231105235;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_leak_pointer_to_stack
extern "C" fn store_release_leak_pointer_to_stack() {
    unsafe {
        core::arch::asm!(
            ".8byte 1172525554395;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: store_release_leak_pointer_to_map
extern "C" fn store_release_leak_pointer_to_map() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = {map_hash_8b} ll;",
            "r2 = 0;",
            "*(u64 *)(r10 - 8) = r2;",
            "r2 = r10;",
            "r2 += -8;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            ".8byte 1168231129307;",
            "l0_1:",
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
// BPF_NAKED: store_release_with_invalid_reg
extern "C" fn store_release_with_invalid_reg() {
    unsafe {
        core::arch::asm!(
            ".8byte 1168231112667;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
