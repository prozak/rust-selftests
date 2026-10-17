// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_ctx_sk_msg.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_ctx_sk_msg` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: access_family_in_sk_msg remote_ip4_in_sk_msg local_ip4_in_sk_msg remote_port_in_sk_msg local_port_in_sk_msg remote_ip6_in_sk_msg local_ip6_in_sk_msg access_size_in_sk_msg of_size_in_sk_msg past_end_of_sk_msg read_offset_in_sk_msg packet_read_for_sk_msg packet_write_for_sk_msg direct_packet_access_sk_msg

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    access_family_in_sk_msg:
        __description("valid access family in SK_MSG"),
        __success;
    remote_ip4_in_sk_msg:
        __description("valid access remote_ip4 in SK_MSG"),
        __success;
    local_ip4_in_sk_msg:
        __description("valid access local_ip4 in SK_MSG"),
        __success;
    remote_port_in_sk_msg:
        __description("valid access remote_port in SK_MSG"),
        __success;
    local_port_in_sk_msg:
        __description("valid access local_port in SK_MSG"),
        __success;
    remote_ip6_in_sk_msg:
        __description("valid access remote_ip6 in SK_MSG"),
        __success;
    local_ip6_in_sk_msg:
        __description("valid access local_ip6 in SK_MSG"),
        __success;
    access_size_in_sk_msg:
        __description("valid access size in SK_MSG"),
        __success;
    of_size_in_sk_msg:
        __description("invalid 64B read of size in SK_MSG"),
        __failure,
        __msg("invalid bpf_context access"),
        __flag("BPF_F_ANY_ALIGNMENT");
    past_end_of_sk_msg:
        __description("invalid read past end of SK_MSG"),
        __failure,
        __msg("invalid bpf_context access");
    read_offset_in_sk_msg:
        __description("invalid read offset in SK_MSG"),
        __failure,
        __msg("invalid bpf_context access"),
        __flag("BPF_F_ANY_ALIGNMENT");
    packet_read_for_sk_msg:
        __description("direct packet read for SK_MSG"),
        __success;
    packet_write_for_sk_msg:
        __description("direct packet write for SK_MSG"),
        __success;
    direct_packet_access_sk_msg:
        __description("overlapping checks for direct packet access SK_MSG"),
        __success;
}

#[link_section = "sk_msg"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_family_in_sk_msg
extern "C" fn access_family_in_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 16);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_msg"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: remote_ip4_in_sk_msg
extern "C" fn remote_ip4_in_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 20);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_msg"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: local_ip4_in_sk_msg
extern "C" fn local_ip4_in_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 24);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_msg"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: remote_port_in_sk_msg
extern "C" fn remote_port_in_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 60);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_msg"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: local_port_in_sk_msg
extern "C" fn local_port_in_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 64);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: remote_ip6_in_sk_msg
extern "C" fn remote_ip6_in_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 28);",
            "r0 = *(u32*)(r1 + 32);",
            "r0 = *(u32*)(r1 + 36);",
            "r0 = *(u32*)(r1 + 40);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: local_ip6_in_sk_msg
extern "C" fn local_ip6_in_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 44);",
            "r0 = *(u32*)(r1 + 48);",
            "r0 = *(u32*)(r1 + 52);",
            "r0 = *(u32*)(r1 + 56);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_msg"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: access_size_in_sk_msg
extern "C" fn access_size_in_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 68);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_msg"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: of_size_in_sk_msg
extern "C" fn of_size_in_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64*)(r1 + 68);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_msg"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: past_end_of_sk_msg
extern "C" fn past_end_of_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 72);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_msg"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_offset_in_sk_msg
extern "C" fn read_offset_in_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 17);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_msg"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_read_for_sk_msg
extern "C" fn packet_read_for_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64*)(r1 + 0);",
            "r3 = *(u64*)(r1 + 8);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_0;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_msg"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_write_for_sk_msg
extern "C" fn packet_write_for_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64*)(r1 + 0);",
            "r3 = *(u64*)(r1 + 8);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_1;",
            "*(u8*)(r2 + 0) = r2;",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_msg"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: direct_packet_access_sk_msg
extern "C" fn direct_packet_access_sk_msg() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64*)(r1 + 0);",
            "r3 = *(u64*)(r1 + 8);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_2;",
            "r1 = r2;",
            "r1 += 6;",
            "if r1 > r3 goto l0_2;",
            "r0 = *(u16*)(r2 + 6);",
            "l0_2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
