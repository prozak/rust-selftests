// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_lwt.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_lwt` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: packet_write_for_lwt_in packet_write_for_lwt_out packet_write_for_lwt_xmit packet_read_for_lwt_in packet_read_for_lwt_out packet_read_for_lwt_xmit checks_for_direct_packet_access make_headroom_for_lwt_xmit tc_classid_for_lwt_in tc_classid_for_lwt_out tc_classid_for_lwt_xmit not_permitted_for_lwt_prog

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    packet_write_for_lwt_in:
        __description("invalid direct packet write for LWT_IN"),
        __failure,
        __msg("cannot write into packet");
    packet_write_for_lwt_out:
        __description("invalid direct packet write for LWT_OUT"),
        __failure,
        __msg("cannot write into packet");
    packet_write_for_lwt_xmit:
        __description("direct packet write for LWT_XMIT"),
        __success,
        __retval("0");
    packet_read_for_lwt_in:
        __description("direct packet read for LWT_IN"),
        __success,
        __retval("0");
    packet_read_for_lwt_out:
        __description("direct packet read for LWT_OUT"),
        __success,
        __retval("0");
    packet_read_for_lwt_xmit:
        __description("direct packet read for LWT_XMIT"),
        __success,
        __retval("0");
    checks_for_direct_packet_access:
        __description("overlapping checks for direct packet access"),
        __success,
        __retval("0");
    make_headroom_for_lwt_xmit:
        __description("make headroom for LWT_XMIT"),
        __success,
        __retval("0");
    tc_classid_for_lwt_in:
        __description("invalid access of tc_classid for LWT_IN"),
        __failure,
        __msg("invalid bpf_context access"),
        __failure_unpriv;
    tc_classid_for_lwt_out:
        __description("invalid access of tc_classid for LWT_OUT"),
        __failure,
        __msg("invalid bpf_context access"),
        __failure_unpriv;
    tc_classid_for_lwt_xmit:
        __description("invalid access of tc_classid for LWT_XMIT"),
        __failure,
        __msg("invalid bpf_context access"),
        __failure_unpriv;
    not_permitted_for_lwt_prog:
        __description("check skb->tc_classid half load not permitted for lwt prog"),
        __failure,
        __msg("invalid bpf_context access");
}

#[link_section = "lwt_in"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_write_for_lwt_in
extern "C" fn packet_write_for_lwt_in() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_0;",
            "*(u8*)(r2 + 0) = r2;",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "lwt_out"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_write_for_lwt_out
extern "C" fn packet_write_for_lwt_out() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
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

#[link_section = "lwt_xmit"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_write_for_lwt_xmit
extern "C" fn packet_write_for_lwt_xmit() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_2;",
            "*(u8*)(r2 + 0) = r2;",
            "l0_2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "lwt_in"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_read_for_lwt_in
extern "C" fn packet_read_for_lwt_in() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_3;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_3:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "lwt_out"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_read_for_lwt_out
extern "C" fn packet_read_for_lwt_out() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_4;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_4:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "lwt_xmit"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: packet_read_for_lwt_xmit
extern "C" fn packet_read_for_lwt_xmit() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_5;",
            "r0 = *(u8*)(r2 + 0);",
            "l0_5:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "lwt_xmit"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: checks_for_direct_packet_access
extern "C" fn checks_for_direct_packet_access() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 8;",
            "if r0 > r3 goto l0_6;",
            "r1 = r2;",
            "r1 += 6;",
            "if r1 > r3 goto l0_6;",
            "r0 = *(u16*)(r2 + 6);",
            "l0_6:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "lwt_xmit"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: make_headroom_for_lwt_xmit
extern "C" fn make_headroom_for_lwt_xmit() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r2 = 34;",
            "r3 = 0;",
            "call 43;",
            "r1 = r6;",
            "r2 = 42;",
            "r3 = 0;",
            "call 43;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tc_classid_for_lwt_in
extern "C" fn tc_classid_for_lwt_in() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 72);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tc_classid_for_lwt_out
extern "C" fn tc_classid_for_lwt_out() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 72);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tc_classid_for_lwt_xmit
extern "C" fn tc_classid_for_lwt_xmit() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 72);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "lwt_in"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: not_permitted_for_lwt_prog
extern "C" fn not_permitted_for_lwt_prog() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r0 = *(u16*)(r1 + 72);",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
