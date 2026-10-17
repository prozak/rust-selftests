// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_cgroup_skb.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_cgroup_skb` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: test_1_for_cgroup_skb test_2_for_cgroup_skb test_3_for_cgroup_skb test_4_for_cgroup_skb tc_classid_for_cgroup_skb data_meta_for_cgroup_skb flow_keys_for_cgroup_skb napi_id_for_cgroup_skb write_tstamp_from_cgroup_skb read_tstamp_from_cgroup_skb

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    test_1_for_cgroup_skb:
        __description("direct packet read test#1 for CGROUP_SKB"),
        __success,
        __failure_unpriv,
        __msg_unpriv("invalid bpf_context access off=76 size=4"),
        __retval("0");
    test_2_for_cgroup_skb:
        __description("direct packet read test#2 for CGROUP_SKB"),
        __success,
        __success_unpriv,
        __retval("0");
    test_3_for_cgroup_skb:
        __description("direct packet read test#3 for CGROUP_SKB"),
        __success,
        __success_unpriv,
        __retval("0");
    test_4_for_cgroup_skb:
        __description("direct packet read test#4 for CGROUP_SKB"),
        __success,
        __success_unpriv,
        __retval("0");
    tc_classid_for_cgroup_skb:
        __description("invalid access of tc_classid for CGROUP_SKB"),
        __failure,
        __msg("invalid bpf_context access"),
        __failure_unpriv;
    data_meta_for_cgroup_skb:
        __description("invalid access of data_meta for CGROUP_SKB"),
        __failure,
        __msg("invalid bpf_context access"),
        __failure_unpriv;
    flow_keys_for_cgroup_skb:
        __description("invalid access of flow_keys for CGROUP_SKB"),
        __failure,
        __msg("invalid bpf_context access"),
        __failure_unpriv;
    napi_id_for_cgroup_skb:
        __description("invalid write access to napi_id for CGROUP_SKB"),
        __failure,
        __msg("invalid bpf_context access"),
        __failure_unpriv;
    write_tstamp_from_cgroup_skb:
        __description("write tstamp from CGROUP_SKB"),
        __success,
        __failure_unpriv,
        __msg_unpriv("invalid bpf_context access off=152 size=8"),
        __retval("0");
    read_tstamp_from_cgroup_skb:
        __description("read tstamp from CGROUP_SKB"),
        __success,
        __success_unpriv,
        __retval("0");
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_1_for_cgroup_skb
extern "C" fn test_1_for_cgroup_skb() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r4 = *(u32*)(r1 + 0);",
            "r5 = *(u32*)(r1 + 4);",
            "r6 = *(u32*)(r1 + 8);",
            "*(u32*)(r1 + 8) = r6;",
            "r7 = *(u32*)(r1 + 12);",
            "r8 = *(u32*)(r1 + 16);",
            "r9 = *(u32*)(r1 + 20);",
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

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_2_for_cgroup_skb
extern "C" fn test_2_for_cgroup_skb() {
    unsafe {
        core::arch::asm!(
            "r4 = *(u32*)(r1 + 24);",
            "r5 = *(u32*)(r1 + 28);",
            "r6 = *(u32*)(r1 + 32);",
            "*(u32*)(r1 + 32) = r6;",
            "r7 = *(u32*)(r1 + 36);",
            "r8 = *(u32*)(r1 + 44);",
            "r9 = *(u32*)(r1 + 68);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_3_for_cgroup_skb
extern "C" fn test_3_for_cgroup_skb() {
    unsafe {
        core::arch::asm!(
            "r4 = *(u32*)(r1 + 48);",
            "r5 = *(u32*)(r1 + 52);",
            "r6 = *(u32*)(r1 + 56);",
            "r7 = *(u32*)(r1 + 60);",
            "r8 = *(u32*)(r1 + 64);",
            "r9 = *(u32*)(r1 + 84);",
            "*(u32*)(r1 + 48) = r4;",
            "*(u32*)(r1 + 52) = r5;",
            "*(u32*)(r1 + 56) = r6;",
            "*(u32*)(r1 + 60) = r7;",
            "*(u32*)(r1 + 64) = r8;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: test_4_for_cgroup_skb
extern "C" fn test_4_for_cgroup_skb() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 88);",
            "r3 = *(u32*)(r1 + 92);",
            "r4 = *(u32*)(r1 + 96);",
            "r5 = *(u32*)(r1 + 100);",
            "r5 = *(u32*)(r1 + 104);",
            "r5 = *(u32*)(r1 + 108);",
            "r5 = *(u32*)(r1 + 112);",
            "r6 = *(u32*)(r1 + 116);",
            "r6 = *(u32*)(r1 + 120);",
            "r6 = *(u32*)(r1 + 124);",
            "r6 = *(u32*)(r1 + 128);",
            "r7 = *(u32*)(r1 + 132);",
            "r8 = *(u32*)(r1 + 136);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tc_classid_for_cgroup_skb
extern "C" fn tc_classid_for_cgroup_skb() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 72);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_meta_for_cgroup_skb
extern "C" fn data_meta_for_cgroup_skb() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 140);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: flow_keys_for_cgroup_skb
extern "C" fn flow_keys_for_cgroup_skb() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u32*)(r1 + 144);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: napi_id_for_cgroup_skb
extern "C" fn napi_id_for_cgroup_skb() {
    unsafe {
        core::arch::asm!(
            "r9 = *(u32*)(r1 + 84);",
            "*(u32*)(r1 + 84) = r9;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: write_tstamp_from_cgroup_skb
extern "C" fn write_tstamp_from_cgroup_skb() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64*)(r1 + 152) = r0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_tstamp_from_cgroup_skb
extern "C" fn read_tstamp_from_cgroup_skb() {
    unsafe {
        core::arch::asm!(
            "r0 = *(u64*)(r1 + 152);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
