// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_xdp.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_xdp` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: xdp_using_ifindex_from_netdev xdp_store_bytes_from_ro_map

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    xdp_using_ifindex_from_netdev:
        __description("XDP, using ifindex from netdev"),
        __success,
        __retval("1");
    xdp_store_bytes_from_ro_map:
        __description("XDP, using xdp_store_bytes from RO map"),
        __success,
        __retval("0");
}

bpf_map! {
    map_array_ro {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const u64,
        map_flags: *const [i32; 128],
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: xdp_using_ifindex_from_netdev
extern "C" fn xdp_using_ifindex_from_netdev() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r2 = *(u32*)(r1 + 12);",
            "if r2 < 1 goto l0_0;",
            "r0 = 1;",
            "l0_0:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: xdp_store_bytes_from_ro_map
extern "C" fn xdp_store_bytes_from_ro_map() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_array_ro} ll;",
            "call 1;",
            "if r0 == 0 goto l0_1;",
            "r1 = r6;",
            "r2 = 0;",
            "r3 = r0;",
            "r4 = 8;",
            "call 190;",
            "l0_1:",
            "exit;",
            map_array_ro = sym map_array_ro,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
