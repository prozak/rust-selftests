// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_xdp_direct_packet_access.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_xdp_direct_packet_access` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: end_mangling_bad_access_1 end_mangling_bad_access_2 end_corner_case_good_access_1 pkt_end_bad_access_1_1 pkt_end_bad_access_2_1 corner_case_1_good_access_1 corner_case_1_bad_access_1 end_pkt_data_good_access_1 corner_case_1_bad_access_2 pkt_data_bad_access_2_1 data_corner_case_good_access_1 corner_case_1_good_access_2 data_pkt_end_good_access_1 corner_case_1_bad_access_3 pkt_end_bad_access_2_2 end_corner_case_good_access_2 corner_case_1_good_access_3 data_corner_case_good_access_2 pkt_data_bad_access_1_1 pkt_data_bad_access_2_2 corner_case_1_good_access_4 corner_case_1_bad_access_4 data_pkt_end_good_access_2 corner_case_1_bad_access_5 pkt_end_bad_access_2_3 end_corner_case_good_access_3 corner_case_1_good_access_5 data_corner_case_good_access_3 pkt_data_bad_access_1_2 pkt_data_bad_access_2_3 corner_case_1_good_access_6 corner_case_1_bad_access_6 end_corner_case_good_access_4 pkt_end_bad_access_1_2 pkt_end_bad_access_2_4 corner_case_1_good_access_7 corner_case_1_bad_access_7 end_pkt_data_good_access_2 corner_case_1_bad_access_8 pkt_data_bad_access_2_4 data_corner_case_good_access_4 corner_case_1_good_access_8 data_corner_case_good_access_5 pkt_data_bad_access_1_3 pkt_data_bad_access_2_5 corner_case_1_good_access_9 corner_case_1_bad_access_9 data_pkt_meta_good_access_1 corner_case_1_bad_access_10 pkt_meta_bad_access_2_1 meta_corner_case_good_access_1 corner_case_1_good_access_10 meta_pkt_data_good_access_1 corner_case_1_bad_access_11 pkt_data_bad_access_2_6 data_corner_case_good_access_6 corner_case_1_good_access_11 meta_corner_case_good_access_2 pkt_meta_bad_access_1_1 pkt_meta_bad_access_2_2 corner_case_1_good_access_12 corner_case_1_bad_access_12 meta_pkt_data_good_access_2 corner_case_1_bad_access_13 pkt_data_bad_access_2_7 data_corner_case_good_access_7 corner_case_1_good_access_13 meta_corner_case_good_access_3 pkt_meta_bad_access_1_2 pkt_meta_bad_access_2_3 corner_case_1_good_access_14 corner_case_1_bad_access_14 data_corner_case_good_access_8 pkt_data_bad_access_1_4 pkt_data_bad_access_2_8 corner_case_1_good_access_15 corner_case_1_bad_access_15 data_pkt_meta_good_access_2 corner_case_1_bad_access_16 pkt_meta_bad_access_2_4 meta_corner_case_good_access_4 corner_case_1_good_access_16 pkt_regsafe_class_displacement

use bpf_rs_core::{bpf_object, test_tags};

test_tags! {
    end_mangling_bad_access_1:
        __description("XDP pkt read, pkt_end mangling, bad access 1"),
        __failure,
        __msg("R3 pointer arithmetic on pkt_end");
    end_mangling_bad_access_2:
        __description("XDP pkt read, pkt_end mangling, bad access 2"),
        __failure,
        __msg("R3 pointer arithmetic on pkt_end");
    end_corner_case_good_access_1:
        __description("XDP pkt read, pkt_data' > pkt_end, corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_end_bad_access_1_1:
        __description("XDP pkt read, pkt_data' > pkt_end, bad access 1"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_end_bad_access_2_1:
        __description("XDP pkt read, pkt_data' > pkt_end, bad access 2"),
        __failure,
        __msg("R1 offset is outside of the packet"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_1:
        __description("XDP pkt read, pkt_data' > pkt_end, corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_1:
        __description("XDP pkt read, pkt_data' > pkt_end, corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    end_pkt_data_good_access_1:
        __description("XDP pkt read, pkt_end > pkt_data', good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_2:
        __description("XDP pkt read, pkt_end > pkt_data', corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_data_bad_access_2_1:
        __description("XDP pkt read, pkt_end > pkt_data', bad access 2"),
        __failure,
        __msg("R1 offset is outside of the packet"),
        __flag("BPF_F_ANY_ALIGNMENT");
    data_corner_case_good_access_1:
        __description("XDP pkt read, pkt_end > pkt_data', corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_2:
        __description("XDP pkt read, pkt_end > pkt_data', corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    data_pkt_end_good_access_1:
        __description("XDP pkt read, pkt_data' < pkt_end, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_3:
        __description("XDP pkt read, pkt_data' < pkt_end, corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_end_bad_access_2_2:
        __description("XDP pkt read, pkt_data' < pkt_end, bad access 2"),
        __failure,
        __msg("R1 offset is outside of the packet"),
        __flag("BPF_F_ANY_ALIGNMENT");
    end_corner_case_good_access_2:
        __description("XDP pkt read, pkt_data' < pkt_end, corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_3:
        __description("XDP pkt read, pkt_data' < pkt_end, corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    data_corner_case_good_access_2:
        __description("XDP pkt read, pkt_end < pkt_data', corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_data_bad_access_1_1:
        __description("XDP pkt read, pkt_end < pkt_data', bad access 1"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_data_bad_access_2_2:
        __description("XDP pkt read, pkt_end < pkt_data', bad access 2"),
        __failure,
        __msg("R1 offset is outside of the packet"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_4:
        __description("XDP pkt read, pkt_end < pkt_data', corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_4:
        __description("XDP pkt read, pkt_end < pkt_data', corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    data_pkt_end_good_access_2:
        __description("XDP pkt read, pkt_data' >= pkt_end, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_5:
        __description("XDP pkt read, pkt_data' >= pkt_end, corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_end_bad_access_2_3:
        __description("XDP pkt read, pkt_data' >= pkt_end, bad access 2"),
        __failure,
        __msg("R1 offset is outside of the packet"),
        __flag("BPF_F_ANY_ALIGNMENT");
    end_corner_case_good_access_3:
        __description("XDP pkt read, pkt_data' >= pkt_end, corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_5:
        __description("XDP pkt read, pkt_data' >= pkt_end, corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    data_corner_case_good_access_3:
        __description("XDP pkt read, pkt_end >= pkt_data', corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_data_bad_access_1_2:
        __description("XDP pkt read, pkt_end >= pkt_data', bad access 1"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_data_bad_access_2_3:
        __description("XDP pkt read, pkt_end >= pkt_data', bad access 2"),
        __failure,
        __msg("R1 offset is outside of the packet"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_6:
        __description("XDP pkt read, pkt_end >= pkt_data', corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_6:
        __description("XDP pkt read, pkt_end >= pkt_data', corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    end_corner_case_good_access_4:
        __description("XDP pkt read, pkt_data' <= pkt_end, corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_end_bad_access_1_2:
        __description("XDP pkt read, pkt_data' <= pkt_end, bad access 1"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_end_bad_access_2_4:
        __description("XDP pkt read, pkt_data' <= pkt_end, bad access 2"),
        __failure,
        __msg("R1 offset is outside of the packet"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_7:
        __description("XDP pkt read, pkt_data' <= pkt_end, corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_7:
        __description("XDP pkt read, pkt_data' <= pkt_end, corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    end_pkt_data_good_access_2:
        __description("XDP pkt read, pkt_end <= pkt_data', good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_8:
        __description("XDP pkt read, pkt_end <= pkt_data', corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_data_bad_access_2_4:
        __description("XDP pkt read, pkt_end <= pkt_data', bad access 2"),
        __failure,
        __msg("R1 offset is outside of the packet"),
        __flag("BPF_F_ANY_ALIGNMENT");
    data_corner_case_good_access_4:
        __description("XDP pkt read, pkt_end <= pkt_data', corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_8:
        __description("XDP pkt read, pkt_end <= pkt_data', corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    data_corner_case_good_access_5:
        __description("XDP pkt read, pkt_meta' > pkt_data, corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_data_bad_access_1_3:
        __description("XDP pkt read, pkt_meta' > pkt_data, bad access 1"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_data_bad_access_2_5:
        __description("XDP pkt read, pkt_meta' > pkt_data, bad access 2"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_9:
        __description("XDP pkt read, pkt_meta' > pkt_data, corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_9:
        __description("XDP pkt read, pkt_meta' > pkt_data, corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    data_pkt_meta_good_access_1:
        __description("XDP pkt read, pkt_data > pkt_meta', good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_10:
        __description("XDP pkt read, pkt_data > pkt_meta', corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_meta_bad_access_2_1:
        __description("XDP pkt read, pkt_data > pkt_meta', bad access 2"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    meta_corner_case_good_access_1:
        __description("XDP pkt read, pkt_data > pkt_meta', corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_10:
        __description("XDP pkt read, pkt_data > pkt_meta', corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    meta_pkt_data_good_access_1:
        __description("XDP pkt read, pkt_meta' < pkt_data, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_11:
        __description("XDP pkt read, pkt_meta' < pkt_data, corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_data_bad_access_2_6:
        __description("XDP pkt read, pkt_meta' < pkt_data, bad access 2"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    data_corner_case_good_access_6:
        __description("XDP pkt read, pkt_meta' < pkt_data, corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_11:
        __description("XDP pkt read, pkt_meta' < pkt_data, corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    meta_corner_case_good_access_2:
        __description("XDP pkt read, pkt_data < pkt_meta', corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_meta_bad_access_1_1:
        __description("XDP pkt read, pkt_data < pkt_meta', bad access 1"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_meta_bad_access_2_2:
        __description("XDP pkt read, pkt_data < pkt_meta', bad access 2"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_12:
        __description("XDP pkt read, pkt_data < pkt_meta', corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_12:
        __description("XDP pkt read, pkt_data < pkt_meta', corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    meta_pkt_data_good_access_2:
        __description("XDP pkt read, pkt_meta' >= pkt_data, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_13:
        __description("XDP pkt read, pkt_meta' >= pkt_data, corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_data_bad_access_2_7:
        __description("XDP pkt read, pkt_meta' >= pkt_data, bad access 2"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    data_corner_case_good_access_7:
        __description("XDP pkt read, pkt_meta' >= pkt_data, corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_13:
        __description("XDP pkt read, pkt_meta' >= pkt_data, corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    meta_corner_case_good_access_3:
        __description("XDP pkt read, pkt_data >= pkt_meta', corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_meta_bad_access_1_2:
        __description("XDP pkt read, pkt_data >= pkt_meta', bad access 1"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_meta_bad_access_2_3:
        __description("XDP pkt read, pkt_data >= pkt_meta', bad access 2"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_14:
        __description("XDP pkt read, pkt_data >= pkt_meta', corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_14:
        __description("XDP pkt read, pkt_data >= pkt_meta', corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    data_corner_case_good_access_8:
        __description("XDP pkt read, pkt_meta' <= pkt_data, corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_data_bad_access_1_4:
        __description("XDP pkt read, pkt_meta' <= pkt_data, bad access 1"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_data_bad_access_2_8:
        __description("XDP pkt read, pkt_meta' <= pkt_data, bad access 2"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_15:
        __description("XDP pkt read, pkt_meta' <= pkt_data, corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_15:
        __description("XDP pkt read, pkt_meta' <= pkt_data, corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    data_pkt_meta_good_access_2:
        __description("XDP pkt read, pkt_data <= pkt_meta', good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_bad_access_16:
        __description("XDP pkt read, pkt_data <= pkt_meta', corner case -1, bad access"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_meta_bad_access_2_4:
        __description("XDP pkt read, pkt_data <= pkt_meta', bad access 2"),
        __failure,
        __msg("R1 {{min|max}} value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT");
    meta_corner_case_good_access_4:
        __description("XDP pkt read, pkt_data <= pkt_meta', corner case, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    corner_case_1_good_access_16:
        __description("XDP pkt read, pkt_data <= pkt_meta', corner case +1, good access"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    pkt_regsafe_class_displacement:
        __description("XDP pkt regsafe preserves packet pointer class displacement"),
        __failure,
        __msg("R2 min value is outside of the allowed memory range"),
        __flag("BPF_F_ANY_ALIGNMENT"),
        __flag("BPF_F_TEST_STATE_FREQ");
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: end_mangling_bad_access_1
extern "C" fn end_mangling_bad_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "r3 += 8;",
            "if r1 > r3 goto l0_0;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: end_mangling_bad_access_2
extern "C" fn end_mangling_bad_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "r3 -= 8;",
            "if r1 > r3 goto l0_1;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: end_corner_case_good_access_1
extern "C" fn end_corner_case_good_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 > r3 goto l0_2;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_end_bad_access_1_1
extern "C" fn pkt_end_bad_access_1_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 > r3 goto l0_3;",
            "r0 = *(u64*)(r1 - 4);",
            "l0_3:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_end_bad_access_2_1
extern "C" fn pkt_end_bad_access_2_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 > r3 goto l0_4;",
            "l0_4:",
            "r0 = *(u64*)(r1 - 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_1
extern "C" fn corner_case_1_good_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 9;",
            "if r1 > r3 goto l0_5;",
            "r0 = *(u64*)(r1 - 9);",
            "l0_5:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_1
extern "C" fn corner_case_1_bad_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 7;",
            "if r1 > r3 goto l0_6;",
            "r0 = *(u64*)(r1 - 7);",
            "l0_6:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: end_pkt_data_good_access_1
extern "C" fn end_pkt_data_good_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 > r1 goto l0_7;",
            "goto l1_7;",
            "l0_7:",
            "r0 = *(u32*)(r1 - 5);",
            "l1_7:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_2
extern "C" fn corner_case_1_bad_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 6;",
            "if r3 > r1 goto l0_8;",
            "goto l1_8;",
            "l0_8:",
            "r0 = *(u64*)(r1 - 6);",
            "l1_8:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_data_bad_access_2_1
extern "C" fn pkt_data_bad_access_2_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 > r1 goto l0_9;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_9:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_corner_case_good_access_1
extern "C" fn data_corner_case_good_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 7;",
            "if r3 > r1 goto l0_10;",
            "goto l1_10;",
            "l0_10:",
            "r0 = *(u64*)(r1 - 7);",
            "l1_10:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_2
extern "C" fn corner_case_1_good_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 > r1 goto l0_11;",
            "goto l1_11;",
            "l0_11:",
            "r0 = *(u64*)(r1 - 8);",
            "l1_11:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_pkt_end_good_access_1
extern "C" fn data_pkt_end_good_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 < r3 goto l0_12;",
            "goto l1_12;",
            "l0_12:",
            "r0 = *(u32*)(r1 - 5);",
            "l1_12:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_3
extern "C" fn corner_case_1_bad_access_3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 6;",
            "if r1 < r3 goto l0_13;",
            "goto l1_13;",
            "l0_13:",
            "r0 = *(u64*)(r1 - 6);",
            "l1_13:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_end_bad_access_2_2
extern "C" fn pkt_end_bad_access_2_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 < r3 goto l0_14;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_14:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: end_corner_case_good_access_2
extern "C" fn end_corner_case_good_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 7;",
            "if r1 < r3 goto l0_15;",
            "goto l1_15;",
            "l0_15:",
            "r0 = *(u64*)(r1 - 7);",
            "l1_15:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_3
extern "C" fn corner_case_1_good_access_3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 < r3 goto l0_16;",
            "goto l1_16;",
            "l0_16:",
            "r0 = *(u64*)(r1 - 8);",
            "l1_16:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_corner_case_good_access_2
extern "C" fn data_corner_case_good_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 < r1 goto l0_17;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_17:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_data_bad_access_1_1
extern "C" fn pkt_data_bad_access_1_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 < r1 goto l0_18;",
            "r0 = *(u64*)(r1 - 4);",
            "l0_18:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_data_bad_access_2_2
extern "C" fn pkt_data_bad_access_2_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 < r1 goto l0_19;",
            "l0_19:",
            "r0 = *(u64*)(r1 - 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_4
extern "C" fn corner_case_1_good_access_4() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 9;",
            "if r3 < r1 goto l0_20;",
            "r0 = *(u64*)(r1 - 9);",
            "l0_20:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_4
extern "C" fn corner_case_1_bad_access_4() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 7;",
            "if r3 < r1 goto l0_21;",
            "r0 = *(u64*)(r1 - 7);",
            "l0_21:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_pkt_end_good_access_2
extern "C" fn data_pkt_end_good_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 >= r3 goto l0_22;",
            "r0 = *(u32*)(r1 - 5);",
            "l0_22:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_5
extern "C" fn corner_case_1_bad_access_5() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 6;",
            "if r1 >= r3 goto l0_23;",
            "r0 = *(u64*)(r1 - 6);",
            "l0_23:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_end_bad_access_2_3
extern "C" fn pkt_end_bad_access_2_3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 >= r3 goto l0_24;",
            "l0_24:",
            "r0 = *(u32*)(r1 - 5);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: end_corner_case_good_access_3
extern "C" fn end_corner_case_good_access_3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 7;",
            "if r1 >= r3 goto l0_25;",
            "r0 = *(u64*)(r1 - 7);",
            "l0_25:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_5
extern "C" fn corner_case_1_good_access_5() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 >= r3 goto l0_26;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_26:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_corner_case_good_access_3
extern "C" fn data_corner_case_good_access_3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 >= r1 goto l0_27;",
            "goto l1_27;",
            "l0_27:",
            "r0 = *(u64*)(r1 - 8);",
            "l1_27:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_data_bad_access_1_2
extern "C" fn pkt_data_bad_access_1_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 >= r1 goto l0_28;",
            "goto l1_28;",
            "l0_28:",
            "r0 = *(u64*)(r1 - 4);",
            "l1_28:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_data_bad_access_2_3
extern "C" fn pkt_data_bad_access_2_3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 >= r1 goto l0_29;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_29:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_6
extern "C" fn corner_case_1_good_access_6() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 9;",
            "if r3 >= r1 goto l0_30;",
            "goto l1_30;",
            "l0_30:",
            "r0 = *(u64*)(r1 - 9);",
            "l1_30:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_6
extern "C" fn corner_case_1_bad_access_6() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 7;",
            "if r3 >= r1 goto l0_31;",
            "goto l1_31;",
            "l0_31:",
            "r0 = *(u64*)(r1 - 7);",
            "l1_31:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: end_corner_case_good_access_4
extern "C" fn end_corner_case_good_access_4() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 <= r3 goto l0_32;",
            "goto l1_32;",
            "l0_32:",
            "r0 = *(u64*)(r1 - 8);",
            "l1_32:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_end_bad_access_1_2
extern "C" fn pkt_end_bad_access_1_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 <= r3 goto l0_33;",
            "goto l1_33;",
            "l0_33:",
            "r0 = *(u64*)(r1 - 4);",
            "l1_33:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_end_bad_access_2_4
extern "C" fn pkt_end_bad_access_2_4() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 <= r3 goto l0_34;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_34:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_7
extern "C" fn corner_case_1_good_access_7() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 9;",
            "if r1 <= r3 goto l0_35;",
            "goto l1_35;",
            "l0_35:",
            "r0 = *(u64*)(r1 - 9);",
            "l1_35:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_7
extern "C" fn corner_case_1_bad_access_7() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 7;",
            "if r1 <= r3 goto l0_36;",
            "goto l1_36;",
            "l0_36:",
            "r0 = *(u64*)(r1 - 7);",
            "l1_36:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: end_pkt_data_good_access_2
extern "C" fn end_pkt_data_good_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 <= r1 goto l0_37;",
            "r0 = *(u32*)(r1 - 5);",
            "l0_37:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_8
extern "C" fn corner_case_1_bad_access_8() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 6;",
            "if r3 <= r1 goto l0_38;",
            "r0 = *(u64*)(r1 - 6);",
            "l0_38:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_data_bad_access_2_4
extern "C" fn pkt_data_bad_access_2_4() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 <= r1 goto l0_39;",
            "l0_39:",
            "r0 = *(u32*)(r1 - 5);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_corner_case_good_access_4
extern "C" fn data_corner_case_good_access_4() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 7;",
            "if r3 <= r1 goto l0_40;",
            "r0 = *(u64*)(r1 - 7);",
            "l0_40:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_8
extern "C" fn corner_case_1_good_access_8() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r3 = *(u32*)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 <= r1 goto l0_41;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_41:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_corner_case_good_access_5
extern "C" fn data_corner_case_good_access_5() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 > r3 goto l0_42;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_42:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_data_bad_access_1_3
extern "C" fn pkt_data_bad_access_1_3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 > r3 goto l0_43;",
            "r0 = *(u64*)(r1 - 4);",
            "l0_43:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_data_bad_access_2_5
extern "C" fn pkt_data_bad_access_2_5() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 > r3 goto l0_44;",
            "l0_44:",
            "r0 = *(u64*)(r1 - 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_9
extern "C" fn corner_case_1_good_access_9() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 9;",
            "if r1 > r3 goto l0_45;",
            "r0 = *(u64*)(r1 - 9);",
            "l0_45:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_9
extern "C" fn corner_case_1_bad_access_9() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 7;",
            "if r1 > r3 goto l0_46;",
            "r0 = *(u64*)(r1 - 7);",
            "l0_46:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_pkt_meta_good_access_1
extern "C" fn data_pkt_meta_good_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 > r1 goto l0_47;",
            "goto l1_47;",
            "l0_47:",
            "r0 = *(u32*)(r1 - 5);",
            "l1_47:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_10
extern "C" fn corner_case_1_bad_access_10() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 6;",
            "if r3 > r1 goto l0_48;",
            "goto l1_48;",
            "l0_48:",
            "r0 = *(u64*)(r1 - 6);",
            "l1_48:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_meta_bad_access_2_1
extern "C" fn pkt_meta_bad_access_2_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 > r1 goto l0_49;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_49:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_corner_case_good_access_1
extern "C" fn meta_corner_case_good_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 7;",
            "if r3 > r1 goto l0_50;",
            "goto l1_50;",
            "l0_50:",
            "r0 = *(u64*)(r1 - 7);",
            "l1_50:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_10
extern "C" fn corner_case_1_good_access_10() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 > r1 goto l0_51;",
            "goto l1_51;",
            "l0_51:",
            "r0 = *(u64*)(r1 - 8);",
            "l1_51:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_pkt_data_good_access_1
extern "C" fn meta_pkt_data_good_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 < r3 goto l0_52;",
            "goto l1_52;",
            "l0_52:",
            "r0 = *(u32*)(r1 - 5);",
            "l1_52:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_11
extern "C" fn corner_case_1_bad_access_11() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 6;",
            "if r1 < r3 goto l0_53;",
            "goto l1_53;",
            "l0_53:",
            "r0 = *(u64*)(r1 - 6);",
            "l1_53:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_data_bad_access_2_6
extern "C" fn pkt_data_bad_access_2_6() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 < r3 goto l0_54;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_54:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_corner_case_good_access_6
extern "C" fn data_corner_case_good_access_6() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 7;",
            "if r1 < r3 goto l0_55;",
            "goto l1_55;",
            "l0_55:",
            "r0 = *(u64*)(r1 - 7);",
            "l1_55:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_11
extern "C" fn corner_case_1_good_access_11() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 < r3 goto l0_56;",
            "goto l1_56;",
            "l0_56:",
            "r0 = *(u64*)(r1 - 8);",
            "l1_56:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_corner_case_good_access_2
extern "C" fn meta_corner_case_good_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 < r1 goto l0_57;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_57:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_meta_bad_access_1_1
extern "C" fn pkt_meta_bad_access_1_1() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 < r1 goto l0_58;",
            "r0 = *(u64*)(r1 - 4);",
            "l0_58:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_meta_bad_access_2_2
extern "C" fn pkt_meta_bad_access_2_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 < r1 goto l0_59;",
            "l0_59:",
            "r0 = *(u64*)(r1 - 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_12
extern "C" fn corner_case_1_good_access_12() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 9;",
            "if r3 < r1 goto l0_60;",
            "r0 = *(u64*)(r1 - 9);",
            "l0_60:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_12
extern "C" fn corner_case_1_bad_access_12() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 7;",
            "if r3 < r1 goto l0_61;",
            "r0 = *(u64*)(r1 - 7);",
            "l0_61:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_pkt_data_good_access_2
extern "C" fn meta_pkt_data_good_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 >= r3 goto l0_62;",
            "r0 = *(u32*)(r1 - 5);",
            "l0_62:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_13
extern "C" fn corner_case_1_bad_access_13() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 6;",
            "if r1 >= r3 goto l0_63;",
            "r0 = *(u64*)(r1 - 6);",
            "l0_63:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_data_bad_access_2_7
extern "C" fn pkt_data_bad_access_2_7() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 >= r3 goto l0_64;",
            "l0_64:",
            "r0 = *(u32*)(r1 - 5);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_corner_case_good_access_7
extern "C" fn data_corner_case_good_access_7() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 7;",
            "if r1 >= r3 goto l0_65;",
            "r0 = *(u64*)(r1 - 7);",
            "l0_65:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_13
extern "C" fn corner_case_1_good_access_13() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 >= r3 goto l0_66;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_66:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_corner_case_good_access_3
extern "C" fn meta_corner_case_good_access_3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 >= r1 goto l0_67;",
            "goto l1_67;",
            "l0_67:",
            "r0 = *(u64*)(r1 - 8);",
            "l1_67:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_meta_bad_access_1_2
extern "C" fn pkt_meta_bad_access_1_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 >= r1 goto l0_68;",
            "goto l1_68;",
            "l0_68:",
            "r0 = *(u64*)(r1 - 4);",
            "l1_68:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_meta_bad_access_2_3
extern "C" fn pkt_meta_bad_access_2_3() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 >= r1 goto l0_69;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_69:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_14
extern "C" fn corner_case_1_good_access_14() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 9;",
            "if r3 >= r1 goto l0_70;",
            "goto l1_70;",
            "l0_70:",
            "r0 = *(u64*)(r1 - 9);",
            "l1_70:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_14
extern "C" fn corner_case_1_bad_access_14() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 7;",
            "if r3 >= r1 goto l0_71;",
            "goto l1_71;",
            "l0_71:",
            "r0 = *(u64*)(r1 - 7);",
            "l1_71:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_corner_case_good_access_8
extern "C" fn data_corner_case_good_access_8() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 <= r3 goto l0_72;",
            "goto l1_72;",
            "l0_72:",
            "r0 = *(u64*)(r1 - 8);",
            "l1_72:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_data_bad_access_1_4
extern "C" fn pkt_data_bad_access_1_4() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 <= r3 goto l0_73;",
            "goto l1_73;",
            "l0_73:",
            "r0 = *(u64*)(r1 - 4);",
            "l1_73:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_data_bad_access_2_8
extern "C" fn pkt_data_bad_access_2_8() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 <= r3 goto l0_74;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_74:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_15
extern "C" fn corner_case_1_good_access_15() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 9;",
            "if r1 <= r3 goto l0_75;",
            "goto l1_75;",
            "l0_75:",
            "r0 = *(u64*)(r1 - 9);",
            "l1_75:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_15
extern "C" fn corner_case_1_bad_access_15() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 7;",
            "if r1 <= r3 goto l0_76;",
            "goto l1_76;",
            "l0_76:",
            "r0 = *(u64*)(r1 - 7);",
            "l1_76:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: data_pkt_meta_good_access_2
extern "C" fn data_pkt_meta_good_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 <= r1 goto l0_77;",
            "r0 = *(u32*)(r1 - 5);",
            "l0_77:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_bad_access_16
extern "C" fn corner_case_1_bad_access_16() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 6;",
            "if r3 <= r1 goto l0_78;",
            "r0 = *(u64*)(r1 - 6);",
            "l0_78:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_meta_bad_access_2_4
extern "C" fn pkt_meta_bad_access_2_4() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 <= r1 goto l0_79;",
            "l0_79:",
            "r0 = *(u32*)(r1 - 5);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: meta_corner_case_good_access_4
extern "C" fn meta_corner_case_good_access_4() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 7;",
            "if r3 <= r1 goto l0_80;",
            "r0 = *(u64*)(r1 - 7);",
            "l0_80:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: corner_case_1_good_access_16
extern "C" fn corner_case_1_good_access_16() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 8);",
            "r3 = *(u32*)(r1 + 0);",
            "r1 = r2;",
            "r1 += 8;",
            "if r3 <= r1 goto l0_81;",
            "r0 = *(u64*)(r1 - 8);",
            "l0_81:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: pkt_regsafe_class_displacement
extern "C" fn pkt_regsafe_class_displacement() {
    unsafe {
        core::arch::asm!(
            "r8 = *(u32 *)(r1 + 4);",
            "r9 = *(u32 *)(r1 + 0);",
            "r4 = *(u32 *)(r1 + 16);",
            "r4 &= 15;",
            "r0 = *(u32 *)(r1 + 12);",
            "if r0 != 0 goto l0_82;",
            "r2 = r9;",
            "r2 += r4;",
            "r3 = r2;",
            "r3 += 8;",
            "goto l1_82;",
            "l0_82:",
            "r4 &= 3;",
            "r4 += 8;",
            "r2 = r9;",
            "r2 += r4;",
            "r3 = r2;",
            "l1_82:",
            "if r3 > r8 goto l2_82;",
            "r0 = *(u64 *)(r2 + 0);",
            "l2_82:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

bpf_object!("GPL");
