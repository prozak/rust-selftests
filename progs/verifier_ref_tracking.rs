// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_ref_tracking.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_ref_tracking` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: __kfunc_btf_root dummy_prog_42_tc dummy_prog_24_tc dummy_prog_loop1_tc reference_tracking_leak_potential_reference potential_reference_to_sock_common_1 leak_potential_reference_on_stack potential_reference_on_stack_2 reference_tracking_zero_potential_reference potential_reference_to_sock_common_2 copy_and_zero_potential_references acquire_release_user_key_reference acquire_release_system_key_reference user_key_reference_without_check system_key_reference_without_check release_with_null_key_pointer potential_reference_to_user_key potential_reference_to_system_key tracking_release_reference_without_check to_sock_common_without_check reference_tracking_release_reference release_reference_to_sock_common reference_tracking_release_reference_2 reference_tracking_release_reference_twice release_reference_twice_inside_branch check_free_in_one_subbranch check_free_in_both_subbranches call_free_reference_in_subprog call_free_reference_in_subprog__1 reference_in_subprog_and_outside reference_in_subprog_and_outside__1 alloc_leak_reference_in_subprog alloc_leak_reference_in_subprog__1 alloc_in_subprog_release_outside alloc_in_subprog_release_outside__1 ptr_leak_into_caller_stack ptr_leak_into_caller_stack__1 ptr_leak_into_caller_stack__2 ptr_spill_into_caller_stack ptr_spill_into_caller_stack__1 ptr_spill_into_caller_stack__2 reference_tracking_allow_ld_abs ld_abs_while_holding_reference reference_tracking_allow_ld_ind ld_ind_while_holding_reference check_reference_or_tail_call release_reference_then_tail_call possible_reference_over_tail_call checked_reference_over_tail_call and_release_sock_or_null tracking_mangle_and_release_sock reference_tracking_access_member reference_tracking_write_to_member _64_bit_access_of_member reference_tracking_access_after_release tracking_direct_access_for_lookup bpf_tcp_sock_after_release bpf_sk_fullsock_after_release sk_fullsock_tp_after_release after_bpf_sk_release_tp after_bpf_sk_release_sk bpf_sk_release_listen_sk and_bpf_tcp_sock_sk tracking_valid_pointer_null_comparison tracking_valid_pointer_value_comparison sk_release_btf_tcp_sock to_tcp_sock_after_release to_leak_released_ptr_reg

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    dummy_prog_42_tc:
        __auxiliary;
    dummy_prog_24_tc:
        __auxiliary;
    dummy_prog_loop1_tc:
        __auxiliary;
    reference_tracking_leak_potential_reference:
        __description("reference tracking: leak potential reference"),
        __failure,
        __msg("Unreleased reference");
    potential_reference_to_sock_common_1:
        __description("reference tracking: leak potential reference to sock_common"),
        __failure,
        __msg("Unreleased reference");
    leak_potential_reference_on_stack:
        __description("reference tracking: leak potential reference on stack"),
        __failure,
        __msg("Unreleased reference");
    potential_reference_on_stack_2:
        __description("reference tracking: leak potential reference on stack 2"),
        __failure,
        __msg("Unreleased reference");
    reference_tracking_zero_potential_reference:
        __description("reference tracking: zero potential reference"),
        __failure,
        __msg("Unreleased reference");
    potential_reference_to_sock_common_2:
        __description("reference tracking: zero potential reference to sock_common"),
        __failure,
        __msg("Unreleased reference");
    copy_and_zero_potential_references:
        __description("reference tracking: copy and zero potential references"),
        __failure,
        __msg("Unreleased reference");
    acquire_release_user_key_reference:
        __description("reference tracking: acquire/release user key reference"),
        __success;
    acquire_release_system_key_reference:
        __description("reference tracking: acquire/release system key reference"),
        __success;
    user_key_reference_without_check:
        __description("reference tracking: release user key reference without check"),
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1");
    system_key_reference_without_check:
        __description("reference tracking: release system key reference without check"),
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1");
    release_with_null_key_pointer:
        __description("reference tracking: release with NULL key pointer"),
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1");
    potential_reference_to_user_key:
        __description("reference tracking: leak potential reference to user key"),
        __failure,
        __msg("Unreleased reference");
    potential_reference_to_system_key:
        __description("reference tracking: leak potential reference to system key"),
        __failure,
        __msg("Unreleased reference");
    tracking_release_reference_without_check:
        __description("reference tracking: release reference without check"),
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1");
    to_sock_common_without_check:
        __description("reference tracking: release reference to sock_common without check"),
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1");
    reference_tracking_release_reference:
        __description("reference tracking: release reference"),
        __success,
        __retval("0");
    release_reference_to_sock_common:
        __description("reference tracking: release reference to sock_common"),
        __success,
        __retval("0");
    reference_tracking_release_reference_2:
        __description("reference tracking: release reference 2"),
        __success,
        __retval("0");
    reference_tracking_release_reference_twice:
        __description("reference tracking: release reference twice"),
        __failure,
        __msg("type=scalar expected=sock");
    release_reference_twice_inside_branch:
        __description("reference tracking: release reference twice inside branch"),
        __failure,
        __msg("type=scalar expected=sock");
    check_free_in_one_subbranch:
        __description("reference tracking: alloc, check, free in one subbranch"),
        __failure,
        __msg("Unreleased reference"),
        __flag("BPF_F_ANY_ALIGNMENT");
    check_free_in_both_subbranches:
        __description("reference tracking: alloc, check, free in both subbranches"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    call_free_reference_in_subprog:
        __description("reference tracking in call: free reference in subprog"),
        __success,
        __retval("0");
    reference_in_subprog_and_outside:
        __description("reference tracking in call: free reference in subprog and outside"),
        __failure,
        __msg("type=scalar expected=sock");
    alloc_leak_reference_in_subprog:
        __description("reference tracking in call: alloc & leak reference in subprog"),
        __failure,
        __msg("Unreleased reference");
    alloc_in_subprog_release_outside:
        __description("reference tracking in call: alloc in subprog, release outside"),
        __success,
        __retval("0xbadcafe");
    ptr_leak_into_caller_stack:
        __description("reference tracking in call: sk_ptr leak into caller stack"),
        __failure,
        __msg("Unreleased reference");
    ptr_spill_into_caller_stack:
        __description("reference tracking in call: sk_ptr spill into caller stack"),
        __success,
        __retval("0");
    reference_tracking_allow_ld_abs:
        __description("reference tracking: allow LD_ABS"),
        __success,
        __retval("0");
    ld_abs_while_holding_reference:
        __description("reference tracking: forbid LD_ABS while holding reference"),
        __failure,
        __msg("BPF_LD_[ABS|IND] would lead to reference leak");
    reference_tracking_allow_ld_ind:
        __description("reference tracking: allow LD_IND"),
        __success,
        __retval("1");
    ld_ind_while_holding_reference:
        __description("reference tracking: forbid LD_IND while holding reference"),
        __failure,
        __msg("BPF_LD_[ABS|IND] would lead to reference leak");
    check_reference_or_tail_call:
        __description("reference tracking: check reference or tail call"),
        __success,
        __retval("0");
    release_reference_then_tail_call:
        __description("reference tracking: release reference then tail call"),
        __success,
        __retval("0");
    possible_reference_over_tail_call:
        __description("reference tracking: leak possible reference over tail call"),
        __failure,
        __msg("tail_call would lead to reference leak");
    checked_reference_over_tail_call:
        __description("reference tracking: leak checked reference over tail call"),
        __failure,
        __msg("tail_call would lead to reference leak");
    and_release_sock_or_null:
        __description("reference tracking: mangle and release sock_or_null"),
        __failure,
        __msg("R1 pointer arithmetic on sock_or_null prohibited");
    tracking_mangle_and_release_sock:
        __description("reference tracking: mangle and release sock"),
        __failure,
        __msg("R1 pointer arithmetic on sock prohibited");
    reference_tracking_access_member:
        __description("reference tracking: access member"),
        __success,
        __retval("0");
    reference_tracking_write_to_member:
        __description("reference tracking: write to member"),
        __failure,
        __msg("cannot write into sock");
    _64_bit_access_of_member:
        __description("reference tracking: invalid 64-bit access of member"),
        __failure,
        __msg("invalid sock access off=0 size=8");
    reference_tracking_access_after_release:
        __description("reference tracking: access after release"),
        __failure,
        __msg("!read_ok");
    tracking_direct_access_for_lookup:
        __description("reference tracking: direct access for lookup"),
        __success,
        __retval("0");
    bpf_tcp_sock_after_release:
        __description("reference tracking: use ptr from bpf_tcp_sock() after release"),
        __failure,
        __msg("invalid mem access"),
        __flag("BPF_F_ANY_ALIGNMENT");
    bpf_sk_fullsock_after_release:
        __description("reference tracking: use ptr from bpf_sk_fullsock() after release"),
        __failure,
        __msg("invalid mem access"),
        __flag("BPF_F_ANY_ALIGNMENT");
    sk_fullsock_tp_after_release:
        __description("reference tracking: use ptr from bpf_sk_fullsock(tp) after release"),
        __failure,
        __msg("invalid mem access"),
        __flag("BPF_F_ANY_ALIGNMENT");
    after_bpf_sk_release_tp:
        __description("reference tracking: use sk after bpf_sk_release(tp)"),
        __failure,
        __msg("invalid mem access"),
        __flag("BPF_F_ANY_ALIGNMENT");
    after_bpf_sk_release_sk:
        __description("reference tracking: use ptr from bpf_get_listener_sock() after bpf_sk_release(sk)"),
        __success,
        __retval("0");
    bpf_sk_release_listen_sk:
        __description("reference tracking: bpf_sk_release(listen_sk)"),
        __failure,
        __msg("release function bpf_sk_release expects referenced PTR_TO_BTF_ID passed to R1");
    and_bpf_tcp_sock_sk:
        __description("reference tracking: tp->snd_cwnd after bpf_sk_fullsock(sk) and bpf_tcp_sock(sk)"),
        __failure,
        __msg("invalid mem access");
    tracking_valid_pointer_null_comparison:
        __description("reference tracking: branch tracking valid pointer null comparison"),
        __success,
        __retval("0");
    tracking_valid_pointer_value_comparison:
        __description("reference tracking: branch tracking valid pointer value comparison"),
        __failure,
        __msg("Unreleased reference");
    sk_release_btf_tcp_sock:
        __description("reference tracking: bpf_sk_release(btf_tcp_sock)"),
        __success,
        __retval("0");
    to_tcp_sock_after_release:
        __description("reference tracking: use ptr from bpf_skc_to_tcp_sock() after release"),
        __failure,
        __msg("invalid mem access");
    to_leak_released_ptr_reg:
        __description("reference tracking: try to leak released ptr reg"),
        __success,
        __failure_unpriv,
        __msg_unpriv("R8 !read_ok"),
        __retval("0");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct test_val {
    index: u32,
    foo: [i32; 11],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_prog1_tc {
    r#type: *const [i32; 3],
    max_entries: *const [i32; 4],
    key_size: *const [i32; 4],
    values: [*const c_void; 3],
}
unsafe impl Sync for map_prog1_tc {}

#[link_section = ".maps"]
#[no_mangle]
static map_prog1_tc: map_prog1_tc = map_prog1_tc {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [dummy_prog_42_tc as extern "C" fn() as *const c_void, dummy_prog_loop1_tc as extern "C" fn() as *const c_void, dummy_prog_24_tc as extern "C" fn() as *const c_void],
};

bpf_map! {
    map_array_48b {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const test_val,
    }
}

bpf_map! {
    map_ringbuf {
        r#type: *const [i32; 27],
        max_entries: *const [i32; 4096],
    }
}

extern "C" {
    fn bpf_key_put(a0: *mut c_void);
    fn bpf_lookup_system_key(a0: u64) -> *mut c_void;
    fn bpf_lookup_user_key(a0: i32, a1: u64) -> *mut c_void;
}

// __kfunc_btf_root: the C's reference to each kfunc the asm calls, for its
// BTF prototype (llc emits one only for a real call or address load).
#[no_mangle]
#[inline(never)]
extern "C" fn __kfunc_btf_root() {
    unsafe {
        bpf_key_put(core::ptr::null_mut());
        bpf_lookup_system_key(0);
        bpf_lookup_user_key(0, 0);
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dummy_prog_42_tc
extern "C" fn dummy_prog_42_tc() {
    unsafe {
        core::arch::asm!(
            "r0 = 42;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dummy_prog_24_tc
extern "C" fn dummy_prog_24_tc() {
    unsafe {
        core::arch::asm!(
            "r0 = 24;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dummy_prog_loop1_tc
extern "C" fn dummy_prog_loop1_tc() {
    unsafe {
        core::arch::asm!(
            "r3 = 1;",
            "r2 = {map_prog1_tc} ll;",
            "call 12;",
            "r0 = 41;",
            "exit;",
            map_prog1_tc = sym map_prog1_tc,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reference_tracking_leak_potential_reference
extern "C" fn reference_tracking_leak_potential_reference() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r6 = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: potential_reference_to_sock_common_1
extern "C" fn potential_reference_to_sock_common_1() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 99;",
            "r6 = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: leak_potential_reference_on_stack
extern "C" fn leak_potential_reference_on_stack() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r4 = r10;",
            "r4 += -8;",
            "*(u64*)(r4 + 0) = r0;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: potential_reference_on_stack_2
extern "C" fn potential_reference_on_stack_2() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r4 = r10;",
            "r4 += -8;",
            "*(u64*)(r4 + 0) = r0;",
            "r0 = 0;",
            "r1 = 0;",
            "*(u64*)(r4 + 0) = r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reference_tracking_zero_potential_reference
extern "C" fn reference_tracking_zero_potential_reference() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: potential_reference_to_sock_common_2
extern "C" fn potential_reference_to_sock_common_2() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 99;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: copy_and_zero_potential_references
extern "C" fn copy_and_zero_potential_references() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r7 = r0;",
            "r0 = 0;",
            "r7 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "lsm.s/bpf"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: acquire_release_user_key_reference
extern "C" fn acquire_release_user_key_reference() {
    unsafe {
        core::arch::asm!(
            "r1 = -3;",
            "r2 = 0;",
            "call {bpf_lookup_user_key};",
            "if r0 == 0 goto l0_0;",
            "r1 = r0;",
            "call {bpf_key_put};",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            bpf_key_put = sym bpf_key_put,
            bpf_lookup_user_key = sym bpf_lookup_user_key,
            options(nostack)
        );
    }
}

#[link_section = "lsm.s/bpf"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: acquire_release_system_key_reference
extern "C" fn acquire_release_system_key_reference() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "call {bpf_lookup_system_key};",
            "if r0 == 0 goto l0_1;",
            "r1 = r0;",
            "call {bpf_key_put};",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            bpf_key_put = sym bpf_key_put,
            bpf_lookup_system_key = sym bpf_lookup_system_key,
            options(nostack)
        );
    }
}

#[link_section = "lsm.s/bpf"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: user_key_reference_without_check
extern "C" fn user_key_reference_without_check() {
    unsafe {
        core::arch::asm!(
            "r1 = -3;",
            "r2 = 0;",
            "call {bpf_lookup_user_key};",
            "r1 = r0;",
            "call {bpf_key_put};",
            "r0 = 0;",
            "exit;",
            bpf_key_put = sym bpf_key_put,
            bpf_lookup_user_key = sym bpf_lookup_user_key,
            options(nostack)
        );
    }
}

#[link_section = "lsm.s/bpf"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: system_key_reference_without_check
extern "C" fn system_key_reference_without_check() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "call {bpf_lookup_system_key};",
            "r1 = r0;",
            "call {bpf_key_put};",
            "r0 = 0;",
            "exit;",
            bpf_key_put = sym bpf_key_put,
            bpf_lookup_system_key = sym bpf_lookup_system_key,
            options(nostack)
        );
    }
}

#[link_section = "lsm.s/bpf"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: release_with_null_key_pointer
extern "C" fn release_with_null_key_pointer() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "call {bpf_key_put};",
            "r0 = 0;",
            "exit;",
            bpf_key_put = sym bpf_key_put,
            options(nostack)
        );
    }
}

#[link_section = "lsm.s/bpf"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: potential_reference_to_user_key
extern "C" fn potential_reference_to_user_key() {
    unsafe {
        core::arch::asm!(
            "r1 = -3;",
            "r2 = 0;",
            "call {bpf_lookup_user_key};",
            "exit;",
            bpf_lookup_user_key = sym bpf_lookup_user_key,
            options(nostack)
        );
    }
}

#[link_section = "lsm.s/bpf"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: potential_reference_to_system_key
extern "C" fn potential_reference_to_system_key() {
    unsafe {
        core::arch::asm!(
            "r1 = 1;",
            "call {bpf_lookup_system_key};",
            "exit;",
            bpf_lookup_system_key = sym bpf_lookup_system_key,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tracking_release_reference_without_check
extern "C" fn tracking_release_reference_without_check() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "r2 = 0;",
            "call 86;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_sock_common_without_check
extern "C" fn to_sock_common_without_check() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 99;",
            "r1 = r0;",
            "r2 = 0;",
            "call 86;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reference_tracking_release_reference
extern "C" fn reference_tracking_release_reference() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "if r0 == 0 goto l0_2;",
            "call 86;",
            "l0_2:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: release_reference_to_sock_common
extern "C" fn release_reference_to_sock_common() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 99;",
            "r1 = r0;",
            "if r0 == 0 goto l0_3;",
            "call 86;",
            "l0_3:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reference_tracking_release_reference_2
extern "C" fn reference_tracking_release_reference_2() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "if r0 != 0 goto l0_4;",
            "exit;",
            "l0_4:",
            "call 86;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reference_tracking_release_reference_twice
extern "C" fn reference_tracking_release_reference_twice() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "r6 = r0;",
            "if r0 == 0 goto l0_5;",
            "call 86;",
            "l0_5:",
            "r1 = r6;",
            "call 86;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: release_reference_twice_inside_branch
extern "C" fn release_reference_twice_inside_branch() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "r6 = r0;",
            "if r0 == 0 goto l0_6;",
            "call 86;",
            "r1 = r6;",
            "call 86;",
            "l0_6:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_free_in_one_subbranch
extern "C" fn check_free_in_one_subbranch() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 16;",
            "if r0 <= r3 goto l0_7;",
            "exit;",
            "l0_7:",
            "r6 = *(u32*)(r2 + 8);",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "if r6 == 0 goto l1_7;",
            "exit;",
            "l1_7:",
            "if r0 == 0 goto l2_7;",
            "r1 = r0;",
            "call 86;",
            "l2_7:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_free_in_both_subbranches
extern "C" fn check_free_in_both_subbranches() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 16;",
            "if r0 <= r3 goto l0_8;",
            "exit;",
            "l0_8:",
            "r6 = *(u32*)(r2 + 8);",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "if r6 == 0 goto l1_8;",
            "if r0 == 0 goto l2_8;",
            "r1 = r0;",
            "call 86;",
            "l2_8:",
            "exit;",
            "l1_8:",
            "if r0 == 0 goto l3_8;",
            "r1 = r0;",
            "call 86;",
            "l3_8:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: call_free_reference_in_subprog
extern "C" fn call_free_reference_in_subprog() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "call {call_free_reference_in_subprog__1};",
            "r0 = 0;",
            "exit;",
            call_free_reference_in_subprog__1 = sym call_free_reference_in_subprog__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: call_free_reference_in_subprog__1
extern "C" fn call_free_reference_in_subprog__1() {
    unsafe {
        core::arch::asm!(
            "r2 = r1;",
            "if r2 == 0 goto l0_9;",
            "call 86;",
            "l0_9:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reference_in_subprog_and_outside
extern "C" fn reference_in_subprog_and_outside() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "r6 = r0;",
            "call {reference_in_subprog_and_outside__1};",
            "r1 = r6;",
            "call 86;",
            "exit;",
            reference_in_subprog_and_outside__1 = sym reference_in_subprog_and_outside__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: reference_in_subprog_and_outside__1
extern "C" fn reference_in_subprog_and_outside__1() {
    unsafe {
        core::arch::asm!(
            "r2 = r1;",
            "if r2 == 0 goto l0_10;",
            "call 86;",
            "l0_10:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: alloc_leak_reference_in_subprog
extern "C" fn alloc_leak_reference_in_subprog() {
    unsafe {
        core::arch::asm!(
            "r4 = r10;",
            "r4 += -8;",
            "call {alloc_leak_reference_in_subprog__1};",
            "r1 = r0;",
            "r0 = 0;",
            "exit;",
            alloc_leak_reference_in_subprog__1 = sym alloc_leak_reference_in_subprog__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: alloc_leak_reference_in_subprog__1
extern "C" fn alloc_leak_reference_in_subprog__1() {
    unsafe {
        core::arch::asm!(
            "r6 = r4;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "*(u64*)(r6 + 0) = r0;",
            "r1 = r0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: alloc_in_subprog_release_outside
extern "C" fn alloc_in_subprog_release_outside() {
    unsafe {
        core::arch::asm!(
            "r4 = r10;",
            "call {alloc_in_subprog_release_outside__1};",
            "r1 = r0;",
            "if r0 == 0 goto l0_11;",
            "call 86;",
            "l0_11:",
            "exit;",
            alloc_in_subprog_release_outside__1 = sym alloc_in_subprog_release_outside__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: alloc_in_subprog_release_outside__1
extern "C" fn alloc_in_subprog_release_outside__1() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_leak_into_caller_stack
extern "C" fn ptr_leak_into_caller_stack() {
    unsafe {
        core::arch::asm!(
            "r4 = r10;",
            "r4 += -8;",
            "call {ptr_leak_into_caller_stack__1};",
            "r0 = 0;",
            "exit;",
            ptr_leak_into_caller_stack__1 = sym ptr_leak_into_caller_stack__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_leak_into_caller_stack__1
extern "C" fn ptr_leak_into_caller_stack__1() {
    unsafe {
        core::arch::asm!(
            "r5 = r10;",
            "r5 += -8;",
            "*(u64*)(r5 + 0) = r4;",
            "call {ptr_leak_into_caller_stack__2};",
            "r5 = r10;",
            "r5 += -8;",
            "r4 = *(u64*)(r5 + 0);",
            "*(u64*)(r4 + 0) = r0;",
            "exit;",
            ptr_leak_into_caller_stack__2 = sym ptr_leak_into_caller_stack__2,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_leak_into_caller_stack__2
extern "C" fn ptr_leak_into_caller_stack__2() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_spill_into_caller_stack
extern "C" fn ptr_spill_into_caller_stack() {
    unsafe {
        core::arch::asm!(
            "r4 = r10;",
            "r4 += -8;",
            "call {ptr_spill_into_caller_stack__1};",
            "r0 = 0;",
            "exit;",
            ptr_spill_into_caller_stack__1 = sym ptr_spill_into_caller_stack__1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_spill_into_caller_stack__1
extern "C" fn ptr_spill_into_caller_stack__1() {
    unsafe {
        core::arch::asm!(
            "r5 = r10;",
            "r5 += -8;",
            "*(u64*)(r5 + 0) = r4;",
            "call {ptr_spill_into_caller_stack__2};",
            "r5 = r10;",
            "r5 += -8;",
            "r4 = *(u64*)(r5 + 0);",
            "*(u64*)(r4 + 0) = r0;",
            "if r0 == 0 goto l0_12;",
            "r1 = *(u64*)(r4 + 0);",
            "call 86;",
            "l0_12:",
            "exit;",
            ptr_spill_into_caller_stack__2 = sym ptr_spill_into_caller_stack__2,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_spill_into_caller_stack__2
extern "C" fn ptr_spill_into_caller_stack__2() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reference_tracking_allow_ld_abs
extern "C" fn reference_tracking_allow_ld_abs() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "if r0 == 0 goto l0_13;",
            "call 86;",
            "l0_13:",
            "r0 = *(u8*)skb[0];",
            "r0 = *(u16*)skb[0];",
            "r0 = *(u32*)skb[0];",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_abs_while_holding_reference
extern "C" fn ld_abs_while_holding_reference() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r0 = *(u8*)skb[0];",
            "r0 = *(u16*)skb[0];",
            "r0 = *(u32*)skb[0];",
            "r1 = r0;",
            "if r0 == 0 goto l0_14;",
            "call 86;",
            "l0_14:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reference_tracking_allow_ld_ind
extern "C" fn reference_tracking_allow_ld_ind() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "if r0 == 0 goto l0_15;",
            "call 86;",
            "l0_15:",
            "r7 = 1;",
            ".8byte -9007199254712256;",
            "r0 = r7;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ld_ind_while_holding_reference
extern "C" fn ld_ind_while_holding_reference() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r4 = r0;",
            "r7 = 1;",
            ".8byte -9007199254712256;",
            "r0 = r7;",
            "r1 = r4;",
            "if r1 == 0 goto l0_16;",
            "call 86;",
            "l0_16:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: check_reference_or_tail_call
extern "C" fn check_reference_or_tail_call() {
    unsafe {
        core::arch::asm!(
            "r7 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "if r1 != 0 goto l0_17;",
            "r3 = 3;",
            "r2 = {map_prog1_tc} ll;",
            "r1 = r7;",
            "call 12;",
            "r0 = 0;",
            "exit;",
            "l0_17:",
            "call 86;",
            "exit;",
            map_prog1_tc = sym map_prog1_tc,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: release_reference_then_tail_call
extern "C" fn release_reference_then_tail_call() {
    unsafe {
        core::arch::asm!(
            "r7 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "if r1 == 0 goto l0_18;",
            "call 86;",
            "l0_18:",
            "r3 = 3;",
            "r2 = {map_prog1_tc} ll;",
            "r1 = r7;",
            "call 12;",
            "r0 = 0;",
            "exit;",
            map_prog1_tc = sym map_prog1_tc,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: possible_reference_over_tail_call
extern "C" fn possible_reference_over_tail_call() {
    unsafe {
        core::arch::asm!(
            "r7 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r6 = r0;",
            "r3 = 3;",
            "r2 = {map_prog1_tc} ll;",
            "r1 = r7;",
            "call 12;",
            "r0 = 0;",
            "r1 = r6;",
            "if r1 == 0 goto l0_19;",
            "call 86;",
            "l0_19:",
            "exit;",
            map_prog1_tc = sym map_prog1_tc,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: checked_reference_over_tail_call
extern "C" fn checked_reference_over_tail_call() {
    unsafe {
        core::arch::asm!(
            "r7 = r1;",
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r6 = r0;",
            "if r0 == 0 goto l0_20;",
            "r3 = 0;",
            "r2 = {map_prog1_tc} ll;",
            "r1 = r7;",
            "call 12;",
            "r0 = 0;",
            "r1 = r6;",
            "l0_20:",
            "call 86;",
            "exit;",
            map_prog1_tc = sym map_prog1_tc,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: and_release_sock_or_null
extern "C" fn and_release_sock_or_null() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "r1 += 5;",
            "if r0 == 0 goto l0_21;",
            "call 86;",
            "l0_21:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tracking_mangle_and_release_sock
extern "C" fn tracking_mangle_and_release_sock() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "if r0 == 0 goto l0_22;",
            "r1 += 5;",
            "call 86;",
            "l0_22:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reference_tracking_access_member
extern "C" fn reference_tracking_access_member() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r6 = r0;",
            "if r0 == 0 goto l0_23;",
            "r2 = *(u32*)(r0 + 4);",
            "r1 = r6;",
            "call 86;",
            "l0_23:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reference_tracking_write_to_member
extern "C" fn reference_tracking_write_to_member() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r6 = r0;",
            "if r0 == 0 goto l0_24;",
            "r1 = r6;",
            "r2 = 42 ll;",
            "*(u32*)(r1 + 16) = r2;",
            "r1 = r6;",
            "l0_24:",
            "call 86;",
            "r0 = 0 ll;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: _64_bit_access_of_member
extern "C" fn _64_bit_access_of_member() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r6 = r0;",
            "if r0 == 0 goto l0_25;",
            "r2 = *(u64*)(r0 + 0);",
            "r1 = r6;",
            "call 86;",
            "l0_25:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reference_tracking_access_after_release
extern "C" fn reference_tracking_access_after_release() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r1 = r0;",
            "if r0 == 0 goto l0_26;",
            "call 86;",
            "r2 = *(u32*)(r1 + 0);",
            "l0_26:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tracking_direct_access_for_lookup
extern "C" fn tracking_direct_access_for_lookup() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r2;",
            "r0 += 64;",
            "if r0 > r3 goto l0_27;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r6 = r0;",
            "if r0 == 0 goto l0_27;",
            "r2 = *(u32*)(r0 + 4);",
            "r1 = r6;",
            "call 86;",
            "l0_27:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_tcp_sock_after_release
extern "C" fn bpf_tcp_sock_after_release() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "if r0 != 0 goto l0_28;",
            "exit;",
            "l0_28:",
            "r6 = r0;",
            "r1 = r0;",
            "call 96;",
            "if r0 != 0 goto l1_28;",
            "r1 = r6;",
            "call 86;",
            "exit;",
            "l1_28:",
            "r7 = r0;",
            "r1 = r6;",
            "call 86;",
            "r0 = *(u32*)(r7 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_sk_fullsock_after_release
extern "C" fn bpf_sk_fullsock_after_release() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "if r0 != 0 goto l0_29;",
            "exit;",
            "l0_29:",
            "r6 = r0;",
            "r1 = r0;",
            "call 95;",
            "if r0 != 0 goto l1_29;",
            "r1 = r6;",
            "call 86;",
            "exit;",
            "l1_29:",
            "r7 = r0;",
            "r1 = r6;",
            "call 86;",
            "r0 = *(u32*)(r7 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_fullsock_tp_after_release
extern "C" fn sk_fullsock_tp_after_release() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "if r0 != 0 goto l0_30;",
            "exit;",
            "l0_30:",
            "r6 = r0;",
            "r1 = r0;",
            "call 96;",
            "if r0 != 0 goto l1_30;",
            "r1 = r6;",
            "call 86;",
            "exit;",
            "l1_30:",
            "r1 = r0;",
            "call 95;",
            "r1 = r6;",
            "r6 = r0;",
            "call 86;",
            "if r6 != 0 goto l2_30;",
            "exit;",
            "l2_30:",
            "r0 = *(u32*)(r6 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: after_bpf_sk_release_tp
extern "C" fn after_bpf_sk_release_tp() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "if r0 != 0 goto l0_31;",
            "exit;",
            "l0_31:",
            "r6 = r0;",
            "r1 = r0;",
            "call 96;",
            "if r0 != 0 goto l1_31;",
            "r1 = r6;",
            "call 86;",
            "exit;",
            "l1_31:",
            "r1 = r0;",
            "call 86;",
            "r0 = *(u32*)(r6 + 8);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: after_bpf_sk_release_sk
extern "C" fn after_bpf_sk_release_sk() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "if r0 != 0 goto l0_32;",
            "exit;",
            "l0_32:",
            "r6 = r0;",
            "r1 = r0;",
            "call 98;",
            "if r0 != 0 goto l1_32;",
            "r1 = r6;",
            "call 86;",
            "exit;",
            "l1_32:",
            "r1 = r6;",
            "r6 = r0;",
            "call 86;",
            "r0 = *(u32*)(r6 + 44);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_sk_release_listen_sk
extern "C" fn bpf_sk_release_listen_sk() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "if r0 != 0 goto l0_33;",
            "exit;",
            "l0_33:",
            "r6 = r0;",
            "r1 = r0;",
            "call 98;",
            "if r0 != 0 goto l1_33;",
            "r1 = r6;",
            "call 86;",
            "exit;",
            "l1_33:",
            "r1 = r0;",
            "call 86;",
            "r0 = *(u32*)(r6 + 8);",
            "r1 = r6;",
            "call 86;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: and_bpf_tcp_sock_sk
extern "C" fn and_bpf_tcp_sock_sk() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "if r0 != 0 goto l0_34;",
            "exit;",
            "l0_34:",
            "r6 = r0;",
            "r1 = r0;",
            "call 95;",
            "r7 = r0;",
            "r1 = r6;",
            "call 96;",
            "r8 = r0;",
            "if r7 != 0 goto l1_34;",
            "r1 = r6;",
            "call 86;",
            "exit;",
            "l1_34:",
            "r0 = *(u32*)(r8 + 0);",
            "r1 = r6;",
            "call 86;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tracking_valid_pointer_null_comparison
extern "C" fn tracking_valid_pointer_null_comparison() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r6 = r0;",
            "r3 = 1;",
            "if r6 != 0 goto l0_35;",
            "r3 = 0;",
            "l0_35:",
            "if r6 == 0 goto l1_35;",
            "r1 = r6;",
            "call 86;",
            "l1_35:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: tracking_valid_pointer_value_comparison
extern "C" fn tracking_valid_pointer_value_comparison() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "r6 = r0;",
            "r3 = 1;",
            "if r6 == 0 goto l0_36;",
            "r3 = 0;",
            "if r6 == 1234 goto l0_36;",
            "r1 = r6;",
            "call 86;",
            "l0_36:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_release_btf_tcp_sock
extern "C" fn sk_release_btf_tcp_sock() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "if r0 != 0 goto l0_37;",
            "exit;",
            "l0_37:",
            "r6 = r0;",
            "r1 = r0;",
            "call 137;",
            "if r0 != 0 goto l1_37;",
            "r1 = r6;",
            "call 86;",
            "exit;",
            "l1_37:",
            "r1 = r0;",
            "call 86;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_tcp_sock_after_release
extern "C" fn to_tcp_sock_after_release() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u32*)(r10 - 8) = r2;",
            "*(u64*)(r10 - 16) = r2;",
            "*(u64*)(r10 - 24) = r2;",
            "*(u64*)(r10 - 32) = r2;",
            "*(u64*)(r10 - 40) = r2;",
            "*(u64*)(r10 - 48) = r2;",
            "r2 = r10;",
            "r2 += -48;",
            "r3 = 36;",
            "r4 = 0;",
            "r5 = 0;",
            "call 84;",
            "if r0 != 0 goto l0_38;",
            "exit;",
            "l0_38:",
            "r6 = r0;",
            "r1 = r0;",
            "call 137;",
            "if r0 != 0 goto l1_38;",
            "r1 = r6;",
            "call 86;",
            "exit;",
            "l1_38:",
            "r7 = r0;",
            "r1 = r6;",
            "call 86;",
            "r0 = *(u8*)(r7 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: to_leak_released_ptr_reg
extern "C" fn to_leak_released_ptr_reg() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u32*)(r10 - 4) = r0;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_array_48b} ll;",
            "call 1;",
            "if r0 != 0 goto l0_39;",
            "exit;",
            "l0_39:",
            "r9 = r0;",
            "r0 = 0;",
            "r1 = {map_ringbuf} ll;",
            "r2 = 8;",
            "r3 = 0;",
            "call 131;",
            "if r0 != 0 goto l1_39;",
            "exit;",
            "l1_39:",
            "r8 = r0;",
            "r1 = r8;",
            "r2 = 0;",
            "call 133;",
            "r0 = 0;",
            "*(u64*)(r9 + 0) = r8;",
            "exit;",
            map_array_48b = sym map_array_48b,
            map_ringbuf = sym map_ringbuf,
            options(nostack)
        );
    }
}

bpf_object!("GPL");
