// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_cgroup_storage.c, GENERATED
// by scripts/naked_gen.py (bpf-rs-core idiom): every function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_cgroup_storage` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: valid_cgroup_storage_access invalid_cgroup_storage_access_1 invalid_cgroup_storage_access_2 invalid_cgroup_storage_access_3 invalid_cgroup_storage_access_4 invalid_cgroup_storage_access_5 invalid_cgroup_storage_access_6 per_cpu_cgroup_storage_access cpu_cgroup_storage_access_1 cpu_cgroup_storage_access_2 cpu_cgroup_storage_access_3 cpu_cgroup_storage_access_4 cpu_cgroup_storage_access_5 cpu_cgroup_storage_access_6 non_zero_flags_on_a_pruned_path

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

test_tags! {
    valid_cgroup_storage_access:
        __description("valid cgroup storage access"),
        __success,
        __success_unpriv,
        __retval("0");
    invalid_cgroup_storage_access_1:
        __description("invalid cgroup storage access 1"),
        __failure,
        __msg("cannot pass map_type 1 into func bpf_get_local_storage"),
        __failure_unpriv;
    invalid_cgroup_storage_access_2:
        __description("invalid cgroup storage access 2"),
        __failure,
        __msg("fd 1 is not pointing to valid bpf_map"),
        __failure_unpriv;
    invalid_cgroup_storage_access_3:
        __description("invalid cgroup storage access 3"),
        __failure,
        __msg("invalid access to map value, value_size=64 off=256 size=4"),
        __failure_unpriv;
    invalid_cgroup_storage_access_4:
        __description("invalid cgroup storage access 4"),
        __failure,
        __msg("invalid access to map value, value_size=64 off=-2 size=4"),
        __failure_unpriv,
        __flag("BPF_F_ANY_ALIGNMENT");
    invalid_cgroup_storage_access_5:
        __description("invalid cgroup storage access 5"),
        __failure,
        __msg("get_local_storage() doesn't support non-zero flags"),
        __failure_unpriv;
    invalid_cgroup_storage_access_6:
        __description("invalid cgroup storage access 6"),
        __failure,
        __msg("get_local_storage() doesn't support non-zero flags"),
        __msg_unpriv("R2 leaks addr into helper function");
    per_cpu_cgroup_storage_access:
        __description("valid per-cpu cgroup storage access"),
        __success,
        __success_unpriv,
        __retval("0");
    cpu_cgroup_storage_access_1:
        __description("invalid per-cpu cgroup storage access 1"),
        __failure,
        __msg("cannot pass map_type 1 into func bpf_get_local_storage"),
        __failure_unpriv;
    cpu_cgroup_storage_access_2:
        __description("invalid per-cpu cgroup storage access 2"),
        __failure,
        __msg("fd 1 is not pointing to valid bpf_map"),
        __failure_unpriv;
    cpu_cgroup_storage_access_3:
        __description("invalid per-cpu cgroup storage access 3"),
        __failure,
        __msg("invalid access to map value, value_size=64 off=256 size=4"),
        __failure_unpriv;
    cpu_cgroup_storage_access_4:
        __description("invalid per-cpu cgroup storage access 4"),
        __failure,
        __msg("invalid access to map value, value_size=64 off=-2 size=4"),
        __failure_unpriv,
        __flag("BPF_F_ANY_ALIGNMENT");
    cpu_cgroup_storage_access_5:
        __description("invalid per-cpu cgroup storage access 5"),
        __failure,
        __msg("get_local_storage() doesn't support non-zero flags"),
        __failure_unpriv;
    cpu_cgroup_storage_access_6:
        __description("invalid per-cpu cgroup storage access 6"),
        __failure,
        __msg("get_local_storage() doesn't support non-zero flags"),
        __msg_unpriv("R2 leaks addr into helper function");
    non_zero_flags_on_a_pruned_path:
        __failure,
        __flag("BPF_F_TEST_STATE_FREQ"),
        __msg("get_local_storage() doesn't support non-zero flags");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_cgroup_storage_key {
    cgroup_inode_id: u64,
    attach_type: u32,
}

bpf_map! {
    cgroup_storage {
        r#type: *const [i32; 19],
        max_entries: *const [i32; 0],
        key: *const bpf_cgroup_storage_key,
        value: *const [i8; 64],
    }
}

bpf_map! {
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
}

bpf_map! {
    percpu_cgroup_storage {
        r#type: *const [i32; 21],
        max_entries: *const [i32; 0],
        key: *const bpf_cgroup_storage_key,
        value: *const [i8; 64],
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: valid_cgroup_storage_access
extern "C" fn valid_cgroup_storage_access() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "r1 = {cgroup_storage} ll;",
            "call 81;",
            "r1 = *(u32*)(r0 + 0);",
            "r0 = r1;",
            "r0 &= 1;",
            "exit;",
            cgroup_storage = sym cgroup_storage,
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: invalid_cgroup_storage_access_1
extern "C" fn invalid_cgroup_storage_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "r1 = {map_hash_8b} ll;",
            "call 81;",
            "r1 = *(u32*)(r0 + 0);",
            "r0 = r1;",
            "r0 &= 1;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: invalid_cgroup_storage_access_2
extern "C" fn invalid_cgroup_storage_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            ".8byte 4294971672;",
            ".8byte 0;",
            "call 81;",
            "r0 &= 1;",
            "exit;",
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: invalid_cgroup_storage_access_3
extern "C" fn invalid_cgroup_storage_access_3() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "r1 = {cgroup_storage} ll;",
            "call 81;",
            "r1 = *(u32*)(r0 + 256);",
            "r1 += 1;",
            "r0 = 0;",
            "exit;",
            cgroup_storage = sym cgroup_storage,
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: invalid_cgroup_storage_access_4
extern "C" fn invalid_cgroup_storage_access_4() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "r1 = {cgroup_storage} ll;",
            "call 81;",
            "r1 = *(u32*)(r0 - 2);",
            "r0 = r1;",
            "r1 += 1;",
            "exit;",
            cgroup_storage = sym cgroup_storage,
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: invalid_cgroup_storage_access_5
extern "C" fn invalid_cgroup_storage_access_5() {
    unsafe {
        core::arch::asm!(
            "r2 = 7;",
            "r1 = {cgroup_storage} ll;",
            "call 81;",
            "r1 = *(u32*)(r0 + 0);",
            "r0 = r1;",
            "r0 &= 1;",
            "exit;",
            cgroup_storage = sym cgroup_storage,
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: invalid_cgroup_storage_access_6
extern "C" fn invalid_cgroup_storage_access_6() {
    unsafe {
        core::arch::asm!(
            "r2 = r1;",
            "r1 = {cgroup_storage} ll;",
            "call 81;",
            "r1 = *(u32*)(r0 + 0);",
            "r0 = r1;",
            "r0 &= 1;",
            "exit;",
            cgroup_storage = sym cgroup_storage,
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: per_cpu_cgroup_storage_access
extern "C" fn per_cpu_cgroup_storage_access() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "r1 = {percpu_cgroup_storage} ll;",
            "call 81;",
            "r1 = *(u32*)(r0 + 0);",
            "r0 = r1;",
            "r0 &= 1;",
            "exit;",
            percpu_cgroup_storage = sym percpu_cgroup_storage,
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: cpu_cgroup_storage_access_1
extern "C" fn cpu_cgroup_storage_access_1() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "r1 = {map_hash_8b} ll;",
            "call 81;",
            "r1 = *(u32*)(r0 + 0);",
            "r0 = r1;",
            "r0 &= 1;",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: cpu_cgroup_storage_access_2
extern "C" fn cpu_cgroup_storage_access_2() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            ".8byte 4294971672;",
            ".8byte 0;",
            "call 81;",
            "r0 &= 1;",
            "exit;",
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: cpu_cgroup_storage_access_3
extern "C" fn cpu_cgroup_storage_access_3() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "r1 = {percpu_cgroup_storage} ll;",
            "call 81;",
            "r1 = *(u32*)(r0 + 256);",
            "r1 += 1;",
            "r0 = 0;",
            "exit;",
            percpu_cgroup_storage = sym percpu_cgroup_storage,
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: cpu_cgroup_storage_access_4
extern "C" fn cpu_cgroup_storage_access_4() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "r1 = {cgroup_storage} ll;",
            "call 81;",
            "r1 = *(u32*)(r0 - 2);",
            "r0 = r1;",
            "r1 += 1;",
            "exit;",
            cgroup_storage = sym cgroup_storage,
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: cpu_cgroup_storage_access_5
extern "C" fn cpu_cgroup_storage_access_5() {
    unsafe {
        core::arch::asm!(
            "r2 = 7;",
            "r1 = {percpu_cgroup_storage} ll;",
            "call 81;",
            "r1 = *(u32*)(r0 + 0);",
            "r0 = r1;",
            "r0 &= 1;",
            "exit;",
            percpu_cgroup_storage = sym percpu_cgroup_storage,
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: cpu_cgroup_storage_access_6
extern "C" fn cpu_cgroup_storage_access_6() {
    unsafe {
        core::arch::asm!(
            "r2 = r1;",
            "r1 = {percpu_cgroup_storage} ll;",
            "call 81;",
            "r1 = *(u32*)(r0 + 0);",
            "r0 = r1;",
            "r0 &= 1;",
            "exit;",
            percpu_cgroup_storage = sym percpu_cgroup_storage,
            options(noreturn)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
// BPF_NAKED: non_zero_flags_on_a_pruned_path
extern "C" fn non_zero_flags_on_a_pruned_path() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r2 = 1;",
            "if r0 == 0 goto 1f;",
            "r2 = 0;",
            "1: r1 = {cgroup_storage} ll;",
            "call 81;",
            "r0 = 0;",
            "exit;",
            cgroup_storage = sym cgroup_storage,
            options(noreturn)
        );
    }
}

bpf_object!("GPL");
