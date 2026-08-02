#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/uptr_map_failure.c,
// bpf-rs-core idiom.
//
// No programs, only three BPF_MAP_TYPE_TASK_STORAGE map defs whose value
// types carry a `struct X __uptr *field` member (uptr_test_common.h). The
// userspace test (task_local_storage.c: test_uptr_map_failure) never loads
// this object's programs — it opens the skeleton, then hand-creates each map
// via a raw bpf_map_create() using the object's own BTF, and asserts the
// *map creation* fails with a specific errno (E2BIG / EINVAL / EINVAL).
//
// __uptr is `__attribute__((btf_type_tag("uptr")))` (bpf_helpers.h). The
// kernel only classifies a struct member as a BPF_UPTR special field by
// walking BTF_KIND_TYPE_TAG modifiers on the pointer (kernel/bpf/btf.c
// btf_find_kptr's kptr_type_tags table); the size/zero/kernel-struct checks
// that produce E2BIG/EINVAL (btf_check_and_fixup_fields) only run for fields
// classified that way. rustc has no attribute or mechanism to emit
// BTF_KIND_TYPE_TAG (that's Clang-specific IR metadata consumed by LLVM's
// BPF BTF-generation pass; there is no Rust-source equivalent, and
// btf-macros only emits field byte_offset/field_exists CO-RE relocations,
// not type tags). So every pointer field below reaches the kernel as a
// plain, untagged pointer: btf_find_kptr's type-tag walk yields no match,
// BTF_FIELD_IGNORE is returned, and none of the three maps' value BTF is
// ever recognized as containing a uptr field — map creation is expected to
// *succeed* instead of failing with the asserted errno. This makes the test
// unfixably behaviorally divergent; kept for structural/BTF-shape fidelity.

use bpf_rs_core::{bpf_map, bpf_object};

const TASK_STORAGE: usize = 29; // enum bpf_map_type
const NO_PREALLOC: usize = 1; // BPF_F_NO_PREALLOC
const PAGE_SIZE: usize = 4096;

#[repr(C)]
struct large_data {
    one_page: [u8; PAGE_SIZE],
    a: i32,
}

#[repr(C)]
struct large_uptr {
    udata: *mut large_data,
}

#[repr(C)]
struct empty_data {
    _unused: [u8; 0],
}

#[repr(C)]
struct empty_uptr {
    udata: *mut empty_data,
}

#[repr(C)]
struct cgroup {
    _unused: [u8; 0],
}

#[repr(C)]
struct kstruct_uptr {
    cgrp: *mut cgroup,
}

bpf_map! {
    large_uptr_map {
        r#type: *const [i32; TASK_STORAGE],
        map_flags: *const [i32; NO_PREALLOC],
        key: *const i32,
        value: *const large_uptr,
    }
}

bpf_map! {
    empty_uptr_map {
        r#type: *const [i32; TASK_STORAGE],
        map_flags: *const [i32; NO_PREALLOC],
        key: *const i32,
        value: *const empty_uptr,
    }
}

bpf_map! {
    kstruct_uptr_map {
        r#type: *const [i32; TASK_STORAGE],
        map_flags: *const [i32; NO_PREALLOC],
        key: *const i32,
        value: *const kstruct_uptr,
    }
}

bpf_object!("GPL");
