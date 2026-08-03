#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/htab_reuse.c
// (bpf-rs-core idiom). No BPF programs: the C source only defines two
// HASH maps used purely from userspace (prog_tests/htab_reuse.c) to
// exercise BPF_F_LOCK update/lookup/delete races.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;

// enum bpf_map_type: BPF_MAP_TYPE_HASH.
const BPF_MAP_TYPE_HASH: usize = 1;
// enum: BPF_F_NO_PREALLOC.
const BPF_F_NO_PREALLOC: usize = 1;

// struct bpf_spin_lock { __u32 val; };  -- matched by BTF struct name.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct htab_val {
    lock: bpf_spin_lock,
    data: u32,
}

const HTAB_NDATA: usize = 256;

#[allow(non_camel_case_types)]
#[repr(C)]
struct htab_val_large {
    lock: bpf_spin_lock,
    seq: u32,
    data: [u64; HTAB_NDATA],
}

bpf_map! {
    htab {
        r#type: *const [i32; BPF_MAP_TYPE_HASH],
        max_entries: *const [i32; 64],
        map_flags: *const [i32; BPF_F_NO_PREALLOC],
        key: *const u32,
        value: *const htab_val,
    }
}

bpf_map! {
    htab_lock_consistency {
        r#type: *const [i32; BPF_MAP_TYPE_HASH],
        max_entries: *const [i32; 8],
        map_flags: *const [i32; BPF_F_NO_PREALLOC],
        key: *const u32,
        value: *const htab_val_large,
    }
}

bpf_object!("GPL");
