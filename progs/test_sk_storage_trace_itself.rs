#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_sk_storage_trace_itself.c,
// bpf-rs-core idiom.

use bpf_rs_core::helpers::bpf_sk_storage_get;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object};

// enum bpf_map_type: BPF_MAP_TYPE_SK_STORAGE.
const BPF_MAP_TYPE_SK_STORAGE: usize = 24;
// enum: BPF_F_NO_PREALLOC.
const BPF_F_NO_PREALLOC: usize = 1;

bpf_map! {
    sk_stg_map {
        r#type: *const [i32; BPF_MAP_TYPE_SK_STORAGE],
        map_flags: *const [i32; BPF_F_NO_PREALLOC],
        key: *const i32,
        value: *const i32,
    }
}

const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

#[link_section = "fentry/bpf_sk_storage_free"]
#[no_mangle]
extern "C" fn trace_bpf_sk_storage_free(ctx: *const u64) -> i32 {
    let sk = arg(ctx, 0) as *const core::ffi::c_void;

    let value = bpf_sk_storage_get(
        &sk_stg_map,
        sk,
        core::ptr::null(),
        BPF_SK_STORAGE_GET_F_CREATE,
    ) as *mut i32;

    if !value.is_null() {
        unsafe { *value = 1 };
    }

    0
}

bpf_object!("GPL");
