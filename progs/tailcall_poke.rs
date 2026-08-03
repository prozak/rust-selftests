#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/tailcall_poke.c,
// bpf-rs-core idiom.
//
// jmp_table has explicit key_size/value_size (not key/value types), so it
// needs the bpf_map! escape hatch rather than the BpfMap<K,V,TYPE,MAX>
// generic.

use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object, maps};

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "?fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test(ctx: *const u64) -> i32 {
    let _a = arg(ctx, 0) as i32;
    bpf_tail_call(ctx as *const core::ffi::c_void, &jmp_table, 0);
    0
}

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn call1(ctx: *const u64) -> i32 {
    let _a = arg(ctx, 0) as i32;
    0
}

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn call2(ctx: *const u64) -> i32 {
    let _a = arg(ctx, 0) as i32;
    0
}

bpf_object!("GPL");
