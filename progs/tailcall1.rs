#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tailcall1.c
// (bpf-rs-core idiom).
//
// jmp_table has explicit key_size/value_size (not key/value types), so it
// needs the bpf_map! escape hatch rather than the BpfMap<K,V,TYPE,MAX>
// generic (same shape as tailcall_bpf2bpf1.rs / tailcall_poke.rs).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::maps;
use core::ffi::c_void;

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 3],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_0(_skb: *const __sk_buff) -> i32 {
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_1(_skb: *const __sk_buff) -> i32 {
    1
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_2(_skb: *const __sk_buff) -> i32 {
    2
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn entry(skb: *const __sk_buff) -> i32 {
    let ctx = skb as *const c_void;

    bpf_tail_call(ctx, &jmp_table, 0);
    bpf_tail_call(ctx, &jmp_table, 0);
    bpf_tail_call(ctx, &jmp_table, 0);
    bpf_tail_call(ctx, &jmp_table, 0);

    bpf_tail_call(ctx, &jmp_table, 1);
    bpf_tail_call(ctx, &jmp_table, 1);
    bpf_tail_call(ctx, &jmp_table, 1);
    bpf_tail_call(ctx, &jmp_table, 1);

    bpf_tail_call(ctx, &jmp_table, 2);
    bpf_tail_call(ctx, &jmp_table, 2);
    bpf_tail_call(ctx, &jmp_table, 2);
    bpf_tail_call(ctx, &jmp_table, 2);

    3
}

bpf_object!("GPL");
