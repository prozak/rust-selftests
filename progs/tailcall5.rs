#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tailcall5.c,
// bpf-rs-core idiom.
//
// jmp_table has explicit key_size/value_size (not key/value types), so it
// needs the bpf_map! escape hatch rather than the BpfMap<K,V,TYPE,MAX>
// generic (matches tailcall3.rs/tailcall4.rs idiom).

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::{bpf_map, bpf_object, maps};

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 3],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[no_mangle]
static mut selector: i32 = 0;

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
    let mut idx: i32 = 0;

    let sel = unsafe { selector };
    if sel == 1234 {
        idx = 1;
    } else if sel == 5678 {
        idx = 2;
    }

    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, idx as u32);
    3
}

bpf_object!("GPL");
