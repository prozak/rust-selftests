#![no_std]
#![no_main]

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::{bpf_map, bpf_object, maps};

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 5],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_0(skb: *const __sk_buff) -> i32 {
    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 1);
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_1(skb: *const __sk_buff) -> i32 {
    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 2);
    1
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_2(_skb: *const __sk_buff) -> i32 {
    2
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_3(skb: *const __sk_buff) -> i32 {
    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 4);
    3
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_4(skb: *const __sk_buff) -> i32 {
    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 3);
    4
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn entry(skb: *const __sk_buff) -> i32 {
    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 0);
    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 2);
    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 3);
    3
}

bpf_object!("GPL");
