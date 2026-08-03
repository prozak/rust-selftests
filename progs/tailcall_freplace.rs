#![no_std]
#![no_main]

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::{bpf_map, bpf_object, maps};

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[no_mangle]
static mut count: i32 = 0;

#[link_section = "freplace"]
#[no_mangle]
extern "C" fn entry_freplace(skb: *const __sk_buff) -> i32 {
    unsafe { count += 1 };
    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 0);
    unsafe { count }
}

bpf_object!("GPL");
