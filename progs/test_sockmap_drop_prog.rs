#![no_std]
#![no_main]

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::{bpf_map, bpf_object};

const SK_DROP: i32 = 0;

bpf_map! {
    sock_map_rx {
        r#type: *const [i32; 15], // BPF_MAP_TYPE_SOCKMAP
        max_entries: *const [i32; 20],
        key: *const i32,
        value: *const i32,
    }
}

bpf_map! {
    sock_map_tx {
        r#type: *const [i32; 15], // BPF_MAP_TYPE_SOCKMAP
        max_entries: *const [i32; 20],
        key: *const i32,
        value: *const i32,
    }
}

bpf_map! {
    sock_map_msg {
        r#type: *const [i32; 15], // BPF_MAP_TYPE_SOCKMAP
        max_entries: *const [i32; 20],
        key: *const i32,
        value: *const i32,
    }
}

#[link_section = "sk_skb"]
#[no_mangle]
extern "C" fn prog_skb_verdict(_skb: *const __sk_buff) -> i32 {
    SK_DROP
}

bpf_object!("GPL");
