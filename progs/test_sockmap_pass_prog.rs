#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_sk_redirect_map;
use bpf_rs_core::maps::BpfMap;
use bpf_rs_core::vload;

const BPF_MAP_TYPE_SOCKMAP: usize = 15;
const BPF_F_INGRESS: u64 = 1;

#[link_section = ".maps"]
#[no_mangle]
static sock_map_rx: BpfMap<i32, i32, BPF_MAP_TYPE_SOCKMAP, 20> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static sock_map_tx: BpfMap<i32, i32, BPF_MAP_TYPE_SOCKMAP, 20> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static sock_map_msg: BpfMap<i32, i32, BPF_MAP_TYPE_SOCKMAP, 20> = BpfMap::new();

#[link_section = "sk_skb/stream_verdict"]
#[no_mangle]
extern "C" fn prog_skb_verdict(_skb: *const __sk_buff) -> i32 {
    1 // SK_PASS
}

#[no_mangle]
static mut clone_called: i32 = 0;

#[link_section = "sk_skb/stream_verdict"]
#[no_mangle]
extern "C" fn prog_skb_verdict_clone(_skb: *const __sk_buff) -> i32 {
    unsafe { clone_called = 1 };
    1 // SK_PASS
}

#[link_section = "sk_skb/stream_parser"]
#[no_mangle]
extern "C" fn prog_skb_parser(_skb: *const __sk_buff) -> i32 {
    1 // SK_PASS
}

#[link_section = "sk_skb/stream_verdict"]
#[no_mangle]
extern "C" fn prog_skb_verdict_ingress(skb: *const __sk_buff) -> i32 {
    let one: u32 = 1;
    bpf_sk_redirect_map(skb as *const _, &sock_map_rx, one, BPF_F_INGRESS) as i32
}

#[link_section = "sk_skb/stream_parser"]
#[no_mangle]
extern "C" fn prog_skb_verdict_ingress_strp(skb: *const __sk_buff) -> i32 {
    vload!((*skb).len) as i32
}

bpf_object!("GPL");
