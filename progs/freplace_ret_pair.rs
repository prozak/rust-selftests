#![no_std]
#![no_main]

#[no_mangle]
#[link_section = "freplace/agg_ret_target_func"]
extern "C" fn new_agg_ret_target_func() -> u64 { 0 }

bpf_rs_core::bpf_object!("GPL");
