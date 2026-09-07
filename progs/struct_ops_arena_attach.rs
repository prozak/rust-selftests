#![no_std]
#![no_main]

#[no_mangle]
#[link_section = "fentry"]
extern "C" fn fentry_test_arena(_arg0: *const u64) -> i32 { 0 }

#[no_mangle]
#[link_section = "fexit"]
extern "C" fn fexit_test_arena(_arg1: *const u64) -> i32 { 0 }

#[no_mangle]
#[link_section = "freplace"]
extern "C" fn freplace_test_arena(_arg2: *const u64) -> i32 { 0 }

bpf_rs_core::bpf_object!("GPL");
