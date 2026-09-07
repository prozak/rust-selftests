#![no_std]
#![no_main]

// The pinned C object was built with LLVM 22 and selects this explicit
// upstream fallback. The aggregate-return implementations require LLVM 23.
#[no_mangle]
#[link_section = "socket"]
extern "C" fn dummy_test() -> i32 { 0 }

bpf_rs_core::test_tags! {
    dummy_test: __description("aggregate_ret_kfunc_arena: needs LLVM 23, dummy test"), __skip("needs LLVM 23"), __success;
}
bpf_rs_core::bpf_object!("GPL");
