#![no_std]
#![no_main]

use bpf_rs_core::progs::fentry_arg as arg;

#[no_mangle]
static mut t_b: i64 = 0;
#[no_mangle]
static mut t_c: i64 = 0;
#[no_mangle]
static mut t_ret: i64 = 0;

#[no_mangle]
#[link_section = "fexit/bpf_testmod_test_int128_arg"]
extern "C" fn test_int128_arg_fexit(ctx: *const u64) -> i32 {
    unsafe {
        t_b = arg(ctx, 2) as i32 as i64;
        t_c = arg(ctx, 3) as i64;
        t_ret = arg(ctx, 4) as i64;
    }
    0
}

bpf_rs_core::bpf_object!("GPL");
