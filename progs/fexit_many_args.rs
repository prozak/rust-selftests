#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/fexit_many_args.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;

#[no_mangle]
static mut test1_result: u64 = 0;
#[no_mangle]
static mut test2_result: u64 = 0;
#[no_mangle]
static mut test3_result: u64 = 0;

#[link_section = "fexit/bpf_testmod_fentry_test7"]
#[no_mangle]
extern "C" fn test1(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0);
    let b = arg(ctx, 1);
    let c = arg(ctx, 2) as i16;
    let d = arg(ctx, 3) as i32;
    let e = arg(ctx, 4);
    let f = arg(ctx, 5) as i8;
    let g = arg(ctx, 6) as i32;
    let ret = arg(ctx, 7) as i32;
    unsafe {
        test1_result = (a == 16
            && b == 17
            && c == 18
            && d == 19
            && e == 20
            && f == 21
            && g == 22
            && ret == 133) as u64;
    }
    0
}

#[link_section = "fexit/bpf_testmod_fentry_test11"]
#[no_mangle]
extern "C" fn test2(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0);
    let b = arg(ctx, 1);
    let c = arg(ctx, 2) as i16;
    let d = arg(ctx, 3) as i32;
    let e = arg(ctx, 4);
    let f = arg(ctx, 5) as i8;
    let g = arg(ctx, 6) as i32;
    let h = arg(ctx, 7) as u32;
    let i = arg(ctx, 8) as i64;
    let j = arg(ctx, 9);
    let k = arg(ctx, 10);
    let ret = arg(ctx, 11) as i32;
    unsafe {
        test2_result = (a == 16
            && b == 17
            && c == 18
            && d == 19
            && e == 20
            && f == 21
            && g == 22
            && h == 23
            && i == 24
            && j == 25
            && k == 26
            && ret == 231) as u64;
    }
    0
}

#[link_section = "fexit/bpf_testmod_fentry_test11"]
#[no_mangle]
extern "C" fn test3(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0);
    let b = arg(ctx, 1);
    let c = arg(ctx, 2);
    let d = arg(ctx, 3);
    let e = arg(ctx, 4);
    let f = arg(ctx, 5);
    let g = arg(ctx, 6);
    let h = arg(ctx, 7);
    let i = arg(ctx, 8);
    let j = arg(ctx, 9);
    let k = arg(ctx, 10);
    let ret = arg(ctx, 11);
    unsafe {
        test3_result = (a == 16
            && b == 17
            && c == 18
            && d == 19
            && e == 20
            && f == 21
            && g == 22
            && h == 23
            && i == 24
            && j == 25
            && k == 26
            && ret == 231) as u64;
    }
    0
}

bpf_object!("GPL");
