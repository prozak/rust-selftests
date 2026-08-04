#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/fexit_test.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;

#[no_mangle]
static mut test1_result: u64 = 0;
#[no_mangle]
static mut test2_result: u64 = 0;
#[no_mangle]
static mut test3_result: u64 = 0;
#[no_mangle]
static mut test4_result: u64 = 0;
#[no_mangle]
static mut test5_result: u64 = 0;
#[no_mangle]
static mut test6_result: u64 = 0;
#[no_mangle]
static mut test7_result: u64 = 0;
#[no_mangle]
static mut test8_result: u64 = 0;

// fexit ctx carries the target function's args followed by one extra slot
// for its return value.

#[link_section = "fexit/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32;
    let ret = arg(ctx, 1) as i32;
    unsafe { test1_result = (a == 1 && ret == 2) as u64 };
    0
}

#[link_section = "fexit/bpf_fentry_test2"]
#[no_mangle]
extern "C" fn test2(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32;
    let b = arg(ctx, 1);
    let ret = arg(ctx, 2) as i32;
    unsafe { test2_result = (a == 2 && b == 3 && ret == 5) as u64 };
    0
}

#[link_section = "fexit/bpf_fentry_test3"]
#[no_mangle]
extern "C" fn test3(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i8;
    let b = arg(ctx, 1) as i32;
    let c = arg(ctx, 2);
    let ret = arg(ctx, 3) as i32;
    unsafe { test3_result = (a == 4 && b == 5 && c == 6 && ret == 15) as u64 };
    0
}

#[link_section = "fexit/bpf_fentry_test4"]
#[no_mangle]
extern "C" fn test4(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0); // void *
    let b = arg(ctx, 1) as i8;
    let c = arg(ctx, 2) as i32;
    let d = arg(ctx, 3);
    let ret = arg(ctx, 4) as i32;
    unsafe {
        test4_result = (a == 7 && b == 8 && c == 9 && d == 10 && ret == 34) as u64;
    }
    0
}

#[link_section = "fexit/bpf_fentry_test5"]
#[no_mangle]
extern "C" fn test5(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0);
    let b = arg(ctx, 1); // void *
    let c = arg(ctx, 2) as i16;
    let d = arg(ctx, 3) as i32;
    let e = arg(ctx, 4);
    let ret = arg(ctx, 5) as i32;
    unsafe {
        test5_result =
            (a == 11 && b == 12 && c == 13 && d == 14 && e == 15 && ret == 65) as u64;
    }
    0
}

#[link_section = "fexit/bpf_fentry_test6"]
#[no_mangle]
extern "C" fn test6(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0);
    let b = arg(ctx, 1); // void *
    let c = arg(ctx, 2) as i16;
    let d = arg(ctx, 3) as i32;
    let e = arg(ctx, 4); // void *
    let f = arg(ctx, 5);
    let ret = arg(ctx, 6) as i32;
    unsafe {
        test6_result = (a == 16
            && b == 17
            && c == 18
            && d == 19
            && e == 20
            && f == 21
            && ret == 111) as u64;
    }
    0
}

// struct bpf_fentry_test_t { struct bpf_fentry_test_t *a; };
// ctx[0] is PTR_TO_BTF_ID(bpf_fentry_test_t); the ->a load below is a
// BTF-typed load at offset 0 that the verifier converts to PROBE_MEM.

#[link_section = "fexit/bpf_fentry_test7"]
#[no_mangle]
extern "C" fn test7(ctx: *const u64) -> i32 {
    let arg7 = arg(ctx, 0) as *const u64;
    if arg7.is_null() {
        unsafe { test7_result = 1 };
    }
    0
}

#[link_section = "fexit/bpf_fentry_test8"]
#[no_mangle]
extern "C" fn test8(ctx: *const u64) -> i32 {
    let arg8 = arg(ctx, 0) as *const u64;
    let a = unsafe { *arg8 }; // arg->a
    if a == 0 {
        unsafe { test8_result = 1 };
    }
    0
}

bpf_object!("GPL");
