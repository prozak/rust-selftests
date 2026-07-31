#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/fentry_test.c
// (bpf-next 520d7d79) to Rust, compiled straight to BPF by upstream
// rustc/LLVM — no aya, no bpf-linker.
//
// An fentry program's ctx is an array of u64 slots, one per argument of
// the attach target; the verifier types each ctx[i] load from the
// target's BTF proto. arg_i::<T>(ctx, i) mirrors C's BPF_PROG macro:
// read slot i, truncate to the target arg's type.

#[inline(always)]
fn arg(ctx: *const u64, i: usize) -> u64 {
    unsafe { *ctx.add(i) }
}

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

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32;
    unsafe { test1_result = (a == 1) as u64 };
    0
}

#[link_section = "fentry/bpf_fentry_test2"]
#[no_mangle]
extern "C" fn test2(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i32;
    let b = arg(ctx, 1);
    unsafe { test2_result = (a == 2 && b == 3) as u64 };
    0
}

#[link_section = "fentry/bpf_fentry_test3"]
#[no_mangle]
extern "C" fn test3(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0) as i8;
    let b = arg(ctx, 1) as i32;
    let c = arg(ctx, 2);
    unsafe { test3_result = (a == 4 && b == 5 && c == 6) as u64 };
    0
}

#[link_section = "fentry/bpf_fentry_test4"]
#[no_mangle]
extern "C" fn test4(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0); // void *
    let b = arg(ctx, 1) as i8;
    let c = arg(ctx, 2) as i32;
    let d = arg(ctx, 3);
    unsafe { test4_result = (a == 7 && b == 8 && c == 9 && d == 10) as u64 };
    0
}

#[link_section = "fentry/bpf_fentry_test5"]
#[no_mangle]
extern "C" fn test5(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0);
    let b = arg(ctx, 1); // void *
    let c = arg(ctx, 2) as i16;
    let d = arg(ctx, 3) as i32;
    let e = arg(ctx, 4);
    unsafe {
        test5_result = (a == 11 && b == 12 && c == 13 && d == 14 && e == 15) as u64;
    }
    0
}

#[link_section = "fentry/bpf_fentry_test6"]
#[no_mangle]
extern "C" fn test6(ctx: *const u64) -> i32 {
    let a = arg(ctx, 0);
    let b = arg(ctx, 1); // void *
    let c = arg(ctx, 2) as i16;
    let d = arg(ctx, 3) as i32;
    let e = arg(ctx, 4); // void *
    let f = arg(ctx, 5);
    unsafe {
        test6_result =
            (a == 16 && b == 17 && c == 18 && d == 19 && e == 20 && f == 21) as u64;
    }
    0
}

// struct bpf_fentry_test_t { struct bpf_fentry_test_t *a; };
// ctx[0] is PTR_TO_BTF_ID(bpf_fentry_test_t); the ->a load below is a
// BTF-typed load at offset 0 that the verifier converts to PROBE_MEM.

#[link_section = "fentry/bpf_fentry_test7"]
#[no_mangle]
extern "C" fn test7(ctx: *const u64) -> i32 {
    let arg7 = arg(ctx, 0) as *const u64;
    if arg7.is_null() {
        unsafe { test7_result = 1 };
    }
    0
}

#[link_section = "fentry/bpf_fentry_test8"]
#[no_mangle]
extern "C" fn test8(ctx: *const u64) -> i32 {
    let arg8 = arg(ctx, 0) as *const u64;
    let a = unsafe { *arg8 }; // arg->a
    if a == 0 {
        unsafe { test8_result = 1 };
    }
    0
}

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
