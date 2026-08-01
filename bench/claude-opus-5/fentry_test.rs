#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/fentry_test.c.
//
// Each program is a C BPF_PROG(...) over one of the kernel's
// bpf_fentry_testN() helpers: the fentry ctx is an array of u64 slots, one
// per target-function argument, and BPF_PROG casts slot i down to the
// target argument's C type. The casts below reproduce that truncation
// exactly (int -> i32, char -> i8, short -> i16, void * / __u64 -> u64).
//
// prog_tests/fentry_test.c and prog_tests/fentry_fexit.c walk the whole
// .bss as an array of __u64 and assert every slot is 1, so .bss must hold
// exactly these eight results and nothing else.

#[no_mangle]
static mut test1_result: u64 = 0;

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(ctx: *const u64) -> i32 {
    let a = unsafe { *ctx.add(0) } as i32;
    unsafe { test1_result = (a == 1) as u64 };
    0
}

#[no_mangle]
static mut test2_result: u64 = 0;

#[link_section = "fentry/bpf_fentry_test2"]
#[no_mangle]
extern "C" fn test2(ctx: *const u64) -> i32 {
    let a = unsafe { *ctx.add(0) } as i32;
    let b = unsafe { *ctx.add(1) };
    unsafe { test2_result = (a == 2 && b == 3) as u64 };
    0
}

#[no_mangle]
static mut test3_result: u64 = 0;

#[link_section = "fentry/bpf_fentry_test3"]
#[no_mangle]
extern "C" fn test3(ctx: *const u64) -> i32 {
    let a = unsafe { *ctx.add(0) } as i8;
    let b = unsafe { *ctx.add(1) } as i32;
    let c = unsafe { *ctx.add(2) };
    unsafe { test3_result = (a == 4 && b == 5 && c == 6) as u64 };
    0
}

#[no_mangle]
static mut test4_result: u64 = 0;

#[link_section = "fentry/bpf_fentry_test4"]
#[no_mangle]
extern "C" fn test4(ctx: *const u64) -> i32 {
    let a = unsafe { *ctx.add(0) };
    let b = unsafe { *ctx.add(1) } as i8;
    let c = unsafe { *ctx.add(2) } as i32;
    let d = unsafe { *ctx.add(3) };
    unsafe { test4_result = (a == 7 && b == 8 && c == 9 && d == 10) as u64 };
    0
}

#[no_mangle]
static mut test5_result: u64 = 0;

#[link_section = "fentry/bpf_fentry_test5"]
#[no_mangle]
extern "C" fn test5(ctx: *const u64) -> i32 {
    let a = unsafe { *ctx.add(0) };
    let b = unsafe { *ctx.add(1) };
    let c = unsafe { *ctx.add(2) } as i16;
    let d = unsafe { *ctx.add(3) } as i32;
    let e = unsafe { *ctx.add(4) };
    unsafe { test5_result = (a == 11 && b == 12 && c == 13 && d == 14 && e == 15) as u64 };
    0
}

#[no_mangle]
static mut test6_result: u64 = 0;

#[link_section = "fentry/bpf_fentry_test6"]
#[no_mangle]
extern "C" fn test6(ctx: *const u64) -> i32 {
    let a = unsafe { *ctx.add(0) };
    let b = unsafe { *ctx.add(1) };
    let c = unsafe { *ctx.add(2) } as i16;
    let d = unsafe { *ctx.add(3) } as i32;
    let e = unsafe { *ctx.add(4) };
    let f = unsafe { *ctx.add(5) };
    unsafe {
        test6_result = (a == 16 && b == 17 && c == 18 && d == 19 && e == 20 && f == 21) as u64
    };
    0
}

#[no_mangle]
static mut test7_result: u64 = 0;

#[link_section = "fentry/bpf_fentry_test7"]
#[no_mangle]
extern "C" fn test7(ctx: *const u64) -> i32 {
    // struct bpf_fentry_test_t *arg — the kernel passes NULL here.
    let arg = unsafe { *ctx.add(0) };
    if arg == 0 {
        unsafe { test7_result = 1 };
    }
    0
}

#[no_mangle]
static mut test8_result: u64 = 0;

#[link_section = "fentry/bpf_fentry_test8"]
#[no_mangle]
extern "C" fn test8(ctx: *const u64) -> i32 {
    // arg->a is the first (and only) member of struct bpf_fentry_test_t.
    // ctx slot 0 is a PTR_TO_BTF_ID, so the verifier turns this load into a
    // fault-tolerant PROBE_MEM load — no null check, matching the C source.
    let arg = unsafe { *ctx.add(0) } as *const u64;
    if unsafe { *arg } == 0 {
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
