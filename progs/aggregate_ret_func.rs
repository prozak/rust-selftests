#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Raw instruction tests: preserve each register, instruction and return ABI.
#[repr(C)]
struct arena_pair { lo: *mut char, hi: *mut char }
#[repr(C)]
struct arena_and_scalar { p: *mut char, x: u64 }
#[repr(C)]
struct arena_array { p: [*mut char; 2] }
#[repr(C)]
struct arena_single { p: *mut char }
#[repr(C)]
union arena_upair { p: *mut char, halves: [u64; 2] }

#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_agg_good
extern "C" fn global_agg_good() -> u128 {
    unsafe { core::arch::asm!("r0 = 0x1234;r2 = 0x5678;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_agg_bad
extern "C" fn global_agg_bad() -> u128 {
    unsafe { core::arch::asm!("r0 = 0;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_agg_bad_ptr
extern "C" fn global_agg_bad_ptr() -> u128 {
    unsafe { core::arch::asm!("r0 = 0;r2 = r10;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_global_fail
extern "C" fn aggregate_ret_global_fail() -> i32 {
    unsafe { core::arch::asm!("call {global_agg_bad};r0 = r2;exit;", global_agg_bad = sym global_agg_bad, options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_global_ptr_fail
extern "C" fn aggregate_ret_global_ptr_fail() -> i32 {
    unsafe { core::arch::asm!("call {global_agg_bad_ptr};r0 = r2;exit;", global_agg_bad_ptr = sym global_agg_bad_ptr, options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: static_agg_bad_ptr
extern "C" fn static_agg_bad_ptr() -> u128 {
    unsafe { core::arch::asm!("r0 = 0;r2 = r10;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_static_ptr_fail
extern "C" fn aggregate_ret_static_ptr_fail() -> i32 {
    unsafe { core::arch::asm!("call {static_agg_bad_ptr};r0 = 0;exit;", static_agg_bad_ptr = sym static_agg_bad_ptr, options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: static_agg_no_r2
extern "C" fn static_agg_no_r2() -> u128 {
    unsafe { core::arch::asm!("r0 = 0;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_static_uninit_fail
extern "C" fn aggregate_ret_static_uninit_fail() -> i32 {
    unsafe { core::arch::asm!("call {static_agg_no_r2};r0 = r2;exit;", static_agg_no_r2 = sym static_agg_no_r2, options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: static_agg_precise
extern "C" fn static_agg_precise() -> u128 {
    unsafe { core::arch::asm!("r0 = 0;r2 = 4;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_static_precise
extern "C" fn aggregate_ret_static_precise() -> i32 {
    unsafe { core::arch::asm!("call {static_agg_precise};r6 = r2;r6 &= 7;r1 = r10;r1 += -8;r1 += r6;r0 = 0;*(u8 *)(r1 + 0) = r0;r0 = 0;exit;", static_agg_precise = sym static_agg_precise, options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_global_precise
extern "C" fn aggregate_ret_global_precise() -> i32 {
    unsafe { core::arch::asm!("call {global_agg_good};r6 = r2;r6 &= 7;r1 = r10;r1 += -8;r1 += r6;r0 = 0;*(u8 *)(r1 + 0) = r0;r0 = 0;exit;", global_agg_good = sym global_agg_good, options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_ret_arena_pair
extern "C" fn global_ret_arena_pair() -> arena_pair {
    unsafe { core::arch::asm!("r0 = 0;r2 = 0;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_global_arena_pair
extern "C" fn aggregate_ret_global_arena_pair() -> i32 {
    unsafe { core::arch::asm!("call {global_ret_arena_pair};r0 = 0;exit;", global_ret_arena_pair = sym global_ret_arena_pair, options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_ret_arena_and_scalar
extern "C" fn global_ret_arena_and_scalar() -> arena_and_scalar {
    unsafe { core::arch::asm!("r0 = 0;r2 = 0;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_global_arena_and_scalar
extern "C" fn aggregate_ret_global_arena_and_scalar() -> i32 {
    unsafe { core::arch::asm!("call {global_ret_arena_and_scalar};r0 = 0;exit;", global_ret_arena_and_scalar = sym global_ret_arena_and_scalar, options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_ret_arena_array
extern "C" fn global_ret_arena_array() -> arena_array {
    unsafe { core::arch::asm!("r0 = 0;r2 = 0;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_global_arena_array
extern "C" fn aggregate_ret_global_arena_array() -> i32 {
    unsafe { core::arch::asm!("call {global_ret_arena_array};r0 = 0;exit;", global_ret_arena_array = sym global_ret_arena_array, options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_ret_arena_single
extern "C" fn global_ret_arena_single() -> arena_single {
    unsafe { core::arch::asm!("r0 = 0;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_global_arena_single
extern "C" fn aggregate_ret_global_arena_single() -> i32 {
    unsafe { core::arch::asm!("call {global_ret_arena_single};r0 = 0;exit;", global_ret_arena_single = sym global_ret_arena_single, options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: global_ret_arena_union
extern "C" fn global_ret_arena_union() -> arena_upair {
    unsafe { core::arch::asm!("r0 = 0;r2 = 0;exit;", options(noreturn)); }
}

#[no_mangle]
#[inline(never)]
#[link_section = "tc"]
// BPF_NAKED: aggregate_ret_global_arena_union
extern "C" fn aggregate_ret_global_arena_union() -> i32 {
    unsafe { core::arch::asm!("call {global_ret_arena_union};r0 = 0;exit;", global_ret_arena_union = sym global_ret_arena_union, options(noreturn)); }
}

bpf_rs_core::btf_type_tags! {
    arena_pair.lo: arena; arena_pair.hi: arena;
    arena_and_scalar.p: arena; arena_array.p: arena;
    arena_single.p: arena; arena_upair.p: arena;
}
bpf_rs_core::bpf_object!("GPL");
bpf_rs_core::test_tags! {
    aggregate_ret_global_fail: __failure, __msg("R2 !read_ok");
    aggregate_ret_global_ptr_fail: __load_if_JITed, __failure, __msg("At subprogram exit the register R2 is not a scalar value");
    aggregate_ret_static_ptr_fail: __load_if_JITed, __failure, __msg("cannot return stack pointer to the caller");
    aggregate_ret_static_uninit_fail: __failure, __msg("R2 !read_ok");
    aggregate_ret_static_precise: __load_if_JITed, __success, __retval("0"), __log_level("2"), __msg("mark_precise: frame0: last_idx 5 first_idx 0 subseq_idx -1"), __msg("mark_precise: frame0: regs=r6 stack= before 4: (07) r1 += -8"), __msg("mark_precise: frame0: regs=r6 stack= before 3: (bf) r1 = r10"), __msg("mark_precise: frame0: regs=r6 stack= before 2: (57) r6 &= 7"), __msg("mark_precise: frame0: regs=r6 stack= before 1: (bf) r6 = r2"), __msg("mark_precise: frame0: regs=r2 stack= before 12: (95) exit"), __msg("mark_precise: frame1: regs=r2 stack= before 11: (b7) r2 = 4");
    aggregate_ret_global_precise: __load_if_JITed, __success, __retval("0"), __log_level("2"), __msg("mark_precise: frame0: last_idx 5 first_idx 0 subseq_idx -1"), __msg("mark_precise: frame0: regs=r6 stack= before 4: (07) r1 += -8"), __msg("mark_precise: frame0: regs=r6 stack= before 3: (bf) r1 = r10"), __msg("mark_precise: frame0: regs=r6 stack= before 2: (57) r6 &= 7"), __msg("mark_precise: frame0: regs=r6 stack= before 1: (bf) r6 = r2"), __msg("mark_precise: frame0: regs=r2 stack= before 0: (85) call pc+9");
    aggregate_ret_global_arena_pair: __load_if_JITed, __success, __retval("0");
    aggregate_ret_global_arena_and_scalar: __load_if_JITed, __success, __retval("0");
    aggregate_ret_global_arena_array: __load_if_JITed, __success, __retval("0");
    aggregate_ret_global_arena_single: __success, __retval("0");
    aggregate_ret_global_arena_union: __load_if_JITed, __success, __retval("0");
}
