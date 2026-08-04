#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_multi_pages.c,
// bpf-rs-core idiom.
//
// 40 trivial struct_ops callbacks (tramp_1..tramp_40) wired into
// bpf_testmod_ops's tramp_N members, same as the C TRAMP()/F_TRAMP() macro
// pairs. The point of the test (prog_tests/test_struct_ops_multi_pages.c)
// is only that the generated trampoline image for the struct_ops map spans
// more than one page and still open/load/attaches; no callback value is
// ever read back, so each tramp_N just forwards its single int argument
// (see struct_ops_refcounted.rs for the established pattern of using a
// single generic `extern "C" fn(*const u64) -> i32` pointer type for every
// struct_ops member regardless of the real C prototype).

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;

macro_rules! tramp {
    ($name:ident, $sec:literal) => {
        #[link_section = $sec]
        #[no_mangle]
        extern "C" fn $name(ctx: *const u64) -> i32 {
            arg(ctx, 0) as i32
        }
    };
}

tramp!(tramp_1, "struct_ops/tramp_1");
tramp!(tramp_2, "struct_ops/tramp_2");
tramp!(tramp_3, "struct_ops/tramp_3");
tramp!(tramp_4, "struct_ops/tramp_4");
tramp!(tramp_5, "struct_ops/tramp_5");
tramp!(tramp_6, "struct_ops/tramp_6");
tramp!(tramp_7, "struct_ops/tramp_7");
tramp!(tramp_8, "struct_ops/tramp_8");
tramp!(tramp_9, "struct_ops/tramp_9");
tramp!(tramp_10, "struct_ops/tramp_10");
tramp!(tramp_11, "struct_ops/tramp_11");
tramp!(tramp_12, "struct_ops/tramp_12");
tramp!(tramp_13, "struct_ops/tramp_13");
tramp!(tramp_14, "struct_ops/tramp_14");
tramp!(tramp_15, "struct_ops/tramp_15");
tramp!(tramp_16, "struct_ops/tramp_16");
tramp!(tramp_17, "struct_ops/tramp_17");
tramp!(tramp_18, "struct_ops/tramp_18");
tramp!(tramp_19, "struct_ops/tramp_19");
tramp!(tramp_20, "struct_ops/tramp_20");
tramp!(tramp_21, "struct_ops/tramp_21");
tramp!(tramp_22, "struct_ops/tramp_22");
tramp!(tramp_23, "struct_ops/tramp_23");
tramp!(tramp_24, "struct_ops/tramp_24");
tramp!(tramp_25, "struct_ops/tramp_25");
tramp!(tramp_26, "struct_ops/tramp_26");
tramp!(tramp_27, "struct_ops/tramp_27");
tramp!(tramp_28, "struct_ops/tramp_28");
tramp!(tramp_29, "struct_ops/tramp_29");
tramp!(tramp_30, "struct_ops/tramp_30");
tramp!(tramp_31, "struct_ops/tramp_31");
tramp!(tramp_32, "struct_ops/tramp_32");
tramp!(tramp_33, "struct_ops/tramp_33");
tramp!(tramp_34, "struct_ops/tramp_34");
tramp!(tramp_35, "struct_ops/tramp_35");
tramp!(tramp_36, "struct_ops/tramp_36");
tramp!(tramp_37, "struct_ops/tramp_37");
tramp!(tramp_38, "struct_ops/tramp_38");
tramp!(tramp_39, "struct_ops/tramp_39");
tramp!(tramp_40, "struct_ops/tramp_40");

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    tramp_1: extern "C" fn(*const u64) -> i32,
    tramp_2: extern "C" fn(*const u64) -> i32,
    tramp_3: extern "C" fn(*const u64) -> i32,
    tramp_4: extern "C" fn(*const u64) -> i32,
    tramp_5: extern "C" fn(*const u64) -> i32,
    tramp_6: extern "C" fn(*const u64) -> i32,
    tramp_7: extern "C" fn(*const u64) -> i32,
    tramp_8: extern "C" fn(*const u64) -> i32,
    tramp_9: extern "C" fn(*const u64) -> i32,
    tramp_10: extern "C" fn(*const u64) -> i32,
    tramp_11: extern "C" fn(*const u64) -> i32,
    tramp_12: extern "C" fn(*const u64) -> i32,
    tramp_13: extern "C" fn(*const u64) -> i32,
    tramp_14: extern "C" fn(*const u64) -> i32,
    tramp_15: extern "C" fn(*const u64) -> i32,
    tramp_16: extern "C" fn(*const u64) -> i32,
    tramp_17: extern "C" fn(*const u64) -> i32,
    tramp_18: extern "C" fn(*const u64) -> i32,
    tramp_19: extern "C" fn(*const u64) -> i32,
    tramp_20: extern "C" fn(*const u64) -> i32,
    tramp_21: extern "C" fn(*const u64) -> i32,
    tramp_22: extern "C" fn(*const u64) -> i32,
    tramp_23: extern "C" fn(*const u64) -> i32,
    tramp_24: extern "C" fn(*const u64) -> i32,
    tramp_25: extern "C" fn(*const u64) -> i32,
    tramp_26: extern "C" fn(*const u64) -> i32,
    tramp_27: extern "C" fn(*const u64) -> i32,
    tramp_28: extern "C" fn(*const u64) -> i32,
    tramp_29: extern "C" fn(*const u64) -> i32,
    tramp_30: extern "C" fn(*const u64) -> i32,
    tramp_31: extern "C" fn(*const u64) -> i32,
    tramp_32: extern "C" fn(*const u64) -> i32,
    tramp_33: extern "C" fn(*const u64) -> i32,
    tramp_34: extern "C" fn(*const u64) -> i32,
    tramp_35: extern "C" fn(*const u64) -> i32,
    tramp_36: extern "C" fn(*const u64) -> i32,
    tramp_37: extern "C" fn(*const u64) -> i32,
    tramp_38: extern "C" fn(*const u64) -> i32,
    tramp_39: extern "C" fn(*const u64) -> i32,
    tramp_40: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static multi_pages: bpf_testmod_ops = bpf_testmod_ops {
    tramp_1,
    tramp_2,
    tramp_3,
    tramp_4,
    tramp_5,
    tramp_6,
    tramp_7,
    tramp_8,
    tramp_9,
    tramp_10,
    tramp_11,
    tramp_12,
    tramp_13,
    tramp_14,
    tramp_15,
    tramp_16,
    tramp_17,
    tramp_18,
    tramp_19,
    tramp_20,
    tramp_21,
    tramp_22,
    tramp_23,
    tramp_24,
    tramp_25,
    tramp_26,
    tramp_27,
    tramp_28,
    tramp_29,
    tramp_30,
    tramp_31,
    tramp_32,
    tramp_33,
    tramp_34,
    tramp_35,
    tramp_36,
    tramp_37,
    tramp_38,
    tramp_39,
    tramp_40,
};

bpf_object!("GPL");
