#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/dummy_st_ops_success.c,
// bpf-rs-core idiom.
//
// `bpf_dummy_ops_state` (include/linux/bpf.h) is a fixed, single-`int`
// kernel struct accessed here via a plain `->` field access in the C
// source (not BPF_CORE_READ/preserve_access_index), so per TRANSLATING.md
// this is a direct BTF-checked field access, not a CO-RE relocation case:
// an ordinary `#[repr(C)]` struct with the same single `val: i32` field at
// offset 0 matches the real kernel layout byte-for-byte, same idiom as
// struct_ops_refcounted.rs's opaque task_struct but with the one real field
// exposed.
//
// test_1's `state` is registered `cb__nullable` (net/bpf/bpf_dummy_struct_ops.c),
// so the verifier requires a real null check before any dereference. The C
// source hides the check behind a raw `asm volatile` block so the compiler
// can't prove `state` non-null from the later unconditional `state->val`
// and fold the check away as dead code; `helpers::sink` (the same
// optimizer-barrier primitive TRANSLATING.md documents for `__sink(x)`)
// achieves the same effect here on the pointer value before the check, so
// a plain `if state.is_null()` compiles down to a real conditional branch.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::sink;
use bpf_rs_core::progs::fentry_arg as arg;

#[repr(C)]
struct bpf_dummy_ops_state {
    val: i32,
}

#[link_section = "struct_ops/test_1"]
#[no_mangle]
extern "C" fn test_1(ctx: *const u64) -> i32 {
    let mut state = arg(ctx, 0) as *mut bpf_dummy_ops_state;
    sink(&mut state);

    if state.is_null() {
        return 0xf2f3f4f5u32 as i32;
    }

    let ret = unsafe { (*state).val };
    unsafe { (*state).val = 0x5a };
    ret
}

#[no_mangle]
static mut test_2_args: [u64; 5] = [0; 5];

#[link_section = "struct_ops/test_2"]
#[no_mangle]
extern "C" fn test_2(ctx: *const u64) -> i32 {
    let state = arg(ctx, 0) as *mut bpf_dummy_ops_state;
    let a1 = arg(ctx, 1) as i32;
    let a2 = arg(ctx, 2) as u16;
    let a3 = arg(ctx, 3) as i8;
    let a4 = arg(ctx, 4);

    unsafe {
        test_2_args[0] = (*state).val as i64 as u64;
        test_2_args[1] = a1 as i64 as u64;
        test_2_args[2] = a2 as u64;
        test_2_args[3] = a3 as i64 as u64;
        test_2_args[4] = a4;
    }
    0
}

#[link_section = "struct_ops.s/test_sleepable"]
#[no_mangle]
extern "C" fn test_sleepable(_ctx: *const u64) -> i32 {
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_dummy_ops {
    test_1: extern "C" fn(*const u64) -> i32,
    test_2: extern "C" fn(*const u64) -> i32,
    test_sleepable: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_dummy_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static dummy_1: bpf_dummy_ops = bpf_dummy_ops {
    test_1,
    test_2,
    test_sleepable,
};

bpf_object!("GPL");
