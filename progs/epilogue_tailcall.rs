// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/epilogue_tailcall.c,
// bpf-rs-core idiom.
//
// epilogue_map's one slot is statically &test_epilogue_subprog
// (`.values = { [0] = (void *)&test_epilogue_subprog }`): `[TailcallFn; 1]`
// emits the slot storage and its .rel.maps entry, and scripts/btf_map_slots.py
// rewrites the BTF member to the zero-length array libbpf demands.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_tail_call;
use bpf_rs_core::maps;
use bpf_rs_core::progs::fentry_arg as arg;
use core::ffi::c_void;

#[repr(C)]
struct st_ops_args {
    a: u64,
}

#[inline(never)]
fn subprog(args: *mut st_ops_args) -> i32 {
    unsafe { (*args).a += 1 };
    unsafe { (*args).a as i32 }
}

#[link_section = "struct_ops/test_epilogue_subprog"]
#[no_mangle]
extern "C" fn test_epilogue_subprog(ctx: *const u64) -> i32 {
    let args = arg(ctx, 0) as *mut st_ops_args;
    subprog(args);
    unsafe { (*args).a as i32 }
}

type TailcallFn = extern "C" fn(*const u64) -> i32;

#[repr(C)]
struct epilogue_map {
    r#type: *const [i32; maps::PROG_ARRAY],
    max_entries: *const [i32; 1],
    key_size: *const [i32; 4],
    values: [TailcallFn; 1],
}
unsafe impl Sync for epilogue_map {}

#[link_section = ".maps"]
#[no_mangle]
static epilogue_map: epilogue_map = epilogue_map {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [test_epilogue_subprog],
};

#[link_section = "struct_ops/test_epilogue_tailcall"]
#[no_mangle]
extern "C" fn test_epilogue_tailcall(ctx: *const u64) -> i32 {
    bpf_tail_call(ctx as *const c_void, &epilogue_map, 0);
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_st_ops {
    test_epilogue: TailcallFn,
}
unsafe impl Sync for bpf_testmod_st_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static epilogue_tailcall: bpf_testmod_st_ops = bpf_testmod_st_ops {
    test_epilogue: test_epilogue_tailcall,
};

#[link_section = ".struct_ops.link"]
#[no_mangle]
static epilogue_subprog: bpf_testmod_st_ops = bpf_testmod_st_ops {
    test_epilogue: test_epilogue_subprog,
};

extern "C" {
    fn bpf_kfunc_st_ops_test_epilogue(args: *mut st_ops_args) -> i32;
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_epilogue_tailcall(args: *mut st_ops_args) -> i32 {
    unsafe { bpf_kfunc_st_ops_test_epilogue(args) }
}

bpf_object!("GPL");
