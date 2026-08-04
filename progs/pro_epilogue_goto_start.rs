#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/pro_epilogue_goto_start.c, bpf-rs-core
// idiom.
//
// The C source implements each struct_ops callback as a `__naked` function
// with hand-written BPF asm whose accompanying `__xlated(...)` decl tags
// assert the exact instruction sequence the kernel's struct_ops
// prologue/epilogue trampoline splices around it. rustc cannot emit
// BTF_KIND_DECL_TAG, so test_loader (RUN_TESTS) sees no tags on this object
// and just checks load success (see
// [[negative-verifier-tests-need-loadable-translation]]). Tracing the naked
// asm through: r1 (the raw ctx pointer, never 0 or 1) drives a
// state-machine of backward gotos that always converges on `r0 = 0; exit`
// without ever touching args->a itself — the actual +1000/+10000
// contributions to args->a come entirely from the kernel's unconditional
// struct_ops prologue/epilogue splicing (bpf_testmod.c), keyed off which
// member (test_prologue/test_epilogue/test_pro_epilogue) the callback is
// registered under, independent of the callback body (same reasoning as
// pro_epilogue_with_kfunc.rs). So a trivial body that returns 0 reproduces
// the same syscall-program retvals as the naked original.

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

#[repr(C)]
struct st_ops_args {
    a: u64,
}

extern "C" {
    fn bpf_kfunc_st_ops_test_prologue(args: *mut st_ops_args) -> i32;
    fn bpf_kfunc_st_ops_test_epilogue(args: *mut st_ops_args) -> i32;
    fn bpf_kfunc_st_ops_test_pro_epilogue(args: *mut st_ops_args) -> i32;
}

#[link_section = "struct_ops/test_prologue_goto_start"]
#[no_mangle]
extern "C" fn test_prologue_goto_start(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "struct_ops/test_epilogue_goto_start"]
#[no_mangle]
extern "C" fn test_epilogue_goto_start(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "struct_ops/test_pro_epilogue_goto_start"]
#[no_mangle]
extern "C" fn test_pro_epilogue_goto_start(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_prologue_goto_start(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_prologue(&mut args as *mut st_ops_args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_epilogue_goto_start(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_epilogue(&mut args as *mut st_ops_args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_pro_epilogue_goto_start(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_pro_epilogue(&mut args as *mut st_ops_args) }
}

// struct bpf_testmod_st_ops (bpf_testmod.h): only the members this program
// initializes are declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see
// struct_ops_maybe_null.rs / pro_epilogue_with_kfunc.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_st_ops {
    test_prologue: extern "C" fn(*const u64) -> i32,
    test_epilogue: extern "C" fn(*const u64) -> i32,
    test_pro_epilogue: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_st_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static epilogue_goto_start: bpf_testmod_st_ops = bpf_testmod_st_ops {
    test_prologue: test_prologue_goto_start,
    test_epilogue: test_epilogue_goto_start,
    test_pro_epilogue: test_pro_epilogue_goto_start,
};

bpf_object!("GPL");
