#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/pro_epilogue_with_kfunc.c, bpf-rs-core
// idiom.
//
// The C source implements `test_kfunc_pro_epilogue` as a `__naked` function
// with hand-written BPF asm so the accompanying `__xlated(...)` decl tags
// can assert the *exact* instruction sequence the kernel's struct_ops
// prologue/epilogue trampoline splices around it. rustc cannot emit
// BTF_KIND_DECL_TAG, so test_loader (RUN_TESTS) sees no tags on this
// object and just checks load success (see
// [[negative-verifier-tests-need-loadable-translation]] for the same
// decl-tag gap on __failure/__msg). The trampoline's prologue/epilogue
// splicing itself is unconditional kernel-side behavior keyed off the
// `test_pro_epilogue` struct_ops member (bpf_testmod.c), independent of
// how the callback body is written — so an ordinary (non-naked) function
// with the same semantics is sufficient: extract the args pointer from
// ctx slot 0 (the trampoline's u64-array calling convention, same as
// fentry/fexit — see struct_ops_maybe_null.rs), call the inc10 kfunc on
// it, then call subprog on it. The syscall program's expected retval
// (22022) already encodes the kernel-side prologue (+1000) and epilogue
// (+10000, *2) contributions, so this translation only needs to reproduce
// the (+10 kfunc, +1 subprog) contribution to args->a.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg;
use core::ffi::c_void;

#[repr(C)]
struct st_ops_args {
    a: u64,
}

extern "C" {
    fn bpf_kfunc_st_ops_inc10(args: *mut st_ops_args) -> i32;
    fn bpf_kfunc_st_ops_test_pro_epilogue(args: *mut st_ops_args) -> i32;
}

#[inline(never)]
fn subprog(args: *mut st_ops_args) -> i32 {
    unsafe {
        (*args).a += 1;
        (*args).a as i32
    }
}

#[link_section = "struct_ops/test_pro_epilogue"]
#[no_mangle]
extern "C" fn test_kfunc_pro_epilogue(ctx: *const u64) -> i32 {
    let args = fentry_arg(ctx, 0) as *mut st_ops_args;
    unsafe {
        bpf_kfunc_st_ops_inc10(args);
    }
    subprog(args)
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_pro_epilogue(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_pro_epilogue(&mut args as *mut st_ops_args) }
}

// struct bpf_testmod_st_ops (bpf_testmod.h): only the member this program
// initializes is declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see
// struct_ops_maybe_null.rs / bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_st_ops {
    test_pro_epilogue: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_st_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static pro_epilogue_with_kfunc: bpf_testmod_st_ops = bpf_testmod_st_ops {
    test_pro_epilogue: test_kfunc_pro_epilogue,
};

bpf_object!("GPL");
