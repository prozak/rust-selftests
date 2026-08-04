#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/pro_epilogue.c
// (bpf-rs-core idiom).
//
// The three struct_ops programs (test_prologue/test_epilogue/
// test_pro_epilogue) are `__naked` in the C source: raw asm that loads the
// args ptr, calls the bpf_kfunc_st_ops_inc10 kfunc, calls a noinline
// `subprog` (args->a += 1; return args->a), and exits. The actual
// prologue/epilogue code (args->a += 1000 on entry / args->a += 10000 then
// *2 on exit) is spliced in by the kernel's st_ops_gen_prologue/
// st_ops_gen_epilogue callbacks (bpf_testmod.c), which key purely off
// prog->aux->attach_func_name matching "test_prologue"/"test_epilogue"/
// "test_pro_epilogue" -- a generic, load-time mechanism independent of how
// the program body itself is written (see epilogue_exit.rs for the same
// observation about gen_epilogue). With no BTF_KIND_DECL_TAG surviving
// translation, the __xlated/__retval checks in pro_epilogue.c's RUN_TESTS
// never execute (test_loader's parse_test_spec finds no tags, so
// execute stays false) -- the only oracle is that all programs load. So
// each struct_ops program is written as an ordinary safe fn reproducing the
// same (kfunc call, args->a += 1, return args->a) behavior as the naked asm
// + inlined subprog, matching struct_ops_assoc_reuse.rs's ctx-handling
// idiom (ctx is the raw `u64 *` args array; ctx[0] is the `st_ops_args *`).
//
// __kfunc_btf_root is a plain (non-SEC, never-called) global function in
// the C source whose only purpose is giving the compiler/relocator a
// reachable use of bpf_kfunc_st_ops_inc10 for BTF/relocation purposes; it
// is a GLOBAL FUNC symbol in the clang-built object (confirmed via
// llvm-readelf -sW), so the internalize keep-list requires it verbatim.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use core::ffi::c_void;

#[allow(non_camel_case_types)]
#[repr(C)]
struct st_ops_args {
    a: u64,
}

extern "C" {
    fn bpf_kfunc_st_ops_inc10(args: *mut st_ops_args) -> i32;
    fn bpf_kfunc_st_ops_test_prologue(args: *mut st_ops_args) -> i32;
    fn bpf_kfunc_st_ops_test_epilogue(args: *mut st_ops_args) -> i32;
    fn bpf_kfunc_st_ops_test_pro_epilogue(args: *mut st_ops_args) -> i32;
}

#[no_mangle]
extern "C" fn __kfunc_btf_root() {
    unsafe {
        bpf_kfunc_st_ops_inc10(core::ptr::null_mut());
    }
}

#[link_section = "struct_ops/test_prologue"]
#[no_mangle]
extern "C" fn test_prologue(ctx: *const u64) -> i32 {
    let args = arg(ctx, 0) as *mut st_ops_args;
    unsafe {
        bpf_kfunc_st_ops_inc10(args);
        (*args).a += 1;
        (*args).a as i32
    }
}

#[link_section = "struct_ops/test_epilogue"]
#[no_mangle]
extern "C" fn test_epilogue(ctx: *const u64) -> i32 {
    let args = arg(ctx, 0) as *mut st_ops_args;
    unsafe {
        bpf_kfunc_st_ops_inc10(args);
        (*args).a += 1;
        (*args).a as i32
    }
}

#[link_section = "struct_ops/test_pro_epilogue"]
#[no_mangle]
extern "C" fn test_pro_epilogue(ctx: *const u64) -> i32 {
    let args = arg(ctx, 0) as *mut st_ops_args;
    unsafe {
        bpf_kfunc_st_ops_inc10(args);
        (*args).a += 1;
        (*args).a as i32
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_prologue(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_prologue(&mut args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_epilogue(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_epilogue(&mut args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_pro_epilogue(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_pro_epilogue(&mut args) }
}

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
static pro_epilogue: bpf_testmod_st_ops = bpf_testmod_st_ops {
    test_prologue,
    test_epilogue,
    test_pro_epilogue,
};

bpf_object!("GPL");
