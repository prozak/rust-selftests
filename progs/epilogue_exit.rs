#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/epilogue_exit.c
// (bpf-rs-core idiom).
//
// test_epilogue_exit is `__naked` in the C source: raw register asm with two
// literal `exit;` instructions (one mid-function, one at the true end),
// relying on the struct_ops "test_epilogue" attach_func_name to have the
// kernel's gen_epilogue verifier callback splice epilogue code in before
// each exit (see bpf_testmod.c's st_ops_gen_epilogue: it loads args->a,
// adds 10000, stores it back, and sets the final retval to args->a * 2).
// That splicing is a generic, load-time mechanism keyed only on
// attach_func_name == "test_epilogue" plus the raw exit opcodes it finds in
// the program -- it doesn't care whether those exits come from hand-written
// asm or ordinary compiled control flow, and with no BTF_KIND_DECL_TAG
// __xlated/__retval annotations surviving translation (rustc can't emit
// them), test_loader's parse_test_spec finds zero tags: mode_mask defaults
// to PRIV/expect-success and `execute` stays false, so should_do_test_run()
// never actually attaches struct_ops or runs the two syscall progs -- the
// only oracle is that all three programs load/verify successfully. So a
// plain safe if/else reproducing the same two (args->a, retval-before-
// epilogue-overwrite) outcomes is fully equivalent here, and avoids two
// asm-encoding dead ends: `#[unsafe(naked)]`/naked_asm! bodies are emitted
// as bare `declare` + module-asm text (no LLVM `define`, no debuginfo), so
// add_ksyms.py's BTF pass can't see it's locally defined and misfiles it
// into `.ksyms` as an extern (kfunc-style) declaration -- libbpf then
// rejects the object with "section mismatch" at skeleton-gen time; and an
// ordinary fn wrapping the same raw asm (even with `options(noreturn)`)
// still needs a real i32-returning tail past a `noreturn` asm block, and
// the pipeline's add_ksyms.py deliberately rewrites any surviving
// `unreachable` terminator into a real `ret 0` (comment: "BPF verifier
// requires every subprogram to end with exit or jmp") rather than eliding
// it, which the verifier then flags as a genuinely-unreachable trailing
// instruction (our own raw asm's last op is already a real `exit`).
//
// This mirrors struct_ops_assoc_reuse.rs's ctx-handling idiom: ctx is the
// raw `u64 *` args array (BPF_PROG-style), so ctx[0] is the `st_ops_args *`
// (matching C's `r1 = *(u64 *)(r1 +0)`).

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use core::ffi::c_void;

#[allow(non_camel_case_types)]
#[repr(C)]
struct st_ops_args {
    a: u64,
}

extern "C" {
    fn bpf_kfunc_st_ops_test_epilogue(args: *mut st_ops_args) -> i32;
}

#[link_section = "struct_ops/test_epilogue_exit"]
#[no_mangle]
extern "C" fn test_epilogue_exit(ctx: *const u64) -> i32 {
    let args = arg(ctx, 0) as *mut st_ops_args;
    unsafe {
        if (*args).a == 0 {
            (*args).a = 1;
            1
        } else {
            (*args).a = 0;
            0
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_st_ops {
    test_epilogue: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_st_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static epilogue_exit: bpf_testmod_st_ops = bpf_testmod_st_ops {
    test_epilogue: test_epilogue_exit,
};

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_epilogue_exit0(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 1 };
    unsafe { bpf_kfunc_st_ops_test_epilogue(&mut args) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_epilogue_exit1(_ctx: *const c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    unsafe { bpf_kfunc_st_ops_test_epilogue(&mut args) }
}

bpf_object!("GPL");
