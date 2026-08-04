#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/kprobe_write_ctx.c
// (bpf-rs-core idiom, __TARGET_ARCH_x86 branch only -- this pipeline always
// targets x86-64).
//
// The freplace test attaches `freplace_kprobe` (SEC("?freplace")) onto
// `kprobe_write_ctx` at load time (`bpf_program__set_attach_target(...,
// "kprobe_write_ctx")`); the kernel's btf_prepare_func_args() only accepts a
// kprobe program's ctx arg as PTR_TO_CTX (required for it to later be a
// valid freplace target -- otherwise func_info_aux[].unreliable gets set
// and freplace load fails with "Cannot replace static functions") when the
// pointee BTF type is a named `struct pt_regs`, matching the kernel's own
// ctx type for BPF_PROG_TYPE_KPROBE. So, unlike the raw `*const/*mut u64`
// register-slot idiom used elsewhere (test_uprobe.rs, test_probe_user.rs,
// kprobe_multi_override.rs) where no freplace target is involved, every
// kprobe-family ctx here is typed as `*mut pt_regs` and fields are written
// directly by name (`(*ctx).ax = 0`), matching the C source's own
// `ctx->ax = 0` / `regs->di = 0`.

use bpf_rs_core::bpf_object;

#[allow(non_camel_case_types)]
#[repr(C)]
struct pt_regs {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    bp: u64,
    bx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    ax: u64,
    cx: u64,
    dx: u64,
    si: u64,
    di: u64,
    orig_ax: u64,
    ip: u64,
    cs: u64,
    flags: u64,
    sp: u64,
    ss: u64,
}

#[link_section = "kprobe"]
#[no_mangle]
extern "C" fn kprobe_write_ctx(ctx: *mut pt_regs) -> i32 {
    unsafe { (*ctx).ax = 0 };
    0
}

#[link_section = "kprobe.multi"]
#[no_mangle]
extern "C" fn kprobe_multi_write_ctx(ctx: *mut pt_regs) -> i32 {
    unsafe { (*ctx).ax = 0 };
    0
}

#[link_section = "?kprobe"]
#[no_mangle]
extern "C" fn kprobe_dummy(_ctx: *mut pt_regs) -> i32 {
    0
}

#[link_section = "?freplace"]
#[no_mangle]
extern "C" fn freplace_kprobe(regs: *mut pt_regs) -> i32 {
    unsafe { (*regs).di = 0 };
    0
}

#[link_section = "?fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn fentry(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
