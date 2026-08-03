#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_maybe_null.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg;
use btf_macros::btf;

#[btf]
struct task_struct {
    tgid: i32,
}

#[no_mangle]
static mut tgid: i32 = 0;

// int BPF_PROG(test_maybe_null, int dummy, struct task_struct *task) — ctx
// slot 0 is dummy (unused, matching the C source), slot 1 is the nullable
// task pointer.
#[link_section = "struct_ops/test_maybe_null"]
#[no_mangle]
extern "C" fn test_maybe_null(ctx: *const u64) -> i32 {
    let task = fentry_arg(ctx, 1) as *const task_struct;
    if !task.is_null() {
        let v = *unsafe { &*task }.tgid().get().unwrap();
        unsafe { tgid = v };
    }
    0
}

// struct bpf_testmod_ops (bpf_testmod.h): only the member this program
// initializes is declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_maybe_null: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_1: bpf_testmod_ops = bpf_testmod_ops {
    test_maybe_null,
};

bpf_object!("GPL");
