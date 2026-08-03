#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_kptr_return.c,
// bpf-rs-core idiom.
//
// prog_tests/test_struct_ops_kptr_return.c's test_struct_ops_kptr_return()
// RUN_TESTS() over this object: it's a plain (non-__failure) struct_ops
// program, so it just needs to load and be attachable. The verifier allows
// a struct_ops program tagged as returning a referenced kptr to return
// either that acquired reference (task, released via bpf_task_release when
// dropped, here on the odd-dummy path) or NULL.
//
// BPF_PROG(kptr_return, int dummy, struct task_struct *task, struct cgroup
// *cgrp) unpacks ctx[0]/ctx[1]/ctx[2] (see bpf_tracing.h's ___bpf_ctx_cast);
// cgrp (ctx[2]) is unused by the C body too, so it's never read here.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;

#[repr(C)]
struct task_struct {
    _priv: [u8; 0],
}

extern "C" {
    fn bpf_task_release(p: *mut task_struct);
}

#[link_section = "struct_ops/test_return_ref_kptr"]
#[no_mangle]
extern "C" fn kptr_return(ctx: *const u64) -> *mut task_struct {
    let dummy = arg(ctx, 0) as i32;
    let task = arg(ctx, 1) as *mut task_struct;

    if dummy % 2 != 0 {
        unsafe { bpf_task_release(task) };
        core::ptr::null_mut()
    } else {
        task
    }
}

// struct bpf_testmod_ops (bpf_testmod.h): only the member this program
// initializes is declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_return_ref_kptr: extern "C" fn(*const u64) -> *mut task_struct,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static testmod_kptr_return: bpf_testmod_ops = bpf_testmod_ops {
    test_return_ref_kptr: kptr_return,
};

bpf_object!("GPL");
