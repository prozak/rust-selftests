#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_deny_namespace.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

const CAP_SYS_ADMIN: u32 = 21;
const EPERM: i32 = 1;

#[btf]
struct kernel_cap_t {
    val: u64,
}

#[btf]
struct cred {
    cap_effective: kernel_cap_t,
}

// int BPF_PROG(test_userns_create, const struct cred *cred, int ret) — ctx
// slot 0 is the trusted cred pointer, slot 1 is the accumulated LSM ret.
#[link_section = "lsm.s/userns_create"]
#[no_mangle]
extern "C" fn test_userns_create(ctx: *const u64) -> i32 {
    let cred_ptr = arg(ctx, 0) as *const cred;
    let ret = arg(ctx, 1) as i32;
    let cap_mask: u64 = 1u64 << CAP_SYS_ADMIN;

    if ret != 0 {
        return 0;
    }

    let caps_val = *unsafe { &*cred_ptr }.cap_effective().val().get().unwrap();
    if caps_val & cap_mask != 0 {
        return 0;
    }

    -EPERM
}

bpf_object!("GPL");
