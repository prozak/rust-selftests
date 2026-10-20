// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/nested_trust_failure.c,
// bpf-rs-core idiom (nested_trust_success.rs is the positive half).
//
// Two NEGATIVE verifier tests on nested pointer trust: task->user_cpus_ptr
// is not a trusted nested pointer, so bpf_cpumask_test_cpu rejects it; and
// skb->next is an untrusted pointer, so bpf_sk_storage_get rejects it
// before it ever gets to the sk_buff-vs-sock_common type mismatch.

use bpf_rs_core::helpers::bpf_sk_storage_get;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object};
use bpf_rs_core::test_tags;
use btf_macros::btf;

#[btf]
struct cpumask {
    bits: [u64; 1],
}

#[btf]
struct task_struct {
    user_cpus_ptr: *mut cpumask,
}

#[btf]
struct sk_buff {
    next: *mut sk_buff,
}

extern "C" {
    fn bpf_cpumask_test_cpu(cpu: u32, mask: *const cpumask) -> bool;
}

bpf_map! {
    sk_storage_map {
        r#type: *const [i32; 24],  // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const u64,
    }
}

test_tags! {
    test_invalid_nested_user_cpus: __failure, __msg("R2 must be");
    test_invalid_skb_field: __failure, __msg("R2 type=untrusted_ptr_ expected=ptr_, trusted_ptr_, rcu_ptr_");
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_invalid_nested_user_cpus(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;
    let user_cpus_ptr = *unsafe { &*task }.user_cpus_ptr().get().unwrap();
    unsafe { bpf_cpumask_test_cpu(0, user_cpus_ptr) };
    0
}

#[link_section = "tp_btf/tcp_probe"]
#[no_mangle]
extern "C" fn test_invalid_skb_field(ctx: *const u64) -> i32 {
    let skb = arg(ctx, 1) as *mut sk_buff;
    let next = *unsafe { &*skb }.next().get().unwrap();
    bpf_sk_storage_get(&sk_storage_map, next, core::ptr::null_mut(), 0);
    0
}

bpf_object!("GPL");
