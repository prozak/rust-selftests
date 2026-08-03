#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/nested_trust_success.c
// (bpf-rs-core idiom).

use bpf_rs_core::helpers::bpf_sk_storage_get;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;

#[btf]
struct cpumask {
    bits: [u64; 1],
}

#[btf]
struct task_struct {
    cpus_ptr: *const cpumask,
    cpus_mask: cpumask,
}

#[btf]
struct sock {}

#[btf]
struct sk_buff {
    sk: *mut sock,
}

extern "C" {
    fn bpf_cpumask_test_cpu(cpu: u32, mask: *const cpumask) -> bool;
    fn bpf_cpumask_first_zero(mask: *const cpumask) -> u32;
}

bpf_map! {
    sk_storage_map {
        r#type: *const [i32; 24],  // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const u64,
    }
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_read_cpumask(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;
    let cpus_ptr = *unsafe { &*task }.cpus_ptr().get().unwrap();
    unsafe { bpf_cpumask_test_cpu(0, cpus_ptr) };
    0
}

#[link_section = "tp_btf/tcp_probe"]
#[no_mangle]
extern "C" fn test_skb_field(ctx: *const u64) -> i32 {
    let skb = arg(ctx, 1) as *mut sk_buff;
    let sk = *unsafe { &*skb }.sk().get().unwrap();
    bpf_sk_storage_get(&sk_storage_map, sk, core::ptr::null_mut(), 0);
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_nested_offset(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;
    let mask_ptr = unsafe { &*task }.cpus_mask().bits().as_ptr() as *const cpumask;
    unsafe { bpf_cpumask_first_zero(mask_ptr) };
    0
}

bpf_object!("GPL");
