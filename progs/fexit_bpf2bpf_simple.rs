#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/fexit_bpf2bpf_simple.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

// Minimal local CO-RE view of the kernel's real `struct sk_buff`, matching
// the C source's own local re-declaration (only the `len` field is needed;
// matched against target BTF by name).
#[btf]
struct sk_buff {
    len: u32,
}

#[no_mangle]
static mut test_result: u64 = 0;

#[link_section = "fexit/test_pkt_md_access"]
#[no_mangle]
extern "C" fn test_main2(ctx: *const u64) -> i32 {
    let skb = arg(ctx, 0) as *const sk_buff;
    let ret = arg(ctx, 1) as i32;

    let len = *unsafe { &*skb }.len().get().unwrap();
    if len != 74 || ret != 0 {
        return 0;
    }

    unsafe { test_result = 1 };
    0
}

bpf_object!("GPL");
