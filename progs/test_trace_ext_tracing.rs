#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_trace_ext_tracing.c
// (bpf-rs-core idiom).
//
// fentry/fexit attach to test_pkt_md_access_new, itself a freplace
// extension of the tc program test_pkt_md_access. The trampoline's real
// arg 0 is a kernel `struct sk_buff *` (the tc program's actual runtime
// argument, as opposed to the `struct __sk_buff *` the tc program source
// sees) — read `len` through the `#[btf]` CO-RE path, matching the C
// source's own `struct sk_buff *skb` BPF_PROG declaration.

use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::bpf_object;
use btf_macros::btf;

#[btf]
struct sk_buff {
    len: u32,
}

#[no_mangle]
static mut fentry_called: u64 = 0;

#[link_section = "fentry/test_pkt_md_access_new"]
#[no_mangle]
extern "C" fn fentry(ctx: *const u64) -> i32 {
    let skb = arg(ctx, 0) as *const sk_buff;
    let len = *unsafe { &*skb }.len().get().unwrap();
    unsafe { fentry_called = len as u64 };
    0
}

#[no_mangle]
static mut fexit_called: u64 = 0;

#[link_section = "fexit/test_pkt_md_access_new"]
#[no_mangle]
extern "C" fn fexit(ctx: *const u64) -> i32 {
    let skb = arg(ctx, 0) as *const sk_buff;
    let len = *unsafe { &*skb }.len().get().unwrap();
    unsafe { fexit_called = len as u64 };
    0
}

bpf_object!("GPL");
