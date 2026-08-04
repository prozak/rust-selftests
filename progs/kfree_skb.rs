#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/kfree_skb.c,
// bpf-rs-core idiom.
//
// tp_btf/fentry/fexit ctx args are trusted PTR_TO_BTF_ID: the verifier
// types them from the real kernel function/tracepoint prototype regardless
// of how the local Rust side casts the raw ctx slot, so #[btf] field
// chains through struct-typed pointers (dev) can dereference directly
// (`.get()`), exactly like C's `__builtin_preserve_access_index`. Only the
// non-struct `data` pointer needs an explicit bpf_probe_read_kernel to read
// past it, matching the C original's own split between direct CO-RE field
// reads and probe-read calls.
//
// Each field access chain off a given root is routed through its own
// #[inline(never)] helper (see btf-chain-merge-across-branches-corrupts-
// debuginfo in this repo's translation notes for the same underlying LLVM
// BPFAbstractMemberAccessPass fragility): querying a second field off an
// already-queried #[btf] root inside the same function crashes `opt` at
// -O2 (replaceWithGEP segfaults on a preserve_access_index call that
// SimplifyCFG has partly folded away). Isolating each chain in its own
// never-inlined function keeps every function's IR to exactly one such
// call until after the crash-prone pass has already run; the O2 inliner
// folds the helpers back in afterward.
//
// The C source's `dev->ifalias->rcuhead.next`/`->func` chase and the
// `__pkt_type_offset`/`pkt_type` read only ever feed bpf_printk() calls
// (stripped here as diagnostic-only, not checked by the userspace test),
// so both are dropped along with `struct callback_head`/`dev_ifalias`.

use core::ffi::c_void;

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_probe_read_kernel, bpf_skb_output};
use bpf_rs_core::progs::fentry_arg;
use btf_macros::btf;

bpf_map! {
    perf_buf_map {
        r#type: *const [i32; 4], // BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
        key: *const i32,
        value: *const i32,
    }
}

#[btf]
struct net_device {
    ifindex: i32,
}

#[btf]
struct atomic_local {
    counter: i32,
}

#[btf]
struct refcount_local {
    refs: atomic_local,
}

#[btf]
struct sk_buff {
    len: u32,
    dev: *mut net_device,
    users: refcount_local,
    data: *mut u8,
    cb: [u8; 48],
}

#[repr(C)]
struct Meta {
    ifindex: i32,
    cb32_0: u32,
    cb8_0: u8,
}

#[inline(always)]
fn htons(x: u16) -> u16 {
    x.to_be()
}

const BPF_F_CURRENT_CPU: u64 = 0xffffffff;

#[inline(never)]
fn skb_len(skb: *const sk_buff) -> u32 {
    *unsafe { &*skb }.len().get().unwrap()
}

#[inline(never)]
fn skb_users(skb: *const sk_buff) -> i32 {
    *unsafe { &*skb }.users().refs().counter().get().unwrap()
}

#[inline(never)]
fn skb_data(skb: *const sk_buff) -> *mut u8 {
    *unsafe { &*skb }.data().get().unwrap()
}

#[inline(never)]
fn skb_dev(skb: *const sk_buff) -> *mut net_device {
    *unsafe { &*skb }.dev().get().unwrap()
}

#[inline(never)]
fn skb_cb_ptr(skb: *const sk_buff) -> *const u8 {
    unsafe { &*skb }.cb().as_ptr() as *const u8
}

#[inline(never)]
fn dev_ifindex(dev: *const net_device) -> i32 {
    *unsafe { &*dev }.ifindex().get().unwrap()
}

#[link_section = "tp_btf/kfree_skb"]
#[no_mangle]
extern "C" fn trace_kfree_skb(ctx: *const u64) -> i32 {
    let skb = fentry_arg(ctx, 0) as *const sk_buff;

    let users = skb_users(skb);
    let data = skb_data(skb);
    let dev = skb_dev(skb);
    let ifindex = dev_ifindex(dev);
    let cb8: *const u8 = skb_cb_ptr(skb);
    let cb32: *const u32 = cb8 as *const u32;

    let meta = Meta {
        ifindex,
        cb32_0: unsafe { core::ptr::read_unaligned(cb32.add(2)) },
        cb8_0: unsafe { *cb8.add(8) },
    };

    let mut pkt_data: u16 = 0;
    bpf_probe_read_kernel(
        &mut pkt_data,
        core::mem::size_of::<u16>() as u32,
        unsafe { data.add(12) } as *const c_void,
    );

    if users != 1 || pkt_data != htons(0x86dd) || meta.ifindex != 1 {
        // raw tp ignores return value
        return 0;
    }

    bpf_skb_output(
        skb as *const c_void,
        &perf_buf_map,
        (72u64 << 32) | BPF_F_CURRENT_CPU,
        &meta,
        core::mem::size_of::<Meta>() as u64,
    );
    0
}

// The C original names its bss global `result` (an anonymous struct of the
// two bools); the internalize keep-list is derived from the C object's
// global symbol names, so the symbol must be called `result` here too, or
// the whole .bss DATASEC gets internalized away (nothing in this object
// ever reads it back, so an internalized-linkage global's writes are dead
// stores) and the regenerated skeleton loses its `bss` map entirely. A
// *named* Rust struct type here makes bpftool's skeleton generator emit an
// unresolved forward declaration (it assumes a named struct's definition
// exists in a header the userspace TU already includes -- see
// named-struct-bss-member-must-match-uapi-name); a fixed-size array of a
// primitive avoids that entirely and matches the anonymous struct's raw
// 2-byte layout the userspace test reads via bpf_map_lookup_elem.
#[no_mangle]
static mut result: [bool; 2] = [false, false];

#[link_section = "fentry/eth_type_trans"]
#[no_mangle]
extern "C" fn fentry_eth_type_trans(ctx: *const u64) -> i32 {
    let skb = fentry_arg(ctx, 0) as *const sk_buff;
    let dev = fentry_arg(ctx, 1) as *const net_device;

    let len = skb_len(skb);
    let ifindex = dev_ifindex(dev);

    // fentry sees full packet including L2 header
    if len != 74 || ifindex != 1 {
        return 0;
    }
    unsafe {
        (*core::ptr::addr_of_mut!(result))[0] = true;
    }
    0
}

#[link_section = "fexit/eth_type_trans"]
#[no_mangle]
extern "C" fn fexit_eth_type_trans(ctx: *const u64) -> i32 {
    let skb = fentry_arg(ctx, 0) as *const sk_buff;
    let dev = fentry_arg(ctx, 1) as *const net_device;
    let protocol = fentry_arg(ctx, 2) as u16;

    let len = skb_len(skb);
    let ifindex = dev_ifindex(dev);

    // fexit sees packet without L2 header that eth_type_trans should have
    // consumed.
    if len != 60 || protocol != htons(0x86dd) || ifindex != 1 {
        return 0;
    }
    unsafe {
        (*core::ptr::addr_of_mut!(result))[1] = true;
    }
    0
}

bpf_object!("GPL");
