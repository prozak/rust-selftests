#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_qdisc_fail__incompl_ops.c,
// bpf-rs-core idiom.
//
// This Qdisc_ops mirror is missing `.init` on purpose: prog_tests/bpf_qdisc.c's
// test_incompl_ops() expects open_and_load() to succeed (the object itself is
// fine) but bpf_map__attach_struct_ops() on the "test" map to fail — the
// kernel's bpf_qdisc struct_ops reg_check (net/sched/bpf_qdisc.c) rejects
// registration of a qdisc that never defines .init, at attach time rather
// than load time.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;

#[repr(C)]
struct sk_buff {
    _priv: [u8; 0],
}

#[repr(C)]
struct Qdisc {
    _priv: [u8; 0],
}

// struct bpf_sk_buff_ptr (net/sched/bpf_qdisc.c): { struct sk_buff *skb; }
#[repr(C)]
struct bpf_sk_buff_ptr {
    _priv: [u8; 0],
}

const NET_XMIT_DROP: i32 = 0x01;

extern "C" {
    fn bpf_qdisc_skb_drop(skb: *mut sk_buff, to_free_list: *mut bpf_sk_buff_ptr);
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_qdisc_test_enqueue(ctx: *const u64) -> i32 {
    let skb = arg(ctx, 0) as *mut sk_buff;
    let to_free = arg(ctx, 2) as *mut bpf_sk_buff_ptr;

    unsafe { bpf_qdisc_skb_drop(skb, to_free) };
    NET_XMIT_DROP
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_qdisc_test_dequeue(_ctx: *const u64) -> *mut sk_buff {
    core::ptr::null_mut()
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_qdisc_test_reset(_ctx: *const u64) {}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_qdisc_test_destroy(_ctx: *const u64) {}

// struct Qdisc_ops (include/net/sch_generic.h): only the members this
// program initializes are declared — libbpf's struct_ops relocation matches
// local struct members against the kernel type by name (see
// bpf_tcp_nogpl.rs). `.init` is deliberately absent, matching the C source.
#[allow(non_camel_case_types)]
#[repr(C)]
struct Qdisc_ops {
    id: [u8; 16],
    enqueue: extern "C" fn(*const u64) -> i32,
    dequeue: extern "C" fn(*const u64) -> *mut sk_buff,
    reset: extern "C" fn(*const u64),
    destroy: extern "C" fn(*const u64),
}

unsafe impl Sync for Qdisc_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static test: Qdisc_ops = Qdisc_ops {
    id: *b"bpf_qdisc_test\0\0",
    enqueue: bpf_qdisc_test_enqueue,
    dequeue: bpf_qdisc_test_dequeue,
    reset: bpf_qdisc_test_reset,
    destroy: bpf_qdisc_test_destroy,
};

bpf_object!("GPL");
