// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_qdisc_fifo.c
// (+ bpf_qdisc_common.h), bpf-rs-core idiom.
//
// q_fifo_lock and q_fifo are C `private(A)` statics: `__hidden` in
// SEC(".data.A"), so BTF_VAR_STATIC and the map is not mmapped by libbpf. A
// private Rust static (no #[no_mangle]) gets the same linkage (see
// test_spin_lock.rs); rust-bpf's #[btf_tag] still finds it by its
// debug-info name and puts C's __contains(skb_node, node) decl tag on it.
// skb_node.skb is `struct sk_buff __kptr *` (btf_type_tags! below) and
// bpf_obj_new() takes skb_node's local type id like C's
// bpf_obj_new(typeof(*skbn)).
//
// Qdisc and sk_buff are #[btf] CO-RE views; every field chain lives in its
// own #[inline(never)] accessor (kfree_skb.rs explains the opt crash a
// second chain off the same root in one function provokes).

// BTF_TYPE_ID: skb_node_id local struct skb_node

use bpf_rs_core::bpf_object;
use bpf_rs_core::btf_type_tags;
use bpf_rs_core::helpers::{bpf_kptr_xchg, bpf_spin_lock, bpf_spin_unlock};
use bpf_rs_core::progs::fentry_arg;
use btf_macros::{btf, btf_tag};
use core::ffi::c_void;

const NET_XMIT_SUCCESS: i32 = 0x00;
const NET_XMIT_DROP: i32 = 0x01;

#[btf]
struct qdisc_skb_head {
    qlen: u32,
}

// include/uapi/linux/gen_stats.h
#[btf]
struct gnet_stats_queue {
    backlog: u32,
}

#[btf]
struct Qdisc {
    q: qdisc_skb_head,
    limit: u32,
    qstats: gnet_stats_queue,
}

#[btf]
struct sk_buff {
    cb: [u8; 48],
}

#[btf]
struct qdisc_skb_cb {
    pkt_len: u32,
}

// struct bpf_sk_buff_ptr (net/sched/bpf_qdisc.c): { struct sk_buff *skb; }
#[repr(C)]
struct bpf_sk_buff_ptr {
    _priv: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_list_head {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_list_node {
    __opaque: [u64; 3],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct skb_node {
    skb: *mut sk_buff,
    node: bpf_list_node,
}

#[allow(non_upper_case_globals)]
#[link_section = ".data.A"]
static mut q_fifo_lock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:skb_node:node")]
#[link_section = ".data.A"]
static mut q_fifo: bpf_list_head = bpf_list_head { __opaque: [0; 2] };

#[no_mangle]
// translint: allow(bool-global) — `init_called` is only ever stored to
// (`init_called = true`), never tested, in C and here alike.
static mut init_called: bool = false;

#[repr(C)]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

extern "C" {
    fn skb_node_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);
    fn bpf_list_push_back(head: *mut bpf_list_head, node: *mut bpf_list_node) -> i32;
    fn bpf_list_pop_front(head: *mut bpf_list_head) -> *mut bpf_list_node;
    fn bpf_qdisc_skb_drop(skb: *mut sk_buff, to_free_list: *mut bpf_sk_buff_ptr);
    fn bpf_qdisc_bstats_update(sch: *mut Qdisc, skb: *const sk_buff);
    fn bpf_kfree_skb(skb: *mut sk_buff);
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
}

#[inline(never)]
fn sch_qlen(sch: *mut Qdisc) -> u32 {
    *unsafe { &*sch }.q().qlen().get().unwrap()
}

#[inline(never)]
fn sch_qlen_ptr(sch: *mut Qdisc) -> *mut u32 {
    unsafe { &*sch }.q().qlen().as_mut_ptr()
}

#[inline(never)]
fn sch_limit(sch: *mut Qdisc) -> u32 {
    *unsafe { &*sch }.limit().get().unwrap()
}

#[inline(never)]
fn sch_limit_ptr(sch: *mut Qdisc) -> *mut u32 {
    unsafe { &*sch }.limit().as_mut_ptr()
}

#[inline(never)]
fn sch_backlog_ptr(sch: *mut Qdisc) -> *mut u32 {
    unsafe { &*sch }.qstats().backlog().as_mut_ptr()
}

// bpf_qdisc_common.h: qdisc_skb_cb(skb) = (struct qdisc_skb_cb *)skb->cb
#[inline(never)]
fn skb_qdisc_cb(skb: *const sk_buff) -> *const qdisc_skb_cb {
    unsafe { &*skb }.cb().as_ptr() as *const qdisc_skb_cb
}

#[inline(never)]
fn cb_pkt_len(cb: *const qdisc_skb_cb) -> u32 {
    *unsafe { &*cb }.pkt_len().get().unwrap()
}

#[inline(always)]
fn qdisc_pkt_len(skb: *const sk_buff) -> u32 {
    cb_pkt_len(skb_qdisc_cb(skb))
}

// container_of(node, struct skb_node, node)
#[inline(always)]
unsafe fn skb_node_of(node: *mut bpf_list_node) -> *mut skb_node {
    (node as *mut u8).sub(core::mem::offset_of!(skb_node, node)) as *mut skb_node
}

#[link_section = "struct_ops/bpf_fifo_enqueue"]
#[no_mangle]
extern "C" fn bpf_fifo_enqueue(ctx: *const u64) -> i32 {
    let mut skb = fentry_arg(ctx, 0) as *mut sk_buff;
    let sch = fentry_arg(ctx, 1) as *mut Qdisc;
    let to_free = fentry_arg(ctx, 2) as *mut bpf_sk_buff_ptr;

    unsafe {
        'drop: {
            if sch_qlen(sch) == sch_limit(sch) {
                break 'drop;
            }

            let skbn = bpf_obj_new(skb_node_id()) as *mut skb_node;
            if skbn.is_null() {
                break 'drop;
            }

            let pkt_len = qdisc_pkt_len(skb);

            *sch_qlen_ptr(sch) += 1;
            skb = bpf_kptr_xchg(core::ptr::addr_of_mut!((*skbn).skb).cast(), skb.cast()).cast();
            if !skb.is_null() {
                bpf_qdisc_skb_drop(skb, to_free);
            }

            bpf_spin_lock(core::ptr::addr_of_mut!(q_fifo_lock));
            bpf_list_push_back(
                core::ptr::addr_of_mut!(q_fifo),
                core::ptr::addr_of_mut!((*skbn).node),
            );
            bpf_spin_unlock(core::ptr::addr_of_mut!(q_fifo_lock));

            *sch_backlog_ptr(sch) += pkt_len;
            return NET_XMIT_SUCCESS;
        }
        bpf_qdisc_skb_drop(skb, to_free);
    }
    NET_XMIT_DROP
}

#[link_section = "struct_ops/bpf_fifo_dequeue"]
#[no_mangle]
extern "C" fn bpf_fifo_dequeue(ctx: *const u64) -> *mut sk_buff {
    let sch = fentry_arg(ctx, 0) as *mut Qdisc;

    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!(q_fifo_lock));
        let node = bpf_list_pop_front(core::ptr::addr_of_mut!(q_fifo));
        bpf_spin_unlock(core::ptr::addr_of_mut!(q_fifo_lock));
        if node.is_null() {
            return core::ptr::null_mut();
        }

        let skbn = skb_node_of(node);
        let skb: *mut sk_buff =
            bpf_kptr_xchg(core::ptr::addr_of_mut!((*skbn).skb).cast(), core::ptr::null_mut())
                .cast();
        bpf_obj_drop(skbn.cast());
        if skb.is_null() {
            return core::ptr::null_mut();
        }

        *sch_backlog_ptr(sch) -= qdisc_pkt_len(skb);
        bpf_qdisc_bstats_update(sch, skb);
        *sch_qlen_ptr(sch) -= 1;

        skb
    }
}

#[link_section = "struct_ops/bpf_fifo_init"]
#[no_mangle]
extern "C" fn bpf_fifo_init(ctx: *const u64) -> i32 {
    let sch = fentry_arg(ctx, 0) as *mut Qdisc;

    unsafe {
        *sch_limit_ptr(sch) = 1000;
        init_called = true;
    }
    0
}

#[link_section = "struct_ops/bpf_fifo_reset"]
#[no_mangle]
extern "C" fn bpf_fifo_reset(ctx: *const u64) {
    let sch = fentry_arg(ctx, 0) as *mut Qdisc;

    unsafe {
        // bpf_for(i, 0, sch->q.qlen)
        let mut it = bpf_iter_num { __opaque: [0; 1] };
        bpf_iter_num_new(&mut it, 0, sch_qlen(sch) as i32);
        loop {
            if bpf_iter_num_next(&mut it).is_null() {
                break;
            }

            bpf_spin_lock(core::ptr::addr_of_mut!(q_fifo_lock));
            let node = bpf_list_pop_front(core::ptr::addr_of_mut!(q_fifo));
            bpf_spin_unlock(core::ptr::addr_of_mut!(q_fifo_lock));

            if node.is_null() {
                break;
            }

            let skbn = skb_node_of(node);
            let skb: *mut sk_buff = bpf_kptr_xchg(
                core::ptr::addr_of_mut!((*skbn).skb).cast(),
                core::ptr::null_mut(),
            )
            .cast();
            if !skb.is_null() {
                bpf_kfree_skb(skb);
            }
            bpf_obj_drop(skbn.cast());
        }
        bpf_iter_num_destroy(&mut it);
        *sch_qlen_ptr(sch) = 0;
    }
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_fifo_destroy(_ctx: *const u64) {}

// struct Qdisc_ops (include/net/sch_generic.h): only the members this
// program initializes are declared — libbpf's struct_ops relocation matches
// local struct members against the kernel type by name.
#[allow(non_camel_case_types)]
#[repr(C)]
struct Qdisc_ops {
    enqueue: extern "C" fn(*const u64) -> i32,
    dequeue: extern "C" fn(*const u64) -> *mut sk_buff,
    init: extern "C" fn(*const u64) -> i32,
    reset: extern "C" fn(*const u64),
    destroy: extern "C" fn(*const u64),
    id: [u8; 16],
}

unsafe impl Sync for Qdisc_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static fifo: Qdisc_ops = Qdisc_ops {
    enqueue: bpf_fifo_enqueue,
    dequeue: bpf_fifo_dequeue,
    init: bpf_fifo_init,
    reset: bpf_fifo_reset,
    destroy: bpf_fifo_destroy,
    id: *b"bpf_fifo\0\0\0\0\0\0\0\0",
};

btf_type_tags! {
    skb_node.skb: kptr;
}

bpf_object!("GPL");
