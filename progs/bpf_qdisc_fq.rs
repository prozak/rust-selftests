// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![allow(non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_qdisc_fq.c
// (+ bpf_qdisc_common.h), bpf-rs-core idiom. prog_tests/bpf_qdisc.c
// registers the struct_ops, attaches bpf_fq to a veth and runs traffic
// through it (test_fq).
//
// bpf_fq keeps its flows in two hash maps of `__kptr` stashes
// (fq_stashed_flow.flow, btf_type_tags! below), the active flows in two
// bpf_list_heads and the throttled ones in a bpf_rb_root, each under its
// own spin lock in a C `private(X)` section (`__hidden` in SEC(".data.X"):
// private Rust statics in those sections, declared in the C's order,
// scripts/private_sections.py lays them out like the C; rust-bpf's
// #[btf_tag] puts the __contains() decl tags on them, bpf_qdisc_fifo.rs,
// rbtree.rs). Each flow owns a bpf_rb_root of skb_node packets (a member
// decl tag) and a bpf_refcount. `q` is the private(D) configuration
// struct, declared with the C's padding so `.data.D` is 72 bytes.
//
// bpf_obj_new() takes the local type ids like C's bpf_obj_new(typeof(*x)).
// container_of() is pointer arithmetic with offset_of!. The C's
// bpf_loop()/bpf_for_each_map_elem() callbacks and the two rbtree less()
// comparators are extern "C" functions; fq_new_flow is the one static the
// C keeps as a subprogram (called from three places), the other static
// helpers are inlined as clang inlines them. Both maps go to
// fq_remove_flows as `void *` (c_void), as in the C.
//
// CONFIG_HZ is the C's `__kconfig` extern (`// BTF_KCONFIG:` below,
// scripts/ksym_vars.py mirrors the C object's declaration): FQ_GC_AGE is
// 3*CONFIG_HZ jiffies, read at every use. bpf_list_empty() returns the
// kernel's bool, declared u8 and tested `& 1` as clang does.
//
// Qdisc, sk_buff, sock and net_device are #[btf] CO-RE views; every field
// chain lives in its own #[inline(never)] accessor (kfree_skb.rs explains
// the opt crash a second chain off the same root in one function
// provokes). skb->tstamp is the C's ktime_t (s64) in sk_buff's anonymous
// union, which the view flattens like sock_common's skc_hash.

// BTF_TYPE_ID: skb_node_id local struct skb_node
// BTF_TYPE_ID: fq_flow_node_id local struct fq_flow_node

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut, null_mut};

use bpf_rs_core::bpf_object;
use bpf_rs_core::btf_type_tags;
use bpf_rs_core::helpers::{
    bpf_for_each_map_elem, bpf_jiffies64, bpf_kptr_xchg, bpf_ktime_get_ns, bpf_loop,
    bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem, bpf_spin_lock,
    bpf_spin_unlock,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg;
use btf_macros::{btf, btf_tag};

const NET_XMIT_SUCCESS: i32 = 0x00;
const NET_XMIT_DROP: i32 = 0x01;

const TC_PRIO_CONTROL: u32 = 7;
const TC_PRIO_MAX: u32 = 15;

const ENOMEM: i32 = 12;
const E2BIG: i32 = 7;

const TCP_CLOSE: u8 = 7;
const TCPF_LISTEN: u32 = 1 << 10;
const TCPF_NEW_SYN_RECV: u32 = 1 << 12;

const NSEC_PER_USEC: u64 = 1000;
const NSEC_PER_SEC: u64 = 1000000000;

const NUM_QUEUE: u32 = 1 << 20;

/* limit number of collected flows per round */
const FQ_GC_MAX: u32 = 8;

#[allow(non_camel_case_types)]
#[repr(C)]
struct fq_bpf_data {
    quantum: u32,
    initial_quantum: u32,
    flow_refill_delay: u32,
    flow_plimit: u32,
    horizon: u64,
    orphan_mask: u32,
    timer_slack: u32,
    time_next_delayed_flow: u64,
    unthrottle_latency_ns: u64,
    horizon_drop: u8,
    _pad0: [u8; 3],
    new_flow_cnt: u32,
    old_flow_cnt: u32,
    _pad1: [u8; 4],
    ktime_cache: u64,
}

const CLS_RET_PRIO: i32 = 0;
const CLS_RET_NONPRIO: i32 = 1;
const CLS_RET_ERR: i32 = 2;

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C, align(4))]
struct bpf_refcount {
    __opaque: [u32; 1],
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
#[repr(C, align(8))]
struct bpf_rb_root {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_rb_node {
    __opaque: [u64; 4],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct skb_node {
    tstamp: u64,
    skb: *mut sk_buff,
    node: bpf_rb_node,
}

#[allow(non_camel_case_types)]
#[btf_tag]
#[repr(C)]
struct fq_flow_node {
    credit: i32,
    qlen: u32,
    age: u64,
    time_next_packet: u64,
    list_node: bpf_list_node,
    rb_node: bpf_rb_node,
    #[btf_tag(decl_tag = "contains:skb_node:node")]
    queue: bpf_rb_root,
    lock: bpf_spin_lock,
    refcount: bpf_refcount,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct dequeue_nonprio_ctx {
    stop_iter: bool,
    _pad: [u8; 7],
    expire: u64,
    now: u64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct remove_flows_ctx {
    gc_only: bool,
    _pad: [u8; 3],
    reset_cnt: u32,
    reset_max: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct unset_throttled_flows_ctx {
    unset_all: bool,
    _pad: [u8; 7],
    now: u64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct fq_stashed_flow {
    flow: *mut fq_flow_node,
}

#[link_section = ".maps"]
#[no_mangle]
static fq_nonprio_flows: BpfMap<u64, fq_stashed_flow, { maps::HASH }, { NUM_QUEUE as usize }> =
    BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static fq_prio_flows: BpfMap<u64, fq_stashed_flow, { maps::HASH }, 1> = BpfMap::new();

#[link_section = ".data.A"]
static mut fq_delayed_lock: bpf_spin_lock = bpf_spin_lock { val: 0 };
#[btf_tag(decl_tag = "contains:fq_flow_node:rb_node")]
#[link_section = ".data.A"]
static mut fq_delayed: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

#[link_section = ".data.B"]
static mut fq_new_flows_lock: bpf_spin_lock = bpf_spin_lock { val: 0 };
#[btf_tag(decl_tag = "contains:fq_flow_node:list_node")]
#[link_section = ".data.B"]
static mut fq_new_flows: bpf_list_head = bpf_list_head { __opaque: [0; 2] };

#[link_section = ".data.C"]
static mut fq_old_flows_lock: bpf_spin_lock = bpf_spin_lock { val: 0 };
#[btf_tag(decl_tag = "contains:fq_flow_node:list_node")]
#[link_section = ".data.C"]
static mut fq_old_flows: bpf_list_head = bpf_list_head { __opaque: [0; 2] };

#[link_section = ".data.D"]
static mut q: fq_bpf_data = fq_bpf_data {
    quantum: 0,
    initial_quantum: 0,
    flow_refill_delay: 0,
    flow_plimit: 0,
    horizon: 0,
    orphan_mask: 0,
    timer_slack: 0,
    time_next_delayed_flow: 0,
    unthrottle_latency_ns: 0,
    horizon_drop: 0,
    _pad0: [0; 3],
    new_flow_cnt: 0,
    old_flow_cnt: 0,
    _pad1: [0; 4],
    ktime_cache: 0,
};

// Kernel views (CO-RE)
#[btf]
struct qdisc_skb_head {
    qlen: u32,
}

#[btf]
struct gnet_stats_queue {
    backlog: u32,
    drops: u32,
}

#[btf]
struct net_device {
    mtu: u32,
    hard_header_len: u16,
}

#[btf]
struct netdev_queue {
    dev: *mut net_device,
}

#[btf]
struct Qdisc {
    q: qdisc_skb_head,
    limit: u32,
    dev_queue: *mut netdev_queue,
    qstats: gnet_stats_queue,
}

#[btf]
struct sock_common {
    skc_state: u8,
    skc_hash: u32,
}

#[btf]
struct sock {
    __sk_common: sock_common,
}

#[btf]
struct sk_buff {
    sk: *mut sock,
    tstamp: i64,
    cb: [u8; 48],
    priority: u32,
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

#[repr(C)]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

// BTF_KCONFIG: CONFIG_HZ
extern "C" {
    static CONFIG_HZ: u32;
}

extern "C" {
    fn skb_node_id() -> u64;
    fn fq_flow_node_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);
    fn bpf_refcount_acquire(obj: *mut c_void) -> *mut c_void;
    fn bpf_list_push_front(head: *mut bpf_list_head, node: *mut bpf_list_node) -> i32;
    fn bpf_list_push_back(head: *mut bpf_list_head, node: *mut bpf_list_node) -> i32;
    fn bpf_list_pop_front(head: *mut bpf_list_head) -> *mut bpf_list_node;
    fn bpf_list_empty(head: *mut bpf_list_head) -> u8;
    fn bpf_rbtree_add(
        root: *mut bpf_rb_root,
        node: *mut bpf_rb_node,
        less: extern "C" fn(*mut bpf_rb_node, *const bpf_rb_node) -> bool,
    ) -> i32;
    fn bpf_rbtree_first(root: *mut bpf_rb_root) -> *mut bpf_rb_node;
    fn bpf_rbtree_remove(root: *mut bpf_rb_root, node: *mut bpf_rb_node) -> *mut bpf_rb_node;
    fn bpf_qdisc_skb_drop(skb: *mut sk_buff, to_free_list: *mut bpf_sk_buff_ptr);
    fn bpf_qdisc_bstats_update(sch: *mut Qdisc, skb: *const sk_buff);
    fn bpf_qdisc_watchdog_schedule(sch: *mut Qdisc, expire: u64, delta_ns: u64);
    fn bpf_skb_get_hash(skb: *mut sk_buff) -> u32;
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

#[inline(never)]
fn sch_drops_ptr(sch: *mut Qdisc) -> *mut u32 {
    unsafe { &*sch }.qstats().drops().as_mut_ptr()
}

#[inline(never)]
fn sch_dev_queue(sch: *mut Qdisc) -> *mut netdev_queue {
    unsafe { *(&*sch).dev_queue().as_ptr() }
}

#[inline(never)]
fn dq_dev(dq: *mut netdev_queue) -> *mut net_device {
    unsafe { *(&*dq).dev().as_ptr() }
}

#[inline(never)]
fn dev_mtu(dev: *mut net_device) -> u32 {
    *unsafe { &*dev }.mtu().get().unwrap()
}

#[inline(never)]
fn dev_hard_header_len(dev: *mut net_device) -> u16 {
    *unsafe { &*dev }.hard_header_len().get().unwrap()
}

#[inline(never)]
fn skb_sk(skb: *mut sk_buff) -> *mut sock {
    unsafe { *(&*skb).sk().as_ptr() }
}

#[inline(never)]
fn skb_tstamp(skb: *mut sk_buff) -> i64 {
    *unsafe { &*skb }.tstamp().get().unwrap()
}

#[inline(never)]
fn skb_tstamp_ptr(skb: *mut sk_buff) -> *mut i64 {
    unsafe { &*skb }.tstamp().as_mut_ptr()
}

#[inline(never)]
fn skb_priority(skb: *mut sk_buff) -> u32 {
    *unsafe { &*skb }.priority().get().unwrap()
}

#[inline(never)]
fn sk_state(sk: *mut sock) -> u8 {
    *unsafe { &*sk }.__sk_common().skc_state().get().unwrap()
}

#[inline(never)]
fn sk_hash(sk: *mut sock) -> u32 {
    *unsafe { &*sk }.__sk_common().skc_hash().get().unwrap()
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
unsafe fn skb_node_of(node: *mut bpf_rb_node) -> *mut skb_node {
    (node as *mut u8).sub(core::mem::offset_of!(skb_node, node)) as *mut skb_node
}

// container_of(node, struct fq_flow_node, rb_node)
#[inline(always)]
unsafe fn flow_of_rb(node: *mut bpf_rb_node) -> *mut fq_flow_node {
    (node as *mut u8).sub(core::mem::offset_of!(fq_flow_node, rb_node)) as *mut fq_flow_node
}

// container_of(node, struct fq_flow_node, list_node)
#[inline(always)]
unsafe fn flow_of_list(node: *mut bpf_list_node) -> *mut fq_flow_node {
    (node as *mut u8).sub(core::mem::offset_of!(fq_flow_node, list_node)) as *mut fq_flow_node
}

/* Wrapper for bpf_kptr_xchg that expects NULL dst */
#[inline(always)]
unsafe fn bpf_kptr_xchg_back(map_val: *mut c_void, ptr: *mut c_void) {
    let ret = bpf_kptr_xchg(map_val, ptr);
    if !ret.is_null() {
        bpf_obj_drop(ret);
    }
}

extern "C" fn skbn_tstamp_less(a: *mut bpf_rb_node, b: *const bpf_rb_node) -> bool {
    unsafe {
        let skbn_a = skb_node_of(a);
        let skbn_b = skb_node_of(b as *mut bpf_rb_node);

        (*skbn_a).tstamp < (*skbn_b).tstamp
    }
}

extern "C" fn fn_time_next_packet_less(a: *mut bpf_rb_node, b: *const bpf_rb_node) -> bool {
    unsafe {
        let flow_a = flow_of_rb(a);
        let flow_b = flow_of_rb(b as *mut bpf_rb_node);

        (*flow_a).time_next_packet < (*flow_b).time_next_packet
    }
}

#[inline(always)]
unsafe fn fq_flows_add_head(
    head: *mut bpf_list_head,
    lock: *mut bpf_spin_lock,
    flow: *mut fq_flow_node,
    flow_cnt: *mut u32,
) {
    bpf_spin_lock(lock);
    bpf_list_push_front(head, addr_of_mut!((*flow).list_node));
    bpf_spin_unlock(lock);
    *flow_cnt += 1;
}

#[inline(always)]
unsafe fn fq_flows_add_tail(
    head: *mut bpf_list_head,
    lock: *mut bpf_spin_lock,
    flow: *mut fq_flow_node,
    flow_cnt: *mut u32,
) {
    bpf_spin_lock(lock);
    bpf_list_push_back(head, addr_of_mut!((*flow).list_node));
    bpf_spin_unlock(lock);
    *flow_cnt += 1;
}

#[inline(always)]
unsafe fn fq_flows_remove_front(
    head: *mut bpf_list_head,
    lock: *mut bpf_spin_lock,
    node: &mut *mut bpf_list_node,
    flow_cnt: *mut u32,
) {
    bpf_spin_lock(lock);
    *node = bpf_list_pop_front(head);
    bpf_spin_unlock(lock);
    *flow_cnt -= 1;
}

#[inline(always)]
unsafe fn fq_flows_is_empty(head: *mut bpf_list_head, lock: *mut bpf_spin_lock) -> bool {
    bpf_spin_lock(lock);
    let empty = bpf_list_empty(head) & 1;
    bpf_spin_unlock(lock);

    empty != 0
}

/* flow->age is used to denote the state of the flow (not-detached, detached, throttled)
 * as well as the timestamp when the flow is detached.
 *
 * 0: not-detached
 * 1 - (~0ULL-1): detached
 * ~0ULL: throttled
 */
#[inline(always)]
unsafe fn fq_flow_set_detached(flow: *mut fq_flow_node) {
    (*flow).age = bpf_jiffies64();
}

#[inline(always)]
unsafe fn fq_flow_is_detached(flow: *mut fq_flow_node) -> bool {
    (*flow).age != 0 && (*flow).age != !0u64
}

#[inline(always)]
fn sk_listener(sk: *mut sock) -> bool {
    (1u32 << sk_state(sk)) & (TCPF_LISTEN | TCPF_NEW_SYN_RECV) != 0
}

#[inline(never)]
unsafe fn fq_new_flow(flow_map: *const c_void, sflow: &mut *mut fq_stashed_flow, hash: u64) -> i32 {
    let tmp = fq_stashed_flow { flow: null_mut() };

    let flow = bpf_obj_new(fq_flow_node_id()) as *mut fq_flow_node;
    if flow.is_null() {
        return -ENOMEM;
    }

    (*flow).credit = q.initial_quantum as i32;
    (*flow).qlen = 0;
    (*flow).age = 1;
    (*flow).time_next_packet = 0;

    let ret = bpf_map_update_elem(flow_map, &hash, &tmp, 0) as i32;
    if ret == -ENOMEM || ret == -E2BIG {
        fq_gc();
        bpf_map_update_elem(&fq_nonprio_flows, &hash, &tmp, 0);
    }

    *sflow = bpf_map_lookup_elem(flow_map, &hash) as *mut fq_stashed_flow;
    if (*sflow).is_null() {
        bpf_obj_drop(flow.cast());
        return -ENOMEM;
    }

    bpf_kptr_xchg_back(addr_of_mut!((**sflow).flow).cast(), flow.cast());
    0
}

#[inline(always)]
unsafe fn fq_classify(skb: *mut sk_buff, sflow: &mut *mut fq_stashed_flow) -> i32 {
    let sk = skb_sk(skb);
    let mut ret = CLS_RET_NONPRIO;
    let mut hash: u64 = 0;

    if (skb_priority(skb) & TC_PRIO_MAX) == TC_PRIO_CONTROL {
        *sflow = bpf_map_lookup_elem(&fq_prio_flows, &hash) as *mut fq_stashed_flow;
        ret = CLS_RET_PRIO;
    } else {
        if sk.is_null() || sk_listener(sk) {
            hash = (bpf_skb_get_hash(skb) & q.orphan_mask) as u64;
            /* Avoid collision with an existing flow hash, which
             * only uses the lower 32 bits of hash, by setting the
             * upper half of hash to 1.
             */
            hash |= 1u64 << 32;
        } else if sk_state(sk) == TCP_CLOSE {
            hash = (bpf_skb_get_hash(skb) & q.orphan_mask) as u64;
            hash |= 1u64 << 32;
        } else {
            hash = sk_hash(sk) as u64;
        }
        *sflow = bpf_map_lookup_elem(&fq_nonprio_flows, &hash) as *mut fq_stashed_flow;
    }

    if (*sflow).is_null() {
        ret = if fq_new_flow(addr_of!(fq_nonprio_flows).cast(), sflow, hash) < 0 {
            CLS_RET_ERR
        } else {
            CLS_RET_NONPRIO
        };
    }

    ret
}

#[inline(always)]
unsafe fn fq_packet_beyond_horizon(skb: *mut sk_buff) -> bool {
    skb_tstamp(skb) > q.ktime_cache.wrapping_add(q.horizon) as i64
}

#[link_section = "struct_ops/bpf_fq_enqueue"]
#[no_mangle]
extern "C" fn bpf_fq_enqueue(ctx: *const u64) -> i32 {
    let mut skb = fentry_arg(ctx, 0) as *mut sk_buff;
    let sch = fentry_arg(ctx, 1) as *mut Qdisc;
    let to_free = fentry_arg(ctx, 2) as *mut bpf_sk_buff_ptr;
    let mut flow: *mut fq_flow_node = null_mut();
    let mut sflow: *mut fq_stashed_flow = null_mut();
    let time_to_send: u64;

    unsafe {
        'drop: {
            if sch_qlen(sch) >= sch_limit(sch) {
                break 'drop;
            }

            if skb_tstamp(skb) == 0 {
                q.ktime_cache = bpf_ktime_get_ns();
                time_to_send = q.ktime_cache;
            } else {
                if fq_packet_beyond_horizon(skb) {
                    q.ktime_cache = bpf_ktime_get_ns();
                    if fq_packet_beyond_horizon(skb) {
                        if q.horizon_drop != 0 {
                            break 'drop;
                        }

                        *skb_tstamp_ptr(skb) = q.ktime_cache.wrapping_add(q.horizon) as i64;
                    }
                }
                time_to_send = skb_tstamp(skb) as u64;
            }

            let ret = fq_classify(skb, &mut sflow);
            if ret == CLS_RET_ERR {
                break 'drop;
            }

            flow = bpf_kptr_xchg(addr_of_mut!((*sflow).flow).cast(), flow.cast()).cast();
            if flow.is_null() {
                break 'drop;
            }

            if ret == CLS_RET_NONPRIO {
                if (*flow).qlen >= q.flow_plimit {
                    bpf_kptr_xchg_back(addr_of_mut!((*sflow).flow).cast(), flow.cast());
                    break 'drop;
                }

                if fq_flow_is_detached(flow) {
                    let flow_copy = bpf_refcount_acquire(flow.cast()) as *mut fq_flow_node;

                    let jiffies = bpf_jiffies64();
                    if (jiffies.wrapping_sub((*flow_copy).age.wrapping_add(q.flow_refill_delay as u64)) as i64) > 0 {
                        if (*flow_copy).credit < q.quantum as i32 {
                            (*flow_copy).credit = q.quantum as i32;
                        }
                    }
                    (*flow_copy).age = 0;
                    fq_flows_add_tail(
                        addr_of_mut!(fq_new_flows),
                        addr_of_mut!(fq_new_flows_lock),
                        flow_copy,
                        addr_of_mut!(q.new_flow_cnt),
                    );
                }
            }

            let skbn = bpf_obj_new(skb_node_id()) as *mut skb_node;
            if skbn.is_null() {
                bpf_kptr_xchg_back(addr_of_mut!((*sflow).flow).cast(), flow.cast());
                break 'drop;
            }

            *skb_tstamp_ptr(skb) = time_to_send as i64;
            (*skbn).tstamp = time_to_send;

            *sch_backlog_ptr(sch) += qdisc_pkt_len(skb);

            skb = bpf_kptr_xchg(addr_of_mut!((*skbn).skb).cast(), skb.cast()).cast();
            if !skb.is_null() {
                bpf_qdisc_skb_drop(skb, to_free);
            }

            bpf_spin_lock(addr_of_mut!((*flow).lock));
            bpf_rbtree_add(addr_of_mut!((*flow).queue), addr_of_mut!((*skbn).node), skbn_tstamp_less);
            bpf_spin_unlock(addr_of_mut!((*flow).lock));

            (*flow).qlen += 1;
            bpf_kptr_xchg_back(addr_of_mut!((*sflow).flow).cast(), flow.cast());

            *sch_qlen_ptr(sch) += 1;
            return NET_XMIT_SUCCESS;
        }

        bpf_qdisc_skb_drop(skb, to_free);
        *sch_drops_ptr(sch) += 1;
    }
    NET_XMIT_DROP
}

extern "C" fn fq_unset_throttled_flows(_index: u64, ctx: *mut unset_throttled_flows_ctx) -> i64 {
    unsafe {
        bpf_spin_lock(addr_of_mut!(fq_delayed_lock));

        let node = bpf_rbtree_first(addr_of_mut!(fq_delayed));
        if node.is_null() {
            bpf_spin_unlock(addr_of_mut!(fq_delayed_lock));
            return 1;
        }

        let flow = flow_of_rb(node);
        if !(*ctx).unset_all && (*flow).time_next_packet > (*ctx).now {
            q.time_next_delayed_flow = (*flow).time_next_packet;
            bpf_spin_unlock(addr_of_mut!(fq_delayed_lock));
            return 1;
        }

        let node = bpf_rbtree_remove(addr_of_mut!(fq_delayed), addr_of_mut!((*flow).rb_node));

        bpf_spin_unlock(addr_of_mut!(fq_delayed_lock));

        if node.is_null() {
            return 1;
        }

        let flow = flow_of_rb(node);
        (*flow).age = 0;
        fq_flows_add_tail(
            addr_of_mut!(fq_old_flows),
            addr_of_mut!(fq_old_flows_lock),
            flow,
            addr_of_mut!(q.old_flow_cnt),
        );
    }

    0
}

#[inline(always)]
unsafe fn fq_flow_set_throttled(flow: *mut fq_flow_node) {
    (*flow).age = !0u64;

    if q.time_next_delayed_flow > (*flow).time_next_packet {
        q.time_next_delayed_flow = (*flow).time_next_packet;
    }

    bpf_spin_lock(addr_of_mut!(fq_delayed_lock));
    bpf_rbtree_add(addr_of_mut!(fq_delayed), addr_of_mut!((*flow).rb_node), fn_time_next_packet_less);
    bpf_spin_unlock(addr_of_mut!(fq_delayed_lock));
}

#[inline(always)]
unsafe fn fq_check_throttled(now: u64) {
    let mut ctx = unset_throttled_flows_ctx { unset_all: false, _pad: [0; 7], now };

    if q.time_next_delayed_flow > now {
        return;
    }

    let sample: u64 = now.wrapping_sub(q.time_next_delayed_flow);
    q.unthrottle_latency_ns = q.unthrottle_latency_ns.wrapping_sub(q.unthrottle_latency_ns >> 3);
    q.unthrottle_latency_ns = q.unthrottle_latency_ns.wrapping_add(sample >> 3);

    q.time_next_delayed_flow = !0u64;
    bpf_loop(NUM_QUEUE, fq_unset_throttled_flows, &mut ctx, 0);
}

#[inline(always)]
unsafe fn fq_dequeue_nonprio_flows(_index: u32, ctx: *mut dequeue_nonprio_ctx) -> *mut sk_buff {
    let mut skb: *mut sk_buff = null_mut();
    let head: *mut bpf_list_head;
    let lock: *mut bpf_spin_lock;
    let cnt: *mut u32;
    let mut node: *mut bpf_list_node = null_mut();

    'break_loop: {
        if q.new_flow_cnt != 0 {
            head = addr_of_mut!(fq_new_flows);
            lock = addr_of_mut!(fq_new_flows_lock);
            cnt = addr_of_mut!(q.new_flow_cnt);
        } else if q.old_flow_cnt != 0 {
            head = addr_of_mut!(fq_old_flows);
            lock = addr_of_mut!(fq_old_flows_lock);
            cnt = addr_of_mut!(q.old_flow_cnt);
        } else {
            if q.time_next_delayed_flow != !0u64 {
                (*ctx).expire = q.time_next_delayed_flow;
            }
            break 'break_loop;
        }

        fq_flows_remove_front(head, lock, &mut node, cnt);
        if node.is_null() {
            break 'break_loop;
        }

        let flow = flow_of_list(node);
        if (*flow).credit <= 0 {
            (*flow).credit = (*flow).credit.wrapping_add(q.quantum as i32);
            fq_flows_add_tail(
                addr_of_mut!(fq_old_flows),
                addr_of_mut!(fq_old_flows_lock),
                flow,
                addr_of_mut!(q.old_flow_cnt),
            );
            return null_mut();
        }

        bpf_spin_lock(addr_of_mut!((*flow).lock));
        let rb_node = bpf_rbtree_first(addr_of_mut!((*flow).queue));
        if rb_node.is_null() {
            bpf_spin_unlock(addr_of_mut!((*flow).lock));
            let is_empty = fq_flows_is_empty(addr_of_mut!(fq_old_flows), addr_of_mut!(fq_old_flows_lock));
            if head == addr_of_mut!(fq_new_flows) && !is_empty {
                fq_flows_add_tail(
                    addr_of_mut!(fq_old_flows),
                    addr_of_mut!(fq_old_flows_lock),
                    flow,
                    addr_of_mut!(q.old_flow_cnt),
                );
            } else {
                fq_flow_set_detached(flow);
                bpf_obj_drop(flow.cast());
            }
            return null_mut();
        }

        let skbn = skb_node_of(rb_node);
        let time_to_send = (*skbn).tstamp;

        let time_next_packet = if time_to_send > (*flow).time_next_packet {
            time_to_send
        } else {
            (*flow).time_next_packet
        };
        if (*ctx).now < time_next_packet {
            bpf_spin_unlock(addr_of_mut!((*flow).lock));
            (*flow).time_next_packet = time_next_packet;
            fq_flow_set_throttled(flow);
            return null_mut();
        }

        let rb_node = bpf_rbtree_remove(addr_of_mut!((*flow).queue), rb_node);
        bpf_spin_unlock(addr_of_mut!((*flow).lock));

        'add_flow_and_break: {
            if rb_node.is_null() {
                break 'add_flow_and_break;
            }

            let skbn = skb_node_of(rb_node);
            skb = bpf_kptr_xchg(addr_of_mut!((*skbn).skb).cast(), skb.cast()).cast();
            bpf_obj_drop(skbn.cast());

            if skb.is_null() {
                break 'add_flow_and_break;
            }

            (*flow).credit = (*flow).credit.wrapping_sub(qdisc_pkt_len(skb) as i32);
            (*flow).qlen -= 1;
        }

        fq_flows_add_head(head, lock, flow, cnt);
    }

    (*ctx).stop_iter = true;
    skb
}

#[inline(always)]
unsafe fn fq_dequeue_prio() -> *mut sk_buff {
    let mut flow: *mut fq_flow_node = null_mut();
    let mut skb: *mut sk_buff = null_mut();
    let hash: u64 = 0;

    let sflow = bpf_map_lookup_elem(&fq_prio_flows, &hash) as *mut fq_stashed_flow;
    if sflow.is_null() {
        return null_mut();
    }

    flow = bpf_kptr_xchg(addr_of_mut!((*sflow).flow).cast(), flow.cast()).cast();
    if flow.is_null() {
        return null_mut();
    }

    'out: {
        bpf_spin_lock(addr_of_mut!((*flow).lock));
        let rb_node = bpf_rbtree_first(addr_of_mut!((*flow).queue));
        if rb_node.is_null() {
            bpf_spin_unlock(addr_of_mut!((*flow).lock));
            break 'out;
        }

        let skbn = skb_node_of(rb_node);
        let rb_node = bpf_rbtree_remove(addr_of_mut!((*flow).queue), addr_of_mut!((*skbn).node));
        bpf_spin_unlock(addr_of_mut!((*flow).lock));

        if rb_node.is_null() {
            break 'out;
        }

        let skbn = skb_node_of(rb_node);
        skb = bpf_kptr_xchg(addr_of_mut!((*skbn).skb).cast(), skb.cast()).cast();
        bpf_obj_drop(skbn.cast());
    }

    bpf_kptr_xchg_back(addr_of_mut!((*sflow).flow).cast(), flow.cast());

    skb
}

#[link_section = "struct_ops/bpf_fq_dequeue"]
#[no_mangle]
extern "C" fn bpf_fq_dequeue(ctx: *const u64) -> *mut sk_buff {
    let sch = fentry_arg(ctx, 0) as *mut Qdisc;
    let mut cb_ctx = dequeue_nonprio_ctx { stop_iter: false, _pad: [0; 7], expire: 0, now: 0 };
    let mut skb: *mut sk_buff = null_mut();

    unsafe {
        'out: {
            if sch_qlen(sch) == 0 {
                break 'out;
            }

            'dequeue: {
                skb = fq_dequeue_prio();
                if !skb.is_null() {
                    break 'dequeue;
                }

                q.ktime_cache = bpf_ktime_get_ns();
                cb_ctx.now = q.ktime_cache;
                fq_check_throttled(q.ktime_cache);
                // bpf_for(i, 0, sch->limit)
                let limit = sch_limit(sch) as i32;
                let mut it = bpf_iter_num { __opaque: [0; 1] };
                bpf_iter_num_new(&mut it, 0, limit);
                loop {
                    let t = bpf_iter_num_next(&mut it);
                    if t.is_null() {
                        break;
                    }
                    let i = *t;
                    if !(i >= 0 && i < limit) {
                        break;
                    }
                    skb = fq_dequeue_nonprio_flows(i as u32, &mut cb_ctx);
                    if cb_ctx.stop_iter {
                        break;
                    }
                }
                bpf_iter_num_destroy(&mut it);

                if skb.is_null() {
                    if cb_ctx.expire != 0 {
                        bpf_qdisc_watchdog_schedule(sch, cb_ctx.expire, q.timer_slack as u64);
                    }
                    break 'out;
                }
            }

            *sch_qlen_ptr(sch) -= 1;
            *sch_backlog_ptr(sch) -= qdisc_pkt_len(skb);
            bpf_qdisc_bstats_update(sch, skb);
            return skb;
        }
    }
    null_mut()
}

extern "C" fn fq_remove_flows_in_list(_index: u64, _ctx: *mut c_void) -> i64 {
    unsafe {
        bpf_spin_lock(addr_of_mut!(fq_new_flows_lock));
        let mut node = bpf_list_pop_front(addr_of_mut!(fq_new_flows));
        bpf_spin_unlock(addr_of_mut!(fq_new_flows_lock));
        if node.is_null() {
            bpf_spin_lock(addr_of_mut!(fq_old_flows_lock));
            node = bpf_list_pop_front(addr_of_mut!(fq_old_flows));
            bpf_spin_unlock(addr_of_mut!(fq_old_flows_lock));
            if node.is_null() {
                return 1;
            }
        }

        let flow = flow_of_list(node);
        bpf_obj_drop(flow.cast());
    }

    0
}

/// FQ_GC_AGE (3*CONFIG_HZ)
#[inline(always)]
fn fq_gc_age() -> u64 {
    (3 * unsafe { CONFIG_HZ }) as u64
}

#[inline(always)]
unsafe fn fq_gc_candidate(flow: *mut fq_flow_node) -> bool {
    let jiffies = bpf_jiffies64();

    fq_flow_is_detached(flow)
        && (jiffies.wrapping_sub((*flow).age.wrapping_add(fq_gc_age())) as i64) > 0
}

extern "C" fn fq_remove_flows(
    flow_map: *mut c_void,
    hash: *mut u64,
    sflow: *mut fq_stashed_flow,
    ctx: *mut remove_flows_ctx,
) -> i64 {
    unsafe {
        if !(*sflow).flow.is_null() && (!(*ctx).gc_only || fq_gc_candidate((*sflow).flow)) {
            bpf_map_delete_elem(flow_map as *const c_void, &*hash);
            (*ctx).reset_cnt += 1;
        }

        if (*ctx).reset_cnt < (*ctx).reset_max {
            0
        } else {
            1
        }
    }
}

#[inline(always)]
unsafe fn fq_gc() {
    let mut cb_ctx = remove_flows_ctx { gc_only: true, _pad: [0; 3], reset_cnt: 0, reset_max: FQ_GC_MAX };

    bpf_for_each_map_elem(addr_of!(fq_nonprio_flows).cast::<c_void>(), fq_remove_flows, &mut cb_ctx, 0);
}

#[link_section = "struct_ops/bpf_fq_reset"]
#[no_mangle]
extern "C" fn bpf_fq_reset(ctx: *const u64) {
    let sch = fentry_arg(ctx, 0) as *mut Qdisc;
    let mut utf_ctx = unset_throttled_flows_ctx { unset_all: true, _pad: [0; 7], now: 0 };
    let mut rf_ctx = remove_flows_ctx { gc_only: false, _pad: [0; 3], reset_cnt: 0, reset_max: NUM_QUEUE };
    let mut sflow: *mut fq_stashed_flow = null_mut();
    let hash: u64 = 0;

    unsafe {
        *sch_qlen_ptr(sch) = 0;
        *sch_backlog_ptr(sch) = 0;

        bpf_for_each_map_elem(addr_of!(fq_nonprio_flows).cast::<c_void>(), fq_remove_flows, &mut rf_ctx, 0);

        rf_ctx.reset_cnt = 0;
        bpf_for_each_map_elem(addr_of!(fq_prio_flows).cast::<c_void>(), fq_remove_flows, &mut rf_ctx, 0);
        fq_new_flow(addr_of!(fq_prio_flows).cast(), &mut sflow, hash);

        bpf_loop(NUM_QUEUE, fq_remove_flows_in_list, null_mut(), 0);
        q.new_flow_cnt = 0;
        q.old_flow_cnt = 0;

        bpf_loop(NUM_QUEUE, fq_unset_throttled_flows, &mut utf_ctx, 0);
    }
}

#[link_section = "struct_ops/bpf_fq_init"]
#[no_mangle]
extern "C" fn bpf_fq_init(ctx: *const u64) -> i32 {
    let sch = fentry_arg(ctx, 0) as *mut Qdisc;
    let mut sflow: *mut fq_stashed_flow = null_mut();
    let hash: u64 = 0;

    unsafe {
        let dev = dq_dev(sch_dev_queue(sch));
        let psched_mtu: u32 = dev_mtu(dev).wrapping_add(dev_hard_header_len(dev) as u32);

        if fq_new_flow(addr_of!(fq_prio_flows).cast(), &mut sflow, hash) < 0 {
            return -ENOMEM;
        }

        *sch_limit_ptr(sch) = 10000;
        q.initial_quantum = 10u32.wrapping_mul(psched_mtu);
        q.quantum = 2u32.wrapping_mul(psched_mtu);
        q.flow_refill_delay = 40;
        q.flow_plimit = 100;
        q.horizon = 10 * NSEC_PER_SEC;
        q.horizon_drop = 1;
        q.orphan_mask = 1024 - 1;
        q.timer_slack = (10 * NSEC_PER_USEC) as u32;
        q.time_next_delayed_flow = !0u64;
        q.unthrottle_latency_ns = 0;
        q.new_flow_cnt = 0;
        q.old_flow_cnt = 0;
    }

    0
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_fq_destroy(_ctx: *const u64) {}

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
static fq: Qdisc_ops = Qdisc_ops {
    enqueue: bpf_fq_enqueue,
    dequeue: bpf_fq_dequeue,
    init: bpf_fq_init,
    reset: bpf_fq_reset,
    destroy: bpf_fq_destroy,
    id: *b"bpf_fq\0\0\0\0\0\0\0\0\0\0",
};

btf_type_tags! {
    skb_node.skb: kptr;
    fq_stashed_flow.flow: kptr;
}

bpf_object!("GPL");
