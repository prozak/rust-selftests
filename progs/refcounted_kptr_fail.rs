// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/refcounted_kptr_fail.c
// (bpf-rs-core idiom).
//
// Every program but one is a verifier rejection test (prog_tests/
// refcounted_kptr.c: RUN_TESTS(refcounted_kptr_fail)); test_tags! mirrors
// the C __failure/__msg tags. The private(A)/private(B) statics are C
// `__hidden` variables in `.data.A`/`.data.B` (laid out as in the C object:
// glock 0, groot 8; lock 0, head 8), with the __contains decl tags through
// rust-bpf's #[btf_tag]. refcount_acquire_maybe_null
// passes bpf_obj_new()'s result to bpf_refcount_acquire() without a NULL
// check on purpose, refcount_acquire_non_object passes the context, and
// refcount_acquire_list_node_offset passes a pointer into the middle of the
// object; each is what the verifier rejects.

// BTF_TYPE_ID: node_acquire_id local struct node_acquire
// BTF_TYPE_ID: node_refcounted_id local struct node_refcounted
// BTF_TYPE_ID: node_refcount_only_id local struct node_refcount_only

use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_spin_lock, bpf_spin_unlock};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, btf_type_tags, test_tags};
use btf_macros::btf_tag;
use core::ffi::c_void;
use core::ptr::addr_of_mut;

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
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
#[repr(C, align(4))]
struct bpf_refcount {
    __opaque: [u32; 1],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct node_acquire {
    key: i64,
    data: i64,
    node: bpf_rb_node,
    refcount: bpf_refcount,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct node_refcounted {
    key: i64,
    list: bpf_list_node,
    refcount: bpf_refcount,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct node_refcount_only {
    key: i64,
    refcount: bpf_refcount,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_value_refcount_only {
    node: *mut node_refcount_only,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct rcu_graph_node {
    node: bpf_rb_node,
    data: i64,
}

// struct rcu_graph_node *just_here_because_btf_bug;
#[allow(non_upper_case_globals)]
#[no_mangle]
static mut just_here_because_btf_bug: *mut rcu_graph_node = core::ptr::null_mut();

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_value_rcu_graph {
    node: *mut rcu_graph_node,
}

#[allow(non_upper_case_globals)]
#[link_section = ".data.C"]
static mut graph_lock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:rcu_graph_node:node")]
#[link_section = ".data.C"]
static mut graph_root: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

#[link_section = ".maps"]
#[no_mangle]
static stashed_refcount_only: BpfMap<i32, map_value_refcount_only, { maps::ARRAY }, 1> =
    BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stashed_rcu_graph: BpfMap<i32, map_value_rcu_graph, { maps::ARRAY }, 1> = BpfMap::new();

btf_type_tags! {
    map_value_refcount_only.node: kptr;
    map_value_rcu_graph.node: kptr;
}

#[allow(non_upper_case_globals)]
#[link_section = ".data.A"]
static mut glock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_acquire:node")]
#[link_section = ".data.A"]
static mut groot: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

#[allow(non_upper_case_globals)]
#[link_section = ".data.B"]
static mut lock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:node_refcounted:list")]
#[link_section = ".data.B"]
static mut head: bpf_list_head = bpf_list_head { __opaque: [0; 2] };

extern "C" {
    fn node_acquire_id() -> u64;
    fn node_refcounted_id() -> u64;
    fn node_refcount_only_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);
    fn bpf_refcount_acquire(obj: *mut c_void) -> *mut c_void;
    fn bpf_rbtree_add(
        root: *mut bpf_rb_root,
        node: *mut bpf_rb_node,
        less: extern "C" fn(*mut bpf_rb_node, *const bpf_rb_node) -> bool,
    ) -> i32;
    fn bpf_list_push_front(head: *mut bpf_list_head, node: *mut bpf_list_node) -> i32;
    fn bpf_list_pop_front(head: *mut bpf_list_head) -> *mut bpf_list_node;
    fn bpf_rbtree_remove(root: *mut bpf_rb_root, node: *mut bpf_rb_node) -> *mut bpf_rb_node;
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
}

// container_of(ptr, struct node_acquire, node)
#[inline(always)]
unsafe fn entry(n: *mut bpf_rb_node) -> *mut node_acquire {
    (n as *mut u8).sub(core::mem::offset_of!(node_acquire, node)) as *mut node_acquire
}

// container_of(ptr, struct node_refcounted, list)
#[inline(always)]
unsafe fn entry_list(n: *mut bpf_list_node) -> *mut node_refcounted {
    (n as *mut u8).sub(core::mem::offset_of!(node_refcounted, list)) as *mut node_refcounted
}

extern "C" fn less(a: *mut bpf_rb_node, b: *const bpf_rb_node) -> bool {
    unsafe {
        let node_a = entry(a);
        let node_b = entry(b as *mut bpf_rb_node);

        (*node_a).key < (*node_b).key
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_refcounted_node_ref_escapes(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_acquire_id()) as *mut node_acquire;
        if n.is_null() {
            return 1;
        }

        bpf_spin_lock(addr_of_mut!(glock));
        bpf_rbtree_add(addr_of_mut!(groot), addr_of_mut!((*n).node), less);
        /* m becomes an owning ref but is never drop'd or added to a tree */
        let m = bpf_refcount_acquire(n.cast()) as *mut node_acquire;
        bpf_spin_unlock(addr_of_mut!(glock));
        if m.is_null() {
            return 2;
        }

        (*m).key = 2;
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn refcount_acquire_maybe_null(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_acquire_id()) as *mut node_acquire;
        /* Intentionally not testing !n
         * it's MAYBE_NULL for refcount_acquire
         */
        let m = bpf_refcount_acquire(n.cast()) as *mut node_acquire;
        if !m.is_null() {
            bpf_obj_drop(m.cast());
        }
        if !n.is_null() {
            bpf_obj_drop(n.cast());
        }

        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn refcount_acquire_non_object(ctx: *const c_void) -> i64 {
    unsafe { !bpf_refcount_acquire(ctx as *mut c_void).is_null() as i64 }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rbtree_refcounted_node_ref_escapes_owning_input(_ctx: *const c_void) -> i64 {
    unsafe {
        let n = bpf_obj_new(node_acquire_id()) as *mut node_acquire;
        if n.is_null() {
            return 1;
        }

        /* m becomes an owning ref but is never drop'd or added to a tree */
        let m = bpf_refcount_acquire(n.cast()) as *mut node_acquire;
        (*m).key = 2;

        bpf_spin_lock(addr_of_mut!(glock));
        bpf_rbtree_add(addr_of_mut!(groot), addr_of_mut!((*n).node), less);
        bpf_spin_unlock(addr_of_mut!(glock));

        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn refcount_acquire_list_node_offset(_ctx: *const c_void) -> i64 {
    unsafe {
        let node = bpf_obj_new(node_refcounted_id()) as *mut node_refcounted;
        if node.is_null() {
            return 1;
        }

        bpf_spin_lock(addr_of_mut!(lock));
        bpf_list_push_front(addr_of_mut!(head), addr_of_mut!((*node).list));
        let list_node = bpf_list_pop_front(addr_of_mut!(head));
        bpf_spin_unlock(addr_of_mut!(lock));
        if list_node.is_null() {
            return 2;
        }

        let base = entry_list(list_node);
        let r#ref = bpf_refcount_acquire(list_node.cast()) as *mut node_refcounted;
        if !r#ref.is_null() {
            bpf_obj_drop(r#ref.cast());
        }
        bpf_obj_drop(base.cast());
        0
    }
}

// BPF_PROG(rbtree_fail_sleepable_lock_across_rcu, struct file *file, ...):
// the arguments are unused, so the program takes the raw context.
#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn rbtree_fail_sleepable_lock_across_rcu(_ctx: *const c_void) -> i32 {
    unsafe {
        let n = bpf_obj_new(node_acquire_id()) as *mut node_acquire;
        if n.is_null() {
            return 0;
        }

        /* spin_{lock,unlock} are in different RCU CS */
        bpf_rcu_read_lock();
        bpf_spin_lock(addr_of_mut!(glock));
        bpf_rbtree_add(addr_of_mut!(groot), addr_of_mut!((*n).node), less);
        bpf_rcu_read_unlock();

        bpf_rcu_read_lock();
        bpf_spin_unlock(addr_of_mut!(glock));
        bpf_rcu_read_unlock();

        0
    }
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn refcount_acquire_rcu_map_kptr_unchecked_drop(_ctx: *const c_void) -> i64 {
    let idx: i32 = 0;
    unsafe {
        /* Force Clang to emit complete BTF for struct node_refcount_only. */
        let tmp = bpf_obj_new(node_refcount_only_id()) as *mut node_refcount_only;
        if tmp.is_null() {
            return 3;
        }
        bpf_obj_drop(tmp.cast());

        let mapval = bpf_map_lookup_elem(&stashed_refcount_only, &idx)
            as *mut map_value_refcount_only;
        if mapval.is_null() {
            return 1;
        }

        bpf_rcu_read_lock();
        let n = (*mapval).node;
        if n.is_null() {
            bpf_rcu_read_unlock();
            return 2;
        }
        let m = bpf_refcount_acquire(n.cast()) as *mut node_refcount_only;
        bpf_rcu_read_unlock();

        bpf_obj_drop(m.cast());
    }
    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn rbtree_remove_after_rcu_unlock(_ctx: *const c_void) -> i64 {
    let idx: i32 = 0;
    unsafe {
        let mapval = bpf_map_lookup_elem(&stashed_rcu_graph, &idx) as *mut map_value_rcu_graph;
        if mapval.is_null() {
            return 0;
        }

        bpf_rcu_read_lock();
        let node = (*mapval).node;
        if node.is_null() {
            bpf_rcu_read_unlock();
            return 0;
        }
        bpf_rcu_read_unlock();

        bpf_spin_lock(addr_of_mut!(graph_lock));
        let rb_node = bpf_rbtree_remove(addr_of_mut!(graph_root), addr_of_mut!((*node).node));
        bpf_spin_unlock(addr_of_mut!(graph_lock));
        if !rb_node.is_null() {
            // container_of(rb_node, struct rcu_graph_node, node)
            bpf_obj_drop(
                (rb_node as *mut u8).sub(core::mem::offset_of!(rcu_graph_node, node)).cast(),
            );
        }
    }
    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn refcount_acquire_after_rcu_unlock(_ctx: *const c_void) -> i64 {
    let idx: i32 = 0;
    unsafe {
        let mapval = bpf_map_lookup_elem(&stashed_refcount_only, &idx)
            as *mut map_value_refcount_only;
        if mapval.is_null() {
            return 0;
        }

        bpf_rcu_read_lock();
        let node = (*mapval).node;
        if node.is_null() {
            bpf_rcu_read_unlock();
            return 0;
        }
        bpf_rcu_read_unlock();

        let r#ref = bpf_refcount_acquire(node.cast()) as *mut node_refcount_only;
        if !r#ref.is_null() {
            bpf_obj_drop(r#ref.cast());
        }
    }
    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn graph_kptr_after_spin_unlock(_ctx: *const c_void) -> i64 {
    let idx: i32 = 0;
    unsafe {
        let mapval = bpf_map_lookup_elem(&stashed_rcu_graph, &idx) as *mut map_value_rcu_graph;
        if mapval.is_null() {
            return 0;
        }

        bpf_spin_lock(addr_of_mut!(graph_lock));
        let node = (*mapval).node;
        if node.is_null() {
            bpf_spin_unlock(addr_of_mut!(graph_lock));
            return 0;
        }
        bpf_spin_unlock(addr_of_mut!(graph_lock));

        (*node).data
    }
}

test_tags! {
    rbtree_refcounted_node_ref_escapes: __failure, __msg("Unreleased reference id=4 alloc_insn={{[0-9]+}}");
    refcount_acquire_maybe_null: __failure, __msg("Possibly NULL pointer passed to trusted R1"), __msg("requires a non-NULL value of type (void *)");
    refcount_acquire_non_object: __failure, __msg("R1 type=ctx expected=ptr_, rcu_ptr_, ptr_, rcu_ptr_"), __msg("type ctx, but this argument accepts ptr_, rcu_ptr_, ptr_, rcu_ptr_");
    rbtree_refcounted_node_ref_escapes_owning_input: __failure, __msg("Unreleased reference id=3 alloc_insn={{[0-9]+}}");
    refcount_acquire_list_node_offset: __failure, __msg("dereference of modified ptr_ ptr R1");
    rbtree_fail_sleepable_lock_across_rcu: __failure, __msg("function calls are not allowed while holding a lock");
    refcount_acquire_rcu_map_kptr_unchecked_drop: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    rbtree_remove_after_rcu_unlock: __failure, __msg("R2 type=untrusted_ptr_ expected=ptr_, rcu_ptr_, ptr_, rcu_ptr_");
    refcount_acquire_after_rcu_unlock: __failure, __msg("R1 type=untrusted_ptr_ expected=ptr_, rcu_ptr_, ptr_, rcu_ptr_");
    graph_kptr_after_spin_unlock: __failure, __msg("invalid mem access 'scalar'");
}

bpf_object!("GPL");
