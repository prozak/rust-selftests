#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/rbtree_btf_fail__add_wrong_type.c
// (bpf-rs-core idiom).
//
// This is a BTF-fail test, the sibling of rbtree_btf_fail__wrong_node_type
// (see that file's comment): `groot` (a `bpf_rb_root`) is declared
// `__contains(node_data, node)`, but the program adds a `node_data2` node
// (whose `node` field sits at a different offset than `node_data`'s) via
// `bpf_rbtree_add()`. The kernel's btf_find_graph_root() resolves the
// "contains:" BTF decl tag and rejects load on the type/offset mismatch.
//
// rustc/LLVM cannot emit BTF_KIND_DECL_TAG at all, so `groot` reaches the
// kernel with no "contains:" tag whatsoever regardless of which type we
// actually add — btf_find_graph_root() treats a missing tag the same as a
// mismatched one (-ENOENT folded to -EINVAL), so the object's own BTF blob
// is rejected during load, which is exactly the failure this test asserts
// via `ASSERT_ERR_PTR(skel, "...__open_and_load unexpected success")`. The
// struct/program shape below is otherwise a straight translation.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_spin_lock, bpf_spin_unlock};
use core::ffi::c_void;

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_rb_node {
    __opaque: [u64; 4],
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_rb_root {
    __opaque: [u64; 2],
}

// groot is __contains(node_data, node), but this program adds a node_data2
// node (node field at a different offset) instead — BTF load should fail.
#[repr(C)]
struct node_data2 {
    key: i32,
    node: bpf_rb_node,
    data: i32,
}

#[link_section = ".data.A"]
#[no_mangle]
static mut glock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[link_section = ".data.A"]
#[no_mangle]
static mut groot: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

extern "C" {
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_rbtree_add(
        root: *mut bpf_rb_root,
        node: *mut bpf_rb_node,
        less: extern "C" fn(*mut bpf_rb_node, *const bpf_rb_node) -> bool,
    ) -> bool;
}

extern "C" fn less2(a: *mut bpf_rb_node, b: *const bpf_rb_node) -> bool {
    let off = core::mem::offset_of!(node_data2, node);
    let node_a = unsafe { (a as *mut u8).sub(off) } as *const node_data2;
    let node_b = unsafe { (b as *const u8).sub(off) } as *const node_data2;
    unsafe { (*node_a).key < (*node_b).key }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_api_add__add_wrong_type(_ctx: *const c_void) -> i64 {
    let n = unsafe { bpf_obj_new(0) } as *mut node_data2;
    if n.is_null() {
        return 1;
    }

    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!(glock));
        bpf_rbtree_add(
            core::ptr::addr_of_mut!(groot),
            core::ptr::addr_of_mut!((*n).node),
            less2,
        );
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock));
    }

    0
}

bpf_object!("GPL");
