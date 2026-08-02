#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/rbtree_btf_fail__wrong_node_type.c
// (bpf-rs-core idiom).
//
// This is a BTF-fail test: the C source deliberately makes `groot`
// (a `bpf_rb_root`) `__contains(node_data, node)` while `node_data.node`
// is declared as `bpf_list_node` instead of `bpf_rb_node`. The kernel's
// btf_find_graph_root() (kernel/bpf/btf.c) resolves the "contains:" BTF
// decl tag and rejects load if the referenced field isn't a graph node of
// the matching kind — the C comment says "BTF load should fail".
//
// rustc/LLVM cannot emit BTF_KIND_DECL_TAG at all (no clang
// __attribute__((btf_decl_tag)) equivalent in the pipeline), so `groot`
// reaches the kernel with no "contains:" tag whatsoever. btf_find_graph_root()
// treats a missing tag the same as a mismatched one (btf_find_decl_tag_value()
// returns -ENOENT, folded to -EINVAL) — so the object's own BTF blob is
// rejected during load, which is exactly the failure this test asserts via
// `ASSERT_ERR_PTR(skel, "...__open_and_load unexpected success")`. The
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
struct bpf_list_node {
    __opaque: [u64; 3],
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

// BTF load should fail as bpf_rb_root __contains this type and points to
// 'node', but 'node' is not a bpf_rb_node.
#[repr(C)]
struct node_data {
    key: i32,
    data: i32,
    node: bpf_list_node,
}

#[link_section = ".data.A"]
#[no_mangle]
static mut glock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[link_section = ".data.A"]
#[no_mangle]
static mut groot: bpf_rb_root = bpf_rb_root { __opaque: [0; 2] };

extern "C" {
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_rbtree_first(root: *mut bpf_rb_root) -> *mut bpf_rb_node;
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn rbtree_api_add__wrong_node_type(_ctx: *const c_void) -> i64 {
    let n = unsafe { bpf_obj_new(0) } as *mut node_data;
    if n.is_null() {
        return 1;
    }

    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!(glock));
        bpf_rbtree_first(core::ptr::addr_of_mut!(groot));
        bpf_spin_unlock(core::ptr::addr_of_mut!(glock));
    }

    0
}

bpf_object!("GPL");
