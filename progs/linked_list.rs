// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/linked_list.c
// (+ linked_list.h), bpf-rs-core idiom.
//
// glock/ghead (private(A)), glock2 (B), glock_c/ghead_array/ghead_array_one
// (C) and ghead_nested (D) are C `__hidden` statics in SEC(".bss.X"), so
// BTF_VAR_STATIC and the maps are not mmapped by libbpf. A private Rust
// static (no #[no_mangle]) gets the same linkage (see test_spin_lock.rs);
// rust-bpf's #[btf_tag] still finds it by its debug-info name and puts C's
// __contains(foo, node2) decl tag on it, on the array statics too, and on
// foo.head / map_value.head / head_nested_inner.head as member tags.
// bpf_obj_new() takes foo's and bar's local type ids like C's
// bpf_obj_new(typeof(*f)). The C helpers are __always_inline; so are these.

// BTF_TYPE_ID: foo_id local struct foo
// BTF_TYPE_ID: bar_id local struct bar

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_spin_lock, bpf_spin_unlock};
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
struct bar {
    node: bpf_list_node,
    data: i32,
}

#[allow(non_camel_case_types)]
#[btf_tag]
#[repr(C)]
struct foo {
    node: bpf_list_node,
    #[btf_tag(decl_tag = "contains:bar:node")]
    head: bpf_list_head,
    lock: bpf_spin_lock,
    data: i32,
    node2: bpf_list_node,
}

#[allow(non_camel_case_types)]
#[btf_tag]
#[repr(C)]
struct map_value {
    lock: bpf_spin_lock,
    data: i32,
    #[btf_tag(decl_tag = "contains:foo:node2")]
    head: bpf_list_head,
}

// struct array_map { __uint(type, ARRAY); __type(key, int);
// __type(value, struct map_value); __uint(max_entries, 1); }
#[allow(non_camel_case_types)]
#[repr(C)]
struct array_map {
    r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY
    key: *const i32,
    value: *const map_value,
    max_entries: *const [i32; 1],
}
unsafe impl Sync for array_map {}

#[link_section = ".maps"]
#[no_mangle]
static array_map: array_map = array_map {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
};

#[link_section = ".maps"]
#[no_mangle]
static inner_map: array_map = array_map {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
};

// struct { __uint(type, ARRAY_OF_MAPS); __uint(max_entries, 1);
// __type(key, int); __type(value, int); __array(values, struct array_map);
// } map_of_maps = { .values = { [0] = &inner_map } };
//
// `[T; 1]` emits the slot storage and its .rel.maps entry;
// scripts/btf_map_slots.py rewrites the BTF member to the zero-length array
// libbpf demands.
#[allow(non_camel_case_types)]
#[repr(C)]
struct map_of_maps_def {
    r#type: *const [i32; 12], // BPF_MAP_TYPE_ARRAY_OF_MAPS
    max_entries: *const [i32; 1],
    key: *const i32,
    value: *const i32,
    values: [*const array_map; 1],
}
unsafe impl Sync for map_of_maps_def {}

#[link_section = ".maps"]
#[no_mangle]
static map_of_maps: map_of_maps_def = map_of_maps_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [&inner_map],
};

#[allow(non_upper_case_globals)]
#[link_section = ".bss.A"]
static mut glock: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:foo:node2")]
#[link_section = ".bss.A"]
static mut ghead: bpf_list_head = bpf_list_head { __opaque: [0; 2] };

// linked_list.h declares glock2 and nothing in linked_list.c uses it, so
// the C object carries a .bss.B map holding only this lock. rustc drops an
// unreferenced private static (#[used] would make it a global variable,
// and libbpf's mmap of a lock-only map fails with -ENOTSUPP), so the Rust
// object has no .bss.B; no program or test touches it.
// translint: allow(private-layout)
#[allow(non_upper_case_globals, dead_code)]
#[link_section = ".bss.B"]
static mut glock2: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_camel_case_types)]
#[btf_tag]
#[repr(C)]
struct head_nested_inner {
    lock: bpf_spin_lock,
    #[btf_tag(decl_tag = "contains:foo:node2")]
    head: bpf_list_head,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct head_nested {
    dummy: i32,
    inner: head_nested_inner,
}

#[allow(non_upper_case_globals)]
#[link_section = ".bss.C"]
static mut glock_c: bpf_spin_lock = bpf_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:foo:node2")]
#[link_section = ".bss.C"]
static mut ghead_array: [bpf_list_head; 2] =
    [bpf_list_head { __opaque: [0; 2] }, bpf_list_head { __opaque: [0; 2] }];

#[allow(non_upper_case_globals)]
#[btf_tag(decl_tag = "contains:foo:node2")]
#[link_section = ".bss.C"]
static mut ghead_array_one: [bpf_list_head; 1] = [bpf_list_head { __opaque: [0; 2] }];

#[allow(non_upper_case_globals)]
#[link_section = ".bss.D"]
static mut ghead_nested: head_nested = head_nested {
    dummy: 0,
    inner: head_nested_inner {
        lock: bpf_spin_lock { val: 0 },
        head: bpf_list_head { __opaque: [0; 2] },
    },
};

extern "C" {
    fn foo_id() -> u64;
    fn bar_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);
    fn bpf_list_push_front(head: *mut bpf_list_head, node: *mut bpf_list_node) -> i32;
    fn bpf_list_push_back(head: *mut bpf_list_head, node: *mut bpf_list_node) -> i32;
    fn bpf_list_pop_front(head: *mut bpf_list_head) -> *mut bpf_list_node;
    fn bpf_list_pop_back(head: *mut bpf_list_head) -> *mut bpf_list_node;
}

// container_of(n, struct foo, node2) / container_of(n, struct bar, node)
#[inline(always)]
unsafe fn foo_of(n: *mut bpf_list_node) -> *mut foo {
    (n as *mut u8).sub(core::mem::offset_of!(foo, node2)) as *mut foo
}

#[inline(always)]
unsafe fn bar_of(n: *mut bpf_list_node) -> *mut bar {
    (n as *mut u8).sub(core::mem::offset_of!(bar, node)) as *mut bar
}

#[inline(always)]
unsafe fn list_push_pop(lock: *mut bpf_spin_lock, head: *mut bpf_list_head, leave_in_map: bool) -> i32 {
    let f = bpf_obj_new(foo_id()) as *mut foo;
    if f.is_null() {
        return 2;
    }

    bpf_spin_lock(lock);
    let n = bpf_list_pop_front(head);
    bpf_spin_unlock(lock);
    if !n.is_null() {
        bpf_obj_drop(foo_of(n).cast());
        bpf_obj_drop(f.cast());
        return 3;
    }

    bpf_spin_lock(lock);
    let n = bpf_list_pop_back(head);
    bpf_spin_unlock(lock);
    if !n.is_null() {
        bpf_obj_drop(foo_of(n).cast());
        bpf_obj_drop(f.cast());
        return 4;
    }

    bpf_spin_lock(lock);
    (*f).data = 42;
    bpf_list_push_front(head, addr_of_mut!((*f).node2));
    bpf_spin_unlock(lock);
    if leave_in_map {
        return 0;
    }
    bpf_spin_lock(lock);
    let n = bpf_list_pop_back(head);
    bpf_spin_unlock(lock);
    if n.is_null() {
        return 5;
    }
    let f = foo_of(n);
    if (*f).data != 42 {
        bpf_obj_drop(f.cast());
        return 6;
    }

    bpf_spin_lock(lock);
    (*f).data = 13;
    bpf_list_push_front(head, addr_of_mut!((*f).node2));
    bpf_spin_unlock(lock);
    bpf_spin_lock(lock);
    let n = bpf_list_pop_front(head);
    bpf_spin_unlock(lock);
    if n.is_null() {
        return 7;
    }
    let f = foo_of(n);
    if (*f).data != 13 {
        bpf_obj_drop(f.cast());
        return 8;
    }
    bpf_obj_drop(f.cast());

    bpf_spin_lock(lock);
    let n = bpf_list_pop_front(head);
    bpf_spin_unlock(lock);
    if !n.is_null() {
        bpf_obj_drop(foo_of(n).cast());
        return 9;
    }

    bpf_spin_lock(lock);
    let n = bpf_list_pop_back(head);
    bpf_spin_unlock(lock);
    if !n.is_null() {
        bpf_obj_drop(foo_of(n).cast());
        return 10;
    }
    0
}

const NR_MULTIPLE: usize = 200;

#[inline(always)]
unsafe fn list_push_pop_multiple(
    lock: *mut bpf_spin_lock,
    head: *mut bpf_list_head,
    leave_in_map: bool,
) -> i32 {
    let mut f: [*mut foo; NR_MULTIPLE] = [core::ptr::null_mut(); NR_MULTIPLE];

    // Loop following this check adds nodes 2-at-a-time in order to
    // validate multiple release_on_unlock release logic
    if NR_MULTIPLE % 2 != 0 {
        return 10;
    }

    let mut i: usize = 0;
    while i < NR_MULTIPLE {
        let fi = bpf_obj_new(foo_id()) as *mut foo;
        *f.get_unchecked_mut(i) = fi;
        if fi.is_null() {
            return 2;
        }
        (*fi).data = i as i32;

        let fi1 = bpf_obj_new(foo_id()) as *mut foo;
        *f.get_unchecked_mut(i + 1) = fi1;
        if fi1.is_null() {
            bpf_obj_drop(fi.cast());
            return 9;
        }
        (*fi1).data = (i + 1) as i32;

        bpf_spin_lock(lock);
        bpf_list_push_front(head, addr_of_mut!((*fi).node2));
        bpf_list_push_front(head, addr_of_mut!((*fi1).node2));
        bpf_spin_unlock(lock);
        i += 2;
    }

    let mut i: usize = 0;
    while i < NR_MULTIPLE {
        bpf_spin_lock(lock);
        let n = bpf_list_pop_front(head);
        bpf_spin_unlock(lock);
        if n.is_null() {
            return 3;
        }
        let pf = foo_of(n);
        if (*pf).data != (NR_MULTIPLE - i - 1) as i32 {
            bpf_obj_drop(pf.cast());
            return 4;
        }
        bpf_spin_lock(lock);
        bpf_list_push_back(head, addr_of_mut!((*pf).node2));
        bpf_spin_unlock(lock);
        i += 1;
    }

    if leave_in_map {
        return 0;
    }

    let mut i: usize = 0;
    while i < NR_MULTIPLE {
        bpf_spin_lock(lock);
        let n = bpf_list_pop_back(head);
        bpf_spin_unlock(lock);
        if n.is_null() {
            return 5;
        }
        let pf = foo_of(n);
        if (*pf).data != i as i32 {
            bpf_obj_drop(pf.cast());
            return 6;
        }
        bpf_obj_drop(pf.cast());
        i += 1;
    }
    bpf_spin_lock(lock);
    let n = bpf_list_pop_back(head);
    bpf_spin_unlock(lock);
    if !n.is_null() {
        bpf_obj_drop(foo_of(n).cast());
        return 7;
    }

    bpf_spin_lock(lock);
    let n = bpf_list_pop_front(head);
    bpf_spin_unlock(lock);
    if !n.is_null() {
        bpf_obj_drop(foo_of(n).cast());
        return 8;
    }
    0
}

const NR_BA: i32 = 8;

#[inline(always)]
unsafe fn list_in_list(lock: *mut bpf_spin_lock, head: *mut bpf_list_head, leave_in_map: bool) -> i32 {
    let f = bpf_obj_new(foo_id()) as *mut foo;
    if f.is_null() {
        return 2;
    }
    let mut i: i32 = 0;
    while i < NR_BA {
        let b = bpf_obj_new(bar_id()) as *mut bar;
        if b.is_null() {
            bpf_obj_drop(f.cast());
            return 3;
        }
        (*b).data = i;
        bpf_spin_lock(addr_of_mut!((*f).lock));
        bpf_list_push_back(addr_of_mut!((*f).head), addr_of_mut!((*b).node));
        bpf_spin_unlock(addr_of_mut!((*f).lock));
        i += 1;
    }

    bpf_spin_lock(lock);
    (*f).data = 42;
    bpf_list_push_front(head, addr_of_mut!((*f).node2));
    bpf_spin_unlock(lock);

    if leave_in_map {
        return 0;
    }

    bpf_spin_lock(lock);
    let n = bpf_list_pop_front(head);
    bpf_spin_unlock(lock);
    if n.is_null() {
        return 4;
    }
    let f = foo_of(n);
    if (*f).data != 42 {
        bpf_obj_drop(f.cast());
        return 5;
    }

    let mut i: i32 = 0;
    while i < NR_BA {
        bpf_spin_lock(addr_of_mut!((*f).lock));
        let n = bpf_list_pop_front(addr_of_mut!((*f).head));
        bpf_spin_unlock(addr_of_mut!((*f).lock));
        if n.is_null() {
            bpf_obj_drop(f.cast());
            return 6;
        }
        let b = bar_of(n);
        if (*b).data != i {
            bpf_obj_drop(f.cast());
            bpf_obj_drop(b.cast());
            return 7;
        }
        bpf_obj_drop(b.cast());
        i += 1;
    }
    bpf_spin_lock(addr_of_mut!((*f).lock));
    let n = bpf_list_pop_front(addr_of_mut!((*f).head));
    bpf_spin_unlock(addr_of_mut!((*f).lock));
    if !n.is_null() {
        bpf_obj_drop(f.cast());
        bpf_obj_drop(bar_of(n).cast());
        return 8;
    }
    bpf_obj_drop(f.cast());
    0
}

#[inline(always)]
unsafe fn test_list_push_pop(lock: *mut bpf_spin_lock, head: *mut bpf_list_head) -> i32 {
    let ret = list_push_pop(lock, head, false);
    if ret != 0 {
        return ret;
    }
    list_push_pop(lock, head, true)
}

#[inline(always)]
unsafe fn test_list_push_pop_multiple(lock: *mut bpf_spin_lock, head: *mut bpf_list_head) -> i32 {
    let ret = list_push_pop_multiple(lock, head, false);
    if ret != 0 {
        return ret;
    }
    list_push_pop_multiple(lock, head, true)
}

#[inline(always)]
unsafe fn test_list_in_list(lock: *mut bpf_spin_lock, head: *mut bpf_list_head) -> i32 {
    let ret = list_in_list(lock, head, false);
    if ret != 0 {
        return ret;
    }
    list_in_list(lock, head, true)
}

const MAX_LIST_CLEAR_NODES: i32 = 256;

#[inline(always)]
unsafe fn clear_list(lock: *mut bpf_spin_lock, head: *mut bpf_list_head) -> i32 {
    let mut i: i32 = 0;
    while i < MAX_LIST_CLEAR_NODES {
        bpf_spin_lock(lock);
        let n = bpf_list_pop_front(head);
        bpf_spin_unlock(lock);
        if n.is_null() {
            return 0;
        }
        bpf_obj_drop(foo_of(n).cast());
        i += 1;
    }
    1
}

#[inline(always)]
unsafe fn inner_map_value() -> *mut map_value {
    let zero: i32 = 0;
    let map = bpf_map_lookup_elem(&map_of_maps, &zero);
    if map.is_null() {
        return core::ptr::null_mut();
    }
    let zero: i32 = 0;
    bpf_map_lookup_elem(map, &zero) as *mut map_value
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn clear_map_list(_ctx: *const c_void) -> i32 {
    let zero: i32 = 0;
    let v = bpf_map_lookup_elem(&array_map, &zero) as *mut map_value;
    if v.is_null() {
        return 1;
    }
    unsafe { clear_list(addr_of_mut!((*v).lock), addr_of_mut!((*v).head)) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn clear_inner_map_list(_ctx: *const c_void) -> i32 {
    unsafe {
        let v = inner_map_value();
        if v.is_null() {
            return 1;
        }
        clear_list(addr_of_mut!((*v).lock), addr_of_mut!((*v).head))
    }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn clear_global_list(_ctx: *const c_void) -> i32 {
    unsafe { clear_list(addr_of_mut!(glock), addr_of_mut!(ghead)) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn clear_global_nested_list(_ctx: *const c_void) -> i32 {
    unsafe { clear_list(addr_of_mut!(ghead_nested.inner.lock), addr_of_mut!(ghead_nested.inner.head)) }
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn clear_global_array_list(_ctx: *const c_void) -> i32 {
    unsafe {
        let ret = clear_list(addr_of_mut!(glock_c), addr_of_mut!(ghead_array[0]));
        if ret != 0 {
            return ret;
        }
        let ret = clear_list(addr_of_mut!(glock_c), addr_of_mut!(ghead_array[1]));
        if ret != 0 {
            return ret;
        }
        clear_list(addr_of_mut!(glock_c), addr_of_mut!(ghead_array_one[0]))
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn map_list_push_pop(_ctx: *const c_void) -> i32 {
    let zero: i32 = 0;
    let v = bpf_map_lookup_elem(&array_map, &zero) as *mut map_value;
    if v.is_null() {
        return 1;
    }
    unsafe { test_list_push_pop(addr_of_mut!((*v).lock), addr_of_mut!((*v).head)) }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn inner_map_list_push_pop(_ctx: *const c_void) -> i32 {
    unsafe {
        let v = inner_map_value();
        if v.is_null() {
            return 1;
        }
        test_list_push_pop(addr_of_mut!((*v).lock), addr_of_mut!((*v).head))
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn global_list_push_pop(_ctx: *const c_void) -> i32 {
    unsafe { test_list_push_pop(addr_of_mut!(glock), addr_of_mut!(ghead)) }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn global_list_push_pop_nested(_ctx: *const c_void) -> i32 {
    unsafe { test_list_push_pop(addr_of_mut!(ghead_nested.inner.lock), addr_of_mut!(ghead_nested.inner.head)) }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn global_list_array_push_pop(_ctx: *const c_void) -> i32 {
    unsafe {
        let r = test_list_push_pop(addr_of_mut!(glock_c), addr_of_mut!(ghead_array[0]));
        if r != 0 {
            return r;
        }

        let r = test_list_push_pop(addr_of_mut!(glock_c), addr_of_mut!(ghead_array[1]));
        if r != 0 {
            return r;
        }

        // Arrays with only one element is a special case, being treated
        // just like a bpf_list_head variable by the verifier, not an array.
        test_list_push_pop(addr_of_mut!(glock_c), addr_of_mut!(ghead_array_one[0]))
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn map_list_push_pop_multiple(_ctx: *const c_void) -> i32 {
    let zero: i32 = 0;
    let v = bpf_map_lookup_elem(&array_map, &zero) as *mut map_value;
    if v.is_null() {
        return 1;
    }
    unsafe { test_list_push_pop_multiple(addr_of_mut!((*v).lock), addr_of_mut!((*v).head)) }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn inner_map_list_push_pop_multiple(_ctx: *const c_void) -> i32 {
    unsafe {
        let v = inner_map_value();
        if v.is_null() {
            return 1;
        }
        test_list_push_pop_multiple(addr_of_mut!((*v).lock), addr_of_mut!((*v).head))
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn global_list_push_pop_multiple(_ctx: *const c_void) -> i32 {
    unsafe {
        let ret = list_push_pop_multiple(addr_of_mut!(glock), addr_of_mut!(ghead), false);
        if ret != 0 {
            return ret;
        }
        list_push_pop_multiple(addr_of_mut!(glock), addr_of_mut!(ghead), true)
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn map_list_in_list(_ctx: *const c_void) -> i32 {
    let zero: i32 = 0;
    let v = bpf_map_lookup_elem(&array_map, &zero) as *mut map_value;
    if v.is_null() {
        return 1;
    }
    unsafe { test_list_in_list(addr_of_mut!((*v).lock), addr_of_mut!((*v).head)) }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn inner_map_list_in_list(_ctx: *const c_void) -> i32 {
    unsafe {
        let v = inner_map_value();
        if v.is_null() {
            return 1;
        }
        test_list_in_list(addr_of_mut!((*v).lock), addr_of_mut!((*v).head))
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn global_list_in_list(_ctx: *const c_void) -> i32 {
    unsafe { test_list_in_list(addr_of_mut!(glock), addr_of_mut!(ghead)) }
}

bpf_object!("GPL");
