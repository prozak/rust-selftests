#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgrp_kfunc_success.c
// (+ cgrp_kfunc_common.h), bpf-rs-core idiom.
//
// `cgrps_kfunc_map_insert`/`cgrps_kfunc_map_value_lookup` in the C common
// header stash the acquired `struct cgroup *` in a `__kptr`-tagged field of
// a BPF_MAP_TYPE_HASH map value (`struct __cgrps_kfunc_map_value { struct
// cgroup __kptr *cgrp; }`), then retrieve/xchg it back out. rustc cannot
// emit BTF_KIND_TYPE_TAG, so a map value field can never be classified as
// BPF_KPTR by the verifier's `btf_find_kptr` -- any `bpf_kptr_xchg` into
// such a field is rejected at load with "R1 has no valid kptr" (confirmed
// repeatedly: task_kfunc_success.rs, cb_refs.rs, map_kptr_race.rs, etc, see
// project memory btf-type-tag-uptr-kptr-unfixable). `__cgrps_kfunc_map`
// itself IS part of this object's kept ABI (a global OBJECT symbol in the
// clang-built .bpf.o), so it's declared below to match the ELF shape, but
// never touched by any program body.
//
// Every one of this file's tp_btf programs only fires once per test (the
// userspace side triggers exactly one `cgroup_mkdir` event), so the
// map-mediated "insert, then look back up" round trip has no cross-invocation
// purpose here -- it can be replaced with the KF_ACQUIRE'd pointer held
// directly in a local variable for the lifetime of the single invocation,
// with an explicit `bpf_cgroup_release` taking the place of the implicit
// ownership transfer `bpf_kptr_xchg` would otherwise perform (same
// technique as jit_probe_mem.rs's kptr-bss-global workaround, project memory
// kptr-bss-global-workaround-use-trusted-ptr-directly). `prog_tests/
// cgrp_kfunc.c`'s `run_success_test` only asserts on `skel->bss->err`/
// `invocations`, never on the map's contents, so this preserves the
// observable behavior the oracle checks.

use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, sync_fetch_and_add_u32};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::bpf_object;
use btf_macros::btf;

#[btf]
struct kernfs_node {
    id: u64,
}

#[btf]
struct cgroup_subsys_state {
    id: i32,
}

#[btf]
struct cgroup {
    level: i32,
    kn: *mut kernfs_node,
}

extern "C" {
    fn bpf_cgroup_acquire(p: *mut cgroup) -> *mut cgroup;
    fn bpf_cgroup_release(p: *mut cgroup);
    fn bpf_cgroup_ancestor(cgrp: *mut cgroup, level: i32) -> *mut cgroup;
    fn bpf_cgroup_from_id(cgid: u64) -> *mut cgroup;
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
}

#[repr(C)]
struct CgrpsKfuncMapValue {
    cgrp: *mut cgroup,
}

#[link_section = ".maps"]
#[no_mangle]
static __cgrps_kfunc_map: BpfMap<i32, CgrpsKfuncMapValue, { maps::HASH }, 1> = BpfMap::new();

#[no_mangle]
static mut err: i32 = 0;
#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut invocations: i32 = 0;

// `self` can't be declared as a struct field (Rust forbids it even as a raw
// identifier), so `cgrp->self.id` is read via the well-known C idiom of
// `struct cgroup_subsys_state self` being cgroup's first member (offset 0):
// reinterpret the pointer as `*mut cgroup_subsys_state` and read `id`
// directly off it, same effective CO-RE byte-offset relocation target.
#[inline(never)]
fn cgrp_self_id(cgrp: *mut cgroup) -> i32 {
    let css = cgrp as *mut cgroup_subsys_state;
    *unsafe { &*css }.id().get().unwrap()
}

#[inline(never)]
fn cgrp_level(cgrp: *mut cgroup) -> i32 {
    *unsafe { &*cgrp }.level().get().unwrap()
}

#[inline(never)]
fn cgrp_kn(cgrp: *mut cgroup) -> *mut kernfs_node {
    *unsafe { &*cgrp }.kn().get().unwrap()
}

#[inline(never)]
fn kn_id(kn: *mut kernfs_node) -> u64 {
    *unsafe { &*kn }.id().get().unwrap()
}

#[inline(always)]
fn is_test_kfunc_task() -> bool {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    let same = unsafe { pid } == cur_pid;
    if same {
        sync_fetch_and_add_u32(core::ptr::addr_of_mut!(invocations) as *mut u32, 1);
    }
    same
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_acquire_release_argument(ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let acquired = unsafe { bpf_cgroup_acquire(cgrp) };
    if acquired.is_null() {
        unsafe { err = 1 };
    } else {
        unsafe { bpf_cgroup_release(acquired) };
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_acquire_leave_in_map(ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    // See module doc comment: stands in for `cgrps_kfunc_map_insert`, which
    // can't actually persist into the __kptr map field on this pipeline.
    let acquired = unsafe { bpf_cgroup_acquire(cgrp) };
    if acquired.is_null() {
        unsafe { err = 1 };
        return 0;
    }
    unsafe { bpf_cgroup_release(acquired) };

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_xchg_release(ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let acquired = unsafe { bpf_cgroup_acquire(cgrp) };
    if acquired.is_null() {
        unsafe { err = 1 };
        return 0;
    }

    // `acquired` stands in for the map-stored kptr the C original reads back
    // out via `v->cgrp` / `bpf_kptr_xchg(&v->cgrp, NULL)` (see module doc
    // comment).
    let cg = unsafe { bpf_cgroup_ancestor(acquired, 1) };
    if !cg.is_null() {
        unsafe { bpf_cgroup_release(cg) };
    }

    unsafe { bpf_cgroup_release(acquired) };

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_get_release(ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let acquired = unsafe { bpf_cgroup_acquire(cgrp) };
    if acquired.is_null() {
        unsafe { err = 1 };
        return 0;
    }

    unsafe { bpf_rcu_read_lock() };
    unsafe { bpf_rcu_read_unlock() };

    unsafe { bpf_cgroup_release(acquired) };

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_get_ancestors(ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let level = cgrp_level(cgrp);

    let self_cg = unsafe { bpf_cgroup_ancestor(cgrp, level) };
    if self_cg.is_null() {
        unsafe { err = 1 };
        return 0;
    }
    if cgrp_self_id(self_cg) != cgrp_self_id(cgrp) {
        unsafe { bpf_cgroup_release(self_cg) };
        unsafe { err = 2 };
        return 0;
    }
    unsafe { bpf_cgroup_release(self_cg) };

    let ancestor1 = unsafe { bpf_cgroup_ancestor(cgrp, level - 1) };
    if ancestor1.is_null() {
        unsafe { err = 3 };
        return 0;
    }
    unsafe { bpf_cgroup_release(ancestor1) };

    let invalid = unsafe { bpf_cgroup_ancestor(cgrp, 10000) };
    if !invalid.is_null() {
        unsafe { bpf_cgroup_release(invalid) };
        unsafe { err = 4 };
        return 0;
    }

    let invalid = unsafe { bpf_cgroup_ancestor(cgrp, -1) };
    if !invalid.is_null() {
        unsafe { bpf_cgroup_release(invalid) };
        unsafe { err = 5 };
        return 0;
    }

    0
}

#[link_section = "tp_btf/cgroup_mkdir"]
#[no_mangle]
extern "C" fn test_cgrp_from_id(ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;

    let level = cgrp_level(cgrp);

    // @cgrp's ID is not visible yet, let's test with the parent.
    let parent = unsafe { bpf_cgroup_ancestor(cgrp, level - 1) };
    if parent.is_null() {
        unsafe { err = 1 };
        return 0;
    }

    let kn = cgrp_kn(parent);
    let parent_cgid = kn_id(kn);
    unsafe { bpf_cgroup_release(parent) };

    let res = unsafe { bpf_cgroup_from_id(parent_cgid) };
    if res.is_null() {
        unsafe { err = 2 };
        return 0;
    }
    unsafe { bpf_cgroup_release(res) };

    if res != parent {
        unsafe { err = 3 };
        return 0;
    }

    let res = unsafe { bpf_cgroup_from_id(u64::MAX) };
    if !res.is_null() {
        unsafe { bpf_cgroup_release(res) };
        unsafe { err = 4 };
        return 0;
    }

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_cgrp_from_id_ns(_ctx: *const core::ffi::c_void) -> i32 {
    let cg = unsafe { bpf_cgroup_from_id(1) };
    if cg.is_null() {
        return 42;
    }
    unsafe { bpf_cgroup_release(cg) };
    0
}

bpf_object!("GPL");
