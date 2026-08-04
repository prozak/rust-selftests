#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgroup_hierarchical_stats.c
// (bpf-rs-core idiom).
//
// `&cgrp->self` in the C source takes the address of the embedded
// `struct cgroup_subsys_state self;` field, which is the first field
// (offset 0) of `struct cgroup` in this kernel's vmlinux.h -- so a raw
// pointer reinterpret cast is the same address, no field walk needed
// (same shortcut as cgroup_iter_memcg.rs). `cgrp->kn->id` is a genuine
// non-zero-offset two-hop CO-RE chain, resolved through `#[btf]` structs.

use bpf_rs_core::helpers::{
    bpf_get_smp_processor_id, bpf_map_lookup_elem, bpf_map_lookup_percpu_elem,
    bpf_map_update_elem, bpf_seq_printf,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::bpf_object;
use btf_macros::btf;
use core::ffi::c_void;

const BPF_NOEXIST: u64 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
struct percpu_attach_counter {
    prev: u64,
    state: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct attach_counter {
    pending: u64,
    state: u64,
}

#[btf]
struct kernfs_node {
    id: u64,
}

#[btf]
struct cgroup {
    kn: *mut kernfs_node,
}

#[repr(C)]
struct cgroup_subsys_state {
    _opaque: [u8; 0],
}

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__cgroup {
    meta: *mut bpf_iter_meta,
    cgroup: *mut cgroup,
}

extern "C" {
    fn css_rstat_updated(css: *mut cgroup_subsys_state, cpu: i32);
    fn css_rstat_flush(css: *mut cgroup_subsys_state);
}

#[link_section = ".maps"]
#[no_mangle]
static percpu_attach_counters: BpfMap<u64, percpu_attach_counter, { maps::PERCPU_HASH }, 1024> =
    BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static attach_counters: BpfMap<u64, attach_counter, { maps::HASH }, 1024> = BpfMap::new();

#[inline(never)]
fn cgroup_id(cgrp: *mut cgroup) -> u64 {
    let kn = *unsafe { &*cgrp }.kn().get().unwrap();
    *unsafe { &*kn }.id().get().unwrap()
}

#[inline(never)]
fn create_percpu_attach_counter(cg_id: u64, state: u64) -> i64 {
    let init = percpu_attach_counter { state, prev: 0 };
    bpf_map_update_elem(&percpu_attach_counters, &cg_id, &init, BPF_NOEXIST)
}

#[inline(never)]
fn create_attach_counter(cg_id: u64, state: u64, pending: u64) -> i64 {
    let init = attach_counter { state, pending };
    bpf_map_update_elem(&attach_counters, &cg_id, &init, BPF_NOEXIST)
}

#[link_section = "tp_btf/cgroup_attach_task"]
#[no_mangle]
extern "C" fn counter(ctx: *const u64) -> i32 {
    let dst_cgrp = fentry_arg(ctx, 0) as *mut cgroup;
    let cg_id = cgroup_id(dst_cgrp);

    let pcpu_counter =
        bpf_map_lookup_elem(&percpu_attach_counters, &cg_id) as *mut percpu_attach_counter;

    if !pcpu_counter.is_null() {
        unsafe { (*pcpu_counter).state += 1 };
    } else if create_percpu_attach_counter(cg_id, 1) != 0 {
        return 0;
    }

    let css = dst_cgrp as *mut cgroup_subsys_state;
    unsafe { css_rstat_updated(css, bpf_get_smp_processor_id() as i32) };
    0
}

#[link_section = "fentry/bpf_rstat_flush"]
#[no_mangle]
extern "C" fn flusher(ctx: *const u64) -> i32 {
    let cgrp = fentry_arg(ctx, 0) as *mut cgroup;
    let parent = fentry_arg(ctx, 1) as *mut cgroup;
    let cpu = fentry_arg(ctx, 2) as i32;

    let cg_id = cgroup_id(cgrp);
    let parent_cg_id = if !parent.is_null() {
        cgroup_id(parent)
    } else {
        0
    };
    let mut delta: u64 = 0;

    let pcpu_counter = bpf_map_lookup_percpu_elem(&percpu_attach_counters, &cg_id, cpu as u32)
        as *mut percpu_attach_counter;
    if !pcpu_counter.is_null() {
        let state = unsafe { (*pcpu_counter).state };
        delta = delta.wrapping_add(state.wrapping_sub(unsafe { (*pcpu_counter).prev }));
        unsafe { (*pcpu_counter).prev = state };
    }

    let total_counter = bpf_map_lookup_elem(&attach_counters, &cg_id) as *mut attach_counter;
    if total_counter.is_null() {
        if create_attach_counter(cg_id, delta, 0) != 0 {
            return 0;
        }
    } else {
        let pending = unsafe { (*total_counter).pending };
        if pending != 0 {
            delta = delta.wrapping_add(pending);
            unsafe { (*total_counter).pending = 0 };
        }
        unsafe { (*total_counter).state += delta };
    }

    if delta == 0 || parent_cg_id == 0 {
        return 0;
    }

    let parent_counter = bpf_map_lookup_elem(&attach_counters, &parent_cg_id) as *mut attach_counter;
    if !parent_counter.is_null() {
        unsafe { (*parent_counter).pending += delta };
    } else {
        create_attach_counter(parent_cg_id, 0, delta);
    }
    0
}

#[link_section = "iter.s/cgroup"]
#[no_mangle]
extern "C" fn dumper(ctx: *const bpf_iter__cgroup) -> i32 {
    let ctx = unsafe { &*ctx };
    let cgrp = ctx.cgroup;
    let meta = unsafe { &*ctx.meta };

    let cg_id = if !cgrp.is_null() {
        cgroup_id(cgrp)
    } else {
        0
    };

    if cg_id == 0 {
        return 1;
    }

    let css = cgrp as *mut cgroup_subsys_state;
    unsafe { css_rstat_flush(css) };

    let total_counter = bpf_map_lookup_elem(&attach_counters, &cg_id) as *mut attach_counter;
    if total_counter.is_null() {
        static FMT0: [u8; 32] = *b"cg_id: %llu, attach_counter: 0\n\0";
        let params: [u64; 1] = [cg_id];
        bpf_seq_printf(
            meta.seq,
            FMT0.as_ptr() as *const c_void,
            FMT0.len() as u32,
            params.as_ptr() as *const c_void,
            core::mem::size_of_val(&params) as u32,
        );
    } else {
        let state = unsafe { (*total_counter).state };
        static FMT1: [u8; 35] = *b"cg_id: %llu, attach_counter: %llu\n\0";
        let params: [u64; 2] = [cg_id, state];
        bpf_seq_printf(
            meta.seq,
            FMT1.as_ptr() as *const c_void,
            FMT1.len() as u32,
            params.as_ptr() as *const c_void,
            core::mem::size_of_val(&params) as u32,
        );
    }

    0
}

bpf_object!("GPL");
