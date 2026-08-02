#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgroup_iter_memcg.c
// (bpf-rs-core idiom).
//
// `struct cgroup_subsys_state self;` is the first field of `struct cgroup`
// (offset 0 in vmlinux.h), so `&cgrp->self` is the same address as `cgrp`
// reinterpreted as `cgroup_subsys_state *` -- no field walk needed.
//
// `bpf_core_enum_value(enum node_stat_item, ...)` / `enum vm_event_item`
// have no equivalent here (no CO-RE enum-value relocation support in this
// pipeline); the numeric values below are read directly from the
// vmlinux.h this kernel tree ships (node_stat_item / vm_event_item).

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter__cgroup {
    meta: *mut c_void,
    cgroup: *mut c_void,
}

#[repr(C)]
struct cgroup_subsys_state {
    _opaque: [u8; 0],
}

#[repr(C)]
struct mem_cgroup {
    _opaque: [u8; 0],
}

#[repr(C)]
struct memcg_query {
    nr_anon_mapped: usize,
    nr_shmem: usize,
    nr_file_pages: usize,
    nr_file_mapped: usize,
    pgfault: usize,
}

// enum node_stat_item (mm/vmstat + vmlinux.h)
const NR_ANON_MAPPED: i32 = 17;
const NR_FILE_MAPPED: i32 = 18;
const NR_FILE_PAGES: i32 = 19;
const NR_SHMEM: i32 = 22;
// enum vm_event_item
const PGFAULT: i32 = 14;

extern "C" {
    fn bpf_get_mem_cgroup(css: *mut cgroup_subsys_state) -> *mut mem_cgroup;
    fn bpf_put_mem_cgroup(memcg: *mut mem_cgroup);
    fn bpf_mem_cgroup_flush_stats(memcg: *mut mem_cgroup);
    fn bpf_mem_cgroup_page_state(memcg: *mut mem_cgroup, idx: i32) -> usize;
    fn bpf_mem_cgroup_vm_events(memcg: *mut mem_cgroup, event: i32) -> usize;
}

#[link_section = ".data.query"]
#[no_mangle]
static mut memcg_query: memcg_query = memcg_query {
    nr_anon_mapped: 0,
    nr_shmem: 0,
    nr_file_pages: 0,
    nr_file_mapped: 0,
    pgfault: 0,
};

#[link_section = "iter.s/cgroup"]
#[no_mangle]
extern "C" fn cgroup_memcg_query(ctx: *const bpf_iter__cgroup) -> i32 {
    let ctx = unsafe { &*ctx };
    let cgrp = ctx.cgroup;
    if cgrp.is_null() {
        return 1;
    }

    let css = cgrp as *mut cgroup_subsys_state;
    let memcg = unsafe { bpf_get_mem_cgroup(css) };
    if memcg.is_null() {
        return 1;
    }

    unsafe {
        bpf_mem_cgroup_flush_stats(memcg);

        memcg_query.nr_anon_mapped = bpf_mem_cgroup_page_state(memcg, NR_ANON_MAPPED);
        memcg_query.nr_shmem = bpf_mem_cgroup_page_state(memcg, NR_SHMEM);
        memcg_query.nr_file_pages = bpf_mem_cgroup_page_state(memcg, NR_FILE_PAGES);
        memcg_query.nr_file_mapped = bpf_mem_cgroup_page_state(memcg, NR_FILE_MAPPED);
        memcg_query.pgfault = bpf_mem_cgroup_vm_events(memcg, PGFAULT);

        bpf_put_mem_cgroup(memcg);
    }

    0
}

bpf_object!("GPL");
