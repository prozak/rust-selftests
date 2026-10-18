// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_ma_ttrace.c
// (bpf-rs-core idiom). The syscall program walks the bpf_mem_cache of
// every CPU that `htab` allocates from: bpf_core_cast(&htab, struct
// bpf_htab) is bpf_rdonly_cast with the kernel type id (BTF_TYPE_ID,
// scripts/type_id.py), the per-CPU base comes from the __per_cpu_offset
// ksym variable (BTF_KSYM, scripts/ksym_vars.py), and the loop is the
// open-coded num iterator behind C's bpf_for().
// BTF_TYPE_ID: tid_bpf_htab struct bpf_htab
// BTF_TYPE_ID: tid_bpf_mem_cache struct bpf_mem_cache
// BTF_KSYM: __per_cpu_offset

use core::ffi::c_void;

use bpf_rs_core::helpers::bpf_probe_read_kernel;
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;

bpf_map! {
    htab {
        r#type: *const [i32; 1],       // BPF_MAP_TYPE_HASH
        map_flags: *const [i32; 1],    // BPF_F_NO_PREALLOC
        max_entries: *const [i32; 4096],
        key: *const i32,
        value: *const isize,
    }
}

unsafe extern "C" {
    // extern const void __per_cpu_offset __ksym; address-only declaration
    static __per_cpu_offset: c_void;
}

#[no_mangle]
static mut nr_cpus: i32 = 0;
#[no_mangle]
static mut nr_caches: i32 = 0;
#[no_mangle]
static mut in_progress: i32 = 0;
#[no_mangle]
static mut not_freed: i32 = 0;

#[btf]
struct llist_node {}

#[btf]
struct llist_head {
    first: *mut llist_node,
}

#[btf]
struct atomic_t {
    counter: i32,
}

#[btf]
struct bpf_mem_cache {
    unit_size: i32,
    free_by_rcu_ttrace: llist_head,
    waiting_for_gp_ttrace: llist_head,
    call_rcu_ttrace_in_progress: atomic_t,
}

#[btf]
struct bpf_mem_alloc {
    cache: *mut bpf_mem_cache,
}

#[btf]
struct bpf_htab {
    ma: bpf_mem_alloc,
}

#[repr(C, align(8))]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

extern "C" {
    fn bpf_rdonly_cast(obj: *const c_void, btf_id: u32) -> *mut c_void;
    fn tid_bpf_htab() -> u64;
    fn tid_bpf_mem_cache() -> u64;
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
}

/* Look at bpf_mem_cache of every cpu that htab allocates its elements from */
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn check_ttrace(_ctx: *const c_void) -> i32 {
    unsafe {
        let h = bpf_rdonly_cast(core::ptr::addr_of!(htab) as *const c_void, tid_bpf_htab() as u32)
            as *const bpf_htab;
        // BPF_CORE_READ(h, ma.cache): a probe read of the relocated field, so
        // `cache` is a scalar (a direct load through the rdonly_cast pointer
        // would be an untrusted pointer, and adding the unbounded per-CPU
        // offset to it is rejected: "pointer offset is not safe")
        let mut cache: usize = 0;
        bpf_probe_read_kernel(&mut cache, 8, (*h).ma().cache().as_ptr() as *const c_void);
        let offsets = core::ptr::addr_of!(__per_cpu_offset) as *const usize;

        nr_caches = 0;
        in_progress = 0;
        not_freed = 0;
        let mut it = bpf_iter_num { __opaque: [0; 1] };
        bpf_iter_num_new(&mut it, 0, nr_cpus);
        loop {
            let p = bpf_iter_num_next(&mut it);
            if p.is_null() {
                break;
            }
            let cpu = *p;
            let mut off: usize = 0;
            if bpf_probe_read_kernel(&mut off, 8, offsets.offset(cpu as isize) as *const c_void) != 0 {
                bpf_iter_num_destroy(&mut it);
                return -1;
            }
            let c = bpf_rdonly_cast((cache.wrapping_add(off)) as *const c_void, tid_bpf_mem_cache() as u32)
                as *const bpf_mem_cache;
            let c = &*c;
            if *c.unit_size().as_ptr() != 0 {
                nr_caches += 1;
            }
            if *c.call_rcu_ttrace_in_progress().counter().as_ptr() != 0 {
                in_progress += 1;
            }
            if !(*c.free_by_rcu_ttrace().first().as_ptr()).is_null()
                || !(*c.waiting_for_gp_ttrace().first().as_ptr()).is_null()
            {
                not_freed += 1;
            }
        }
        bpf_iter_num_destroy(&mut it);
    }
    0
}

bpf_object!("GPL");
