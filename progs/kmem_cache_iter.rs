#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/kmem_cache_iter.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_task, bpf_map_lookup_elem, bpf_map_update_elem, bpf_probe_read_kernel_str,
    bpf_seq_printf, bpf_strncmp,
};
use bpf_rs_core::maps::{self, BpfMap};
use btf_macros::btf;
use core::ffi::c_void;

const SLAB_NAME_MAX: usize = 32;
const BPF_NOEXIST: u64 = 1;

#[repr(C)]
struct KmemCacheResult {
    name: [u8; SLAB_NAME_MAX],
    obj_size: i64,
}

bpf_map! {
    slab_hash {
        r#type: *const [i32; maps::HASH],
        key_size: *const [i32; 8],
        value_size: *const [i32; SLAB_NAME_MAX],
        max_entries: *const [i32; 1],
    }
}

#[link_section = ".maps"]
#[no_mangle]
static slab_result: BpfMap<i32, KmemCacheResult, { maps::ARRAY }, 1024> = BpfMap::new();

#[btf]
struct kmem_cache {
    name: *const u8,
    size: u32,
}

extern "C" {
    fn bpf_get_kmem_cache(addr: u64) -> *mut kmem_cache;
}

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__kmem_cache {
    meta: *mut bpf_iter_meta,
    s: *mut kmem_cache,
}

#[no_mangle]
static mut task_struct_found: i32 = 0;
#[no_mangle]
static mut kmem_cache_seen: i32 = 0;
#[no_mangle]
static mut open_coded_seen: i32 = 0;

#[link_section = "iter/kmem_cache"]
#[no_mangle]
extern "C" fn slab_info_collector(ctx: *const bpf_iter__kmem_cache) -> i32 {
    let ctx = unsafe { &*ctx };
    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;
    let s = ctx.s;

    if !s.is_null() {
        let s_ref = unsafe { &*s };
        let name_ptr = *s_ref.name().get().unwrap();
        let size = *s_ref.size().get().unwrap();

        static FMT: [u8; 8] = *b"%s: %u\n\0";
        let params: [u64; 2] = [name_ptr as u64, size as u64];
        bpf_seq_printf(
            seq,
            FMT.as_ptr() as *const c_void,
            FMT.len() as u32,
            params.as_ptr() as *const c_void,
            core::mem::size_of_val(&params) as u32,
        );

        let idx: i32 = unsafe { kmem_cache_seen };
        let r = bpf_map_lookup_elem(&slab_result, &idx);
        if r.is_null() {
            return 0;
        }
        let r = r as *mut KmemCacheResult;

        unsafe { kmem_cache_seen += 1 };

        bpf_probe_read_kernel_str(
            unsafe { (*r).name.as_mut_ptr() as *mut c_void },
            SLAB_NAME_MAX as u32,
            name_ptr as *const c_void,
        );
        unsafe { (*r).obj_size = size as i64 };

        if bpf_strncmp(
            unsafe { (*r).name.as_ptr() as *const c_void },
            11,
            b"task_struct\0".as_ptr() as *const c_void,
        ) == 0
        {
            bpf_map_update_elem(&slab_hash, &s, unsafe { &(*r).name }, BPF_NOEXIST);
        }
    }

    0
}

#[link_section = "raw_tp/bpf_test_finish"]
#[no_mangle]
extern "C" fn check_task_struct(_ctx: *const c_void) -> i32 {
    let curr = bpf_get_current_task();
    let s = unsafe { bpf_get_kmem_cache(curr) };
    if s.is_null() {
        unsafe { task_struct_found = -1 };
        return 0;
    }

    let name = bpf_map_lookup_elem(&slab_hash, &s);
    if !name.is_null()
        && bpf_strncmp(
            name as *const c_void,
            11,
            b"task_struct\0".as_ptr() as *const c_void,
        ) == 0
    {
        unsafe { task_struct_found = 1 };
    } else {
        unsafe { task_struct_found = -2 };
    }
    0
}

#[repr(C, align(8))]
struct bpf_iter_kmem_cache {
    __opaque: [u64; 1],
}

extern "C" {
    fn bpf_iter_kmem_cache_new(it: *mut bpf_iter_kmem_cache) -> i32;
    fn bpf_iter_kmem_cache_next(it: *mut bpf_iter_kmem_cache) -> *mut kmem_cache;
    fn bpf_iter_kmem_cache_destroy(it: *mut bpf_iter_kmem_cache);
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn open_coded_iter(_ctx: *const c_void) -> i32 {
    let mut it = bpf_iter_kmem_cache { __opaque: [0; 1] };
    unsafe { bpf_iter_kmem_cache_new(&mut it) };

    loop {
        let s = unsafe { bpf_iter_kmem_cache_next(&mut it) };
        if s.is_null() {
            break;
        }

        let idx: i32 = unsafe { open_coded_seen };
        let r = bpf_map_lookup_elem(&slab_result, &idx);
        if r.is_null() {
            break;
        }
        let r = r as *mut KmemCacheResult;

        let size = *unsafe { &*s }.size().get().unwrap();
        if unsafe { (*r).obj_size } != size as i64 {
            break;
        }

        unsafe { open_coded_seen += 1 };
    }

    unsafe { bpf_iter_kmem_cache_destroy(&mut it) };
    0
}

bpf_object!("GPL");
