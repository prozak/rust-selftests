// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_bpf_ma.c (bpf-rs-core idiom).
//
// The per-size map values hold a `__kptr` / `__percpu_kptr` pointer in the
// C; the tags come from the btf_type_tags! declaration at the bottom.

use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_kptr_xchg, bpf_map_lookup_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, btf_type_tags};
use core::ffi::c_void;

#[repr(C)]
struct generic_map_value {
    data: *mut c_void,
}

// C: DEFINE_ARRAY_WITH_KPTR(_size). kptr doesn't support bin_data_8, which
// is a zero-sized array.
macro_rules! define_array_with_kptr {
    ($size:literal, $bin:ident, $force:ident, $val:ident, $map:ident) => {
        #[repr(C)]
        struct $bin {
            data: [u8; $size - 8],
        }
        // See Commit 5d8d6634ccc, force btf generation for the type
        #[no_mangle]
        static mut $force: *mut $bin = core::ptr::null_mut();
        #[repr(C)]
        struct $val {
            data: *mut $bin,
        }
        #[link_section = ".maps"]
        #[no_mangle]
        static $map: BpfMap<i32, $val, { maps::ARRAY }, 128> = BpfMap::new();
    };
}

// C: DEFINE_ARRAY_WITH_PERCPU_KPTR(_size)
macro_rules! define_array_with_percpu_kptr {
    ($size:literal, $bin:ident, $force:ident, $val:ident, $map:ident) => {
        #[repr(C)]
        struct $bin {
            data: [u8; $size],
        }
        #[no_mangle]
        static mut $force: *mut $bin = core::ptr::null_mut();
        #[repr(C)]
        struct $val {
            data: *mut $bin,
        }
        #[link_section = ".maps"]
        #[no_mangle]
        static $map: BpfMap<i32, $val, { maps::ARRAY }, 128> = BpfMap::new();
    };
}

define_array_with_kptr!(16, bin_data_16, __bin_data_16, map_value_16, array_16);
define_array_with_kptr!(32, bin_data_32, __bin_data_32, map_value_32, array_32);
define_array_with_kptr!(64, bin_data_64, __bin_data_64, map_value_64, array_64);
define_array_with_kptr!(96, bin_data_96, __bin_data_96, map_value_96, array_96);
define_array_with_kptr!(128, bin_data_128, __bin_data_128, map_value_128, array_128);
define_array_with_kptr!(192, bin_data_192, __bin_data_192, map_value_192, array_192);
define_array_with_kptr!(256, bin_data_256, __bin_data_256, map_value_256, array_256);
define_array_with_kptr!(512, bin_data_512, __bin_data_512, map_value_512, array_512);
define_array_with_kptr!(1024, bin_data_1024, __bin_data_1024, map_value_1024, array_1024);
define_array_with_kptr!(2048, bin_data_2048, __bin_data_2048, map_value_2048, array_2048);
define_array_with_kptr!(4096, bin_data_4096, __bin_data_4096, map_value_4096, array_4096);

define_array_with_percpu_kptr!(8, percpu_bin_data_8, __percpu_bin_data_8, map_value_percpu_8, array_percpu_8);
define_array_with_percpu_kptr!(16, percpu_bin_data_16, __percpu_bin_data_16, map_value_percpu_16, array_percpu_16);
define_array_with_percpu_kptr!(32, percpu_bin_data_32, __percpu_bin_data_32, map_value_percpu_32, array_percpu_32);
define_array_with_percpu_kptr!(64, percpu_bin_data_64, __percpu_bin_data_64, map_value_percpu_64, array_percpu_64);
define_array_with_percpu_kptr!(96, percpu_bin_data_96, __percpu_bin_data_96, map_value_percpu_96, array_percpu_96);
define_array_with_percpu_kptr!(128, percpu_bin_data_128, __percpu_bin_data_128, map_value_percpu_128, array_percpu_128);
define_array_with_percpu_kptr!(192, percpu_bin_data_192, __percpu_bin_data_192, map_value_percpu_192, array_percpu_192);
define_array_with_percpu_kptr!(256, percpu_bin_data_256, __percpu_bin_data_256, map_value_percpu_256, array_percpu_256);
define_array_with_percpu_kptr!(512, percpu_bin_data_512, __percpu_bin_data_512, map_value_percpu_512, array_percpu_512);

// --- rodata: userspace resolves the real BTF struct id for each
// bin_data_<N>/percpu_bin_data_<N> by name and patches these arrays before
// load (see prog_tests/test_bpf_ma.c). data_sizes/percpu_data_sizes are
// plain `const` (baked-in values); data_btf_ids/percpu_data_btf_ids are
// `const volatile` (zero here, patched pre-load). percpu_data_btf_ids keeps
// the C original's oversized length (ARRAY_SIZE(data_sizes) == 11, not
// percpu_data_sizes' own 9) -- only indices 0..9 are ever written/read.
#[link_section = ".rodata"]
#[no_mangle]
static data_sizes: [u32; 11] = [16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096];
#[link_section = ".rodata"]
#[no_mangle]
static data_btf_ids: [u32; 11] = [0; 11];

#[link_section = ".rodata"]
#[no_mangle]
static percpu_data_sizes: [u32; 9] = [8, 16, 32, 64, 96, 128, 192, 256, 512];
#[link_section = ".rodata"]
#[no_mangle]
static percpu_data_btf_ids: [u32; 11] = [0; 11];

#[no_mangle]
static mut err: i32 = 0;
#[no_mangle]
static mut pid: u32 = 0;

extern "C" {
    fn bpf_obj_new_impl(local_type_id: u64, meta: *mut c_void) -> *mut c_void;
    fn bpf_obj_drop(p: *mut c_void);
    fn bpf_percpu_obj_new_impl(local_type_id: u64, meta: *mut c_void) -> *mut c_void;
    fn bpf_percpu_obj_drop(p: *mut c_void);
}

#[inline(always)]
fn read_id(ids: &[u32], idx: usize) -> u64 {
    unsafe { core::ptr::read_volatile(ids.as_ptr().add(idx)) as u64 }
}

#[inline(always)]
fn batch_alloc<M>(map: &M, batch: u32, idx: usize) {
    let mut i: u32 = 0;
    while i < batch {
        let key = i;
        let value = bpf_map_lookup_elem(map, &key) as *mut generic_map_value;
        if value.is_null() {
            unsafe { err = 1 };
            return;
        }
        let new = unsafe { bpf_obj_new_impl(read_id(&data_btf_ids, idx), core::ptr::null_mut()) };
        if new.is_null() {
            unsafe { err = 2 };
            return;
        }
        let old = bpf_kptr_xchg(unsafe { core::ptr::addr_of_mut!((*value).data) }.cast(), new);
        if !old.is_null() {
            unsafe {
                bpf_obj_drop(old);
                err = 3;
            }
            return;
        }
        i += 1;
    }
}

#[inline(always)]
fn batch_free<M>(map: &M, batch: u32, _idx: usize) {
    let mut i: u32 = 0;
    while i < batch {
        let key = i;
        let value = bpf_map_lookup_elem(map, &key) as *mut generic_map_value;
        if value.is_null() {
            unsafe { err = 4 };
            return;
        }
        let old = bpf_kptr_xchg(
            unsafe { core::ptr::addr_of_mut!((*value).data) }.cast(),
            core::ptr::null_mut(),
        );
        if old.is_null() {
            unsafe { err = 5 };
            return;
        }
        unsafe { bpf_obj_drop(old) };
        i += 1;
    }
}

#[inline(always)]
fn batch_percpu_alloc<M>(map: &M, batch: u32, idx: usize) {
    let mut i: u32 = 0;
    while i < batch {
        let key = i;
        let value = bpf_map_lookup_elem(map, &key) as *mut generic_map_value;
        if value.is_null() {
            unsafe { err = 1 };
            return;
        }
        // per-cpu allocator may not be able to refill in time
        let new = unsafe {
            bpf_percpu_obj_new_impl(read_id(&percpu_data_btf_ids, idx), core::ptr::null_mut())
        };
        if new.is_null() {
            i += 1;
            continue;
        }
        let old = bpf_kptr_xchg(unsafe { core::ptr::addr_of_mut!((*value).data) }.cast(), new);
        if !old.is_null() {
            unsafe {
                bpf_percpu_obj_drop(old);
                err = 2;
            }
            return;
        }
        i += 1;
    }
}

#[inline(always)]
fn batch_percpu_free<M>(map: &M, batch: u32, _idx: usize) {
    let mut i: u32 = 0;
    while i < batch {
        let key = i;
        let value = bpf_map_lookup_elem(map, &key) as *mut generic_map_value;
        if value.is_null() {
            unsafe { err = 3 };
            return;
        }
        let old = bpf_kptr_xchg(
            unsafe { core::ptr::addr_of_mut!((*value).data) }.cast(),
            core::ptr::null_mut(),
        );
        if old.is_null() {
            i += 1;
            continue;
        }
        unsafe { bpf_percpu_obj_drop(old) };
        i += 1;
    }
}

fn current_pid_matches() -> bool {
    (bpf_get_current_pid_tgid() as u32) == unsafe { pid }
}

#[link_section = "?fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn test_batch_alloc_free(_ctx: *const c_void) -> i32 {
    if !current_pid_matches() {
        return 0;
    }

    // Alloc 128 16-bytes objects in batch to trigger refilling,
    // then free 128 16-bytes objects in batch to trigger freeing.
    batch_alloc(&array_16, 128, 0);
    batch_free(&array_16, 128, 0);
    batch_alloc(&array_32, 128, 1);
    batch_free(&array_32, 128, 1);
    batch_alloc(&array_64, 128, 2);
    batch_free(&array_64, 128, 2);
    batch_alloc(&array_96, 128, 3);
    batch_free(&array_96, 128, 3);
    batch_alloc(&array_128, 128, 4);
    batch_free(&array_128, 128, 4);
    batch_alloc(&array_192, 128, 5);
    batch_free(&array_192, 128, 5);
    batch_alloc(&array_256, 128, 6);
    batch_free(&array_256, 128, 6);
    batch_alloc(&array_512, 64, 7);
    batch_free(&array_512, 64, 7);
    batch_alloc(&array_1024, 32, 8);
    batch_free(&array_1024, 32, 8);
    batch_alloc(&array_2048, 16, 9);
    batch_free(&array_2048, 16, 9);
    batch_alloc(&array_4096, 8, 10);
    batch_free(&array_4096, 8, 10);

    0
}

#[link_section = "?fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn test_free_through_map_free(_ctx: *const c_void) -> i32 {
    if !current_pid_matches() {
        return 0;
    }

    // Alloc 128 16-bytes objects in batch to trigger refilling,
    // then free these objects through map free.
    batch_alloc(&array_16, 128, 0);
    batch_alloc(&array_32, 128, 1);
    batch_alloc(&array_64, 128, 2);
    batch_alloc(&array_96, 128, 3);
    batch_alloc(&array_128, 128, 4);
    batch_alloc(&array_192, 128, 5);
    batch_alloc(&array_256, 128, 6);
    batch_alloc(&array_512, 64, 7);
    batch_alloc(&array_1024, 32, 8);
    batch_alloc(&array_2048, 16, 9);
    batch_alloc(&array_4096, 8, 10);

    0
}

#[link_section = "?fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn test_batch_percpu_alloc_free(_ctx: *const c_void) -> i32 {
    if !current_pid_matches() {
        return 0;
    }

    // Alloc 128 8-bytes per-cpu objects in batch to trigger refilling,
    // then free 128 8-bytes per-cpu objects in batch to trigger freeing.
    batch_percpu_alloc(&array_percpu_8, 128, 0);
    batch_percpu_free(&array_percpu_8, 128, 0);
    batch_percpu_alloc(&array_percpu_16, 128, 1);
    batch_percpu_free(&array_percpu_16, 128, 1);
    batch_percpu_alloc(&array_percpu_32, 128, 2);
    batch_percpu_free(&array_percpu_32, 128, 2);
    batch_percpu_alloc(&array_percpu_64, 128, 3);
    batch_percpu_free(&array_percpu_64, 128, 3);
    batch_percpu_alloc(&array_percpu_96, 128, 4);
    batch_percpu_free(&array_percpu_96, 128, 4);
    batch_percpu_alloc(&array_percpu_128, 128, 5);
    batch_percpu_free(&array_percpu_128, 128, 5);
    batch_percpu_alloc(&array_percpu_192, 128, 6);
    batch_percpu_free(&array_percpu_192, 128, 6);
    batch_percpu_alloc(&array_percpu_256, 128, 7);
    batch_percpu_free(&array_percpu_256, 128, 7);
    batch_percpu_alloc(&array_percpu_512, 64, 8);
    batch_percpu_free(&array_percpu_512, 64, 8);

    0
}

#[link_section = "?fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn test_percpu_free_through_map_free(_ctx: *const c_void) -> i32 {
    if !current_pid_matches() {
        return 0;
    }

    // Alloc 128 8-bytes per-cpu objects in batch to trigger refilling,
    // then free these object through map free.
    batch_percpu_alloc(&array_percpu_8, 128, 0);
    batch_percpu_alloc(&array_percpu_16, 128, 1);
    batch_percpu_alloc(&array_percpu_32, 128, 2);
    batch_percpu_alloc(&array_percpu_64, 128, 3);
    batch_percpu_alloc(&array_percpu_96, 128, 4);
    batch_percpu_alloc(&array_percpu_128, 128, 5);
    batch_percpu_alloc(&array_percpu_192, 128, 6);
    batch_percpu_alloc(&array_percpu_256, 128, 7);
    batch_percpu_alloc(&array_percpu_512, 64, 8);

    0
}

btf_type_tags! {
    map_value_16.data: kptr;
    map_value_32.data: kptr;
    map_value_64.data: kptr;
    map_value_96.data: kptr;
    map_value_128.data: kptr;
    map_value_192.data: kptr;
    map_value_256.data: kptr;
    map_value_512.data: kptr;
    map_value_1024.data: kptr;
    map_value_2048.data: kptr;
    map_value_4096.data: kptr;
    map_value_percpu_8.data: percpu_kptr;
    map_value_percpu_16.data: percpu_kptr;
    map_value_percpu_32.data: percpu_kptr;
    map_value_percpu_64.data: percpu_kptr;
    map_value_percpu_96.data: percpu_kptr;
    map_value_percpu_128.data: percpu_kptr;
    map_value_percpu_192.data: percpu_kptr;
    map_value_percpu_256.data: percpu_kptr;
    map_value_percpu_512.data: percpu_kptr;
}

bpf_object!("GPL");
