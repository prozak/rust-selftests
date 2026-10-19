// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/map_ptr_kern.c
// (bpf-rs-core idiom). One cgroup_skb program reads the kernel's `struct
// bpf_map` fields of 26 map kinds through CO-RE views of the map pointers
// themselves (the verifier types a map pointer as the kernel object), and
// compares them with what the object declared. prog_tests/map_ptr.c loads
// the light skeleton, sets the ring buffer's max_entries to the page size
// and the `page_size` global, and runs cg_skb once expecting a nonzero
// return. `g_line` records the C line of the last check, so the numbers
// below are the C source's.

use core::ffi::c_void;
use core::ptr::addr_of;

use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_map_update_elem, bpf_ringbuf_discard, bpf_ringbuf_reserve,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::bpf_object;
use btf::{BtfType, Field};
use btf_macros::btf;

const LOOP_BOUND: i32 = 0xf;
const MAX_ENTRIES: u32 = 8;
const HALF_ENTRIES: u32 = MAX_ENTRIES >> 1;
const BPF_RINGBUF_HDR_SZ: u64 = 8;

// The UAPI enum (the deprecated aliases share a value and cannot be Rust
// variants; the kernel field is matched by kind and name).
#[repr(u32)]
#[allow(non_camel_case_types, dead_code)]
#[derive(Clone, Copy)]
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC = 0,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PROG_ARRAY = 3,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_STACK_TRACE = 7,
    BPF_MAP_TYPE_CGROUP_ARRAY = 8,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
    BPF_MAP_TYPE_LPM_TRIE = 11,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_HASH_OF_MAPS = 13,
    BPF_MAP_TYPE_DEVMAP = 14,
    BPF_MAP_TYPE_SOCKMAP = 15,
    BPF_MAP_TYPE_CPUMAP = 16,
    BPF_MAP_TYPE_XSKMAP = 17,
    BPF_MAP_TYPE_SOCKHASH = 18,
    BPF_MAP_TYPE_CGROUP_STORAGE = 19,
    BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
    BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
    BPF_MAP_TYPE_QUEUE = 22,
    BPF_MAP_TYPE_STACK = 23,
    BPF_MAP_TYPE_SK_STORAGE = 24,
    BPF_MAP_TYPE_DEVMAP_HASH = 25,
    BPF_MAP_TYPE_STRUCT_OPS = 26,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_INODE_STORAGE = 28,
    BPF_MAP_TYPE_TASK_STORAGE = 29,
    BPF_MAP_TYPE_BLOOM_FILTER = 30,
    BPF_MAP_TYPE_USER_RINGBUF = 31,
    BPF_MAP_TYPE_CGRP_STORAGE = 32,
    BPF_MAP_TYPE_ARENA = 33,
    BPF_MAP_TYPE_INSN_ARRAY = 34,
    BPF_MAP_TYPE_RHASH = 35,
    __MAX_BPF_MAP_TYPE = 36,
}

impl BtfType for bpf_map_type {
    type Carrier = Self;

    type View<'a, Root, Path, Mode>
        = Field<'a, Root, Self, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a;

    #[inline(always)]
    fn __btf_view<'a, Root, Path, Mode>(
        field: Field<'a, Root, Self, Path, Mode>,
    ) -> Self::View<'a, Root, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a,
    {
        field
    }
}

#[no_mangle]
static mut g_map_type: bpf_map_type = bpf_map_type::BPF_MAP_TYPE_UNSPEC;
#[no_mangle]
static mut g_line: u32 = 0;
#[no_mangle]
static mut page_size: i32 = 0; /* userspace should set it */

// The map objects are writable globals, as in C: a `static` would let LLVM
// fold the field reads below from its all-zero initializer.
macro_rules! map_def {
    ($name:ident { $($field:ident : $fty:ty),+ $(,)? }) => {
        #[allow(non_camel_case_types)]
        #[repr(C)]
        struct $name {
            $($field: $fty),+
        }
        #[link_section = ".maps"]
        #[no_mangle]
        static mut $name: $name = $name {
            $($field: core::ptr::null()),+
        };
    };
}

macro_rules! verify_type {
    ($t:ident, $f:ident) => {
        unsafe {
            g_map_type = bpf_map_type::$t;
        }
        if $f() == 0 {
            return 0;
        }
    };
}

macro_rules! verify {
    ($line:expr, $e:expr) => {
        unsafe {
            g_line = $line;
        }
        if !($e) {
            return 0;
        }
    };
}

#[btf]
struct bpf_map {
    map_type: bpf_map_type,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    id: u32,
}

#[inline(always)]
unsafe fn rd<T: Copy>(p: *const T) -> T {
    *p
}

#[inline(always)]
fn map_type(m: &bpf_map) -> u32 {
    unsafe { rd(m.map_type().as_ptr() as *const u32) }
}

#[inline(always)]
fn check_bpf_map_fields(map: *const bpf_map, key_size: u32, value_size: u32, max_entries: u32) -> i32 {
    let map = unsafe { &*map };
    verify!(41, map_type(map) == unsafe { g_map_type } as u32);
    verify!(42, unsafe { rd(map.key_size().as_ptr()) } == key_size);
    verify!(43, unsafe { rd(map.value_size().as_ptr()) } == value_size);
    verify!(44, unsafe { rd(map.max_entries().as_ptr()) } == max_entries);
    verify!(45, unsafe { rd(map.id().as_ptr()) } > 0);

    1
}

#[inline(always)]
fn check_bpf_map_ptr(indirect: *const bpf_map, direct: *const bpf_map) -> i32 {
    let indirect = unsafe { &*indirect };
    let direct = unsafe { &*direct };
    verify!(53, map_type(indirect) == map_type(direct));
    verify!(54, unsafe { rd(indirect.key_size().as_ptr()) == rd(direct.key_size().as_ptr()) });
    verify!(55, unsafe { rd(indirect.value_size().as_ptr()) == rd(direct.value_size().as_ptr()) });
    verify!(56, unsafe { rd(indirect.max_entries().as_ptr()) == rd(direct.max_entries().as_ptr()) });
    verify!(57, unsafe { rd(indirect.id().as_ptr()) == rd(direct.id().as_ptr()) });

    1
}

// A subprogram, as in the C object (clang keeps `check` out of line).
#[inline(never)]
#[export_name = "check"]
extern "C" fn check(
    indirect: *const bpf_map,
    direct: *const bpf_map,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> i32 {
    verify!(65, check_bpf_map_ptr(indirect, direct) != 0);
    verify!(66, check_bpf_map_fields(indirect, key_size, value_size, max_entries) != 0);
    1
}

#[inline(always)]
fn check_default(indirect: *const bpf_map, direct: *const bpf_map) -> i32 {
    verify!(74, check(indirect, direct, 4, 4, MAX_ENTRIES) != 0);
    1
}

#[inline(never)]
#[export_name = "check_default_noinline"]
extern "C" fn check_default_noinline(indirect: *const bpf_map, direct: *const bpf_map) -> i32 {
    verify!(82, check(indirect, direct, 4, 4, MAX_ENTRIES) != 0);
    1
}

#[btf]
struct atomic_t {
    counter: i32,
}

#[btf]
struct bpf_htab {
    map: bpf_map,
    count: atomic_t,
    n_buckets: u32,
    elem_size: u32,
}

map_def! {
    m_hash {
        r#type: *const [i32; maps::HASH],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC, to test bpf_htab.count
        max_entries: *const [i32; 8],
        key: *const u32,
        value: *const u32,
    }
}

extern "C" {
    fn bpf_map_sum_elem_count(map: *const c_void) -> i64;
}

// `&x->map` is the map object itself: the kernel struct's first member.
#[inline(always)]
fn as_map<T>(m: &T) -> *const bpf_map {
    m as *const T as *const bpf_map
}

#[inline(always)]
fn check_hash() -> i32 {
    let hash = unsafe { &*(addr_of!(m_hash) as *const m_hash as *const bpf_htab) };
    let map = addr_of!(m_hash) as *const m_hash as *const bpf_map;

    verify!(114, check_default_noinline(as_map(hash), map) != 0);

    verify!(116, unsafe { rd(hash.n_buckets().as_ptr()) } == MAX_ENTRIES);
    verify!(117, unsafe { rd(hash.elem_size().as_ptr()) } == 32);

    verify!(119, unsafe { rd(hash.count().counter().as_ptr()) } == 0);
    verify!(120, unsafe { bpf_map_sum_elem_count(map as *const c_void) } == 0);

    let mut i: i32 = 0;
    while i < HALF_ENTRIES as i32 {
        let key: u32 = i as u32;
        let val: u32 = 1;

        if bpf_map_update_elem(addr_of!(m_hash), &key, &val, 0) != 0 {
            return 0;
        }
        i += 1;
    }
    verify!(129, unsafe { rd(hash.count().counter().as_ptr()) } == HALF_ENTRIES as i32);
    verify!(130, unsafe { bpf_map_sum_elem_count(map as *const c_void) } == HALF_ENTRIES as i64);

    1
}

#[btf]
struct bpf_array {
    map: bpf_map,
    elem_size: u32,
}

#[link_section = ".maps"]
#[no_mangle]
static mut m_array: BpfMap<u32, u32, { maps::ARRAY }, 8> = BpfMap::new();

#[inline(always)]
fn check_array() -> i32 {
    let array = unsafe { &*(addr_of!(m_array) as *const _ as *const bpf_array) };
    let map = addr_of!(m_array) as *const _ as *const bpf_map;
    let mut n_lookups: i32 = 0;
    let mut n_keys: i32 = 0;

    verify!(153, check_default(as_map(array), map) != 0);

    verify!(155, unsafe { rd(array.elem_size().as_ptr()) } == 8);

    let mut i: i32 = 0;
    while (i as u32) < unsafe { rd(array.map().max_entries().as_ptr()) } && i < LOOP_BOUND {
        let key: u32 = i as u32;
        let val = bpf_map_lookup_elem(addr_of!(m_array), &key) as *mut u32;

        n_lookups += 1;
        if !val.is_null() {
            n_keys += 1;
        }
        i += 1;
    }

    verify!(166, n_lookups == MAX_ENTRIES as i32);
    verify!(167, n_keys == MAX_ENTRIES as i32);

    1
}

#[link_section = ".maps"]
#[no_mangle]
static mut m_prog_array: BpfMap<u32, u32, { maps::PROG_ARRAY }, 8> = BpfMap::new();

#[inline(always)]
fn check_prog_array() -> i32 {
    let prog_array = unsafe { &*(addr_of!(m_prog_array) as *const _ as *const bpf_array) };
    let map = addr_of!(m_prog_array) as *const _ as *const bpf_map;

    verify!(184, check_default(as_map(prog_array), map) != 0);

    1
}

#[link_section = ".maps"]
#[no_mangle]
static mut m_perf_event_array: BpfMap<u32, u32, { maps::PERF_EVENT_ARRAY }, 8> = BpfMap::new();

#[inline(always)]
fn check_perf_event_array() -> i32 {
    let perf_event_array = unsafe { &*(addr_of!(m_perf_event_array) as *const _ as *const bpf_array) };
    let map = addr_of!(m_perf_event_array) as *const _ as *const bpf_map;

    verify!(201, check_default(as_map(perf_event_array), map) != 0);

    1
}

#[link_section = ".maps"]
#[no_mangle]
static mut m_percpu_hash: BpfMap<u32, u32, { maps::PERCPU_HASH }, 8> = BpfMap::new();

#[inline(always)]
fn check_percpu_hash() -> i32 {
    let percpu_hash = unsafe { &*(addr_of!(m_percpu_hash) as *const _ as *const bpf_htab) };
    let map = addr_of!(m_percpu_hash) as *const _ as *const bpf_map;

    verify!(218, check_default(as_map(percpu_hash), map) != 0);

    1
}

#[link_section = ".maps"]
#[no_mangle]
static mut m_percpu_array: BpfMap<u32, u32, { maps::PERCPU_ARRAY }, 8> = BpfMap::new();

#[inline(always)]
fn check_percpu_array() -> i32 {
    let percpu_array = unsafe { &*(addr_of!(m_percpu_array) as *const _ as *const bpf_array) };
    let map = addr_of!(m_percpu_array) as *const _ as *const bpf_map;

    verify!(235, check_default(as_map(percpu_array), map) != 0);

    1
}

#[btf]
struct bpf_stack_map {
    map: bpf_map,
}

#[link_section = ".maps"]
#[no_mangle]
static mut m_stack_trace: BpfMap<u32, u64, { maps::STACK_TRACE }, 8> = BpfMap::new();

#[inline(always)]
fn check_stack_trace() -> i32 {
    let stack_trace = unsafe { &*(addr_of!(m_stack_trace) as *const _ as *const bpf_stack_map) };
    let map = addr_of!(m_stack_trace) as *const _ as *const bpf_map;

    verify!(257, check(as_map(stack_trace), map, 4, 8, MAX_ENTRIES) != 0);

    1
}

const CGROUP_ARRAY: usize = 8;

#[link_section = ".maps"]
#[no_mangle]
static mut m_cgroup_array: BpfMap<u32, u32, CGROUP_ARRAY, 8> = BpfMap::new();

#[inline(always)]
fn check_cgroup_array() -> i32 {
    let cgroup_array = unsafe { &*(addr_of!(m_cgroup_array) as *const _ as *const bpf_array) };
    let map = addr_of!(m_cgroup_array) as *const _ as *const bpf_map;

    verify!(275, check_default(as_map(cgroup_array), map) != 0);

    1
}

#[link_section = ".maps"]
#[no_mangle]
static mut m_lru_hash: BpfMap<u32, u32, { maps::LRU_HASH }, 8> = BpfMap::new();

#[inline(always)]
fn check_lru_hash() -> i32 {
    let lru_hash = unsafe { &*(addr_of!(m_lru_hash) as *const _ as *const bpf_htab) };
    let map = addr_of!(m_lru_hash) as *const _ as *const bpf_map;

    verify!(292, check_default(as_map(lru_hash), map) != 0);

    1
}

#[link_section = ".maps"]
#[no_mangle]
static mut m_lru_percpu_hash: BpfMap<u32, u32, { maps::LRU_PERCPU_HASH }, 8> = BpfMap::new();

#[inline(always)]
fn check_lru_percpu_hash() -> i32 {
    let lru_percpu_hash = unsafe { &*(addr_of!(m_lru_percpu_hash) as *const _ as *const bpf_htab) };
    let map = addr_of!(m_lru_percpu_hash) as *const _ as *const bpf_map;

    verify!(309, check_default(as_map(lru_percpu_hash), map) != 0);

    1
}

#[btf]
struct lpm_trie {
    map: bpf_map,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_lpm_trie_key_hdr {
    prefixlen: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct lpm_key {
    trie_key: bpf_lpm_trie_key_hdr,
    data: u32,
}

const LPM_TRIE: usize = 11;

map_def! {
    m_lpm_trie {
        r#type: *const [i32; LPM_TRIE],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        max_entries: *const [i32; 8],
        key: *const lpm_key,
        value: *const u32,
    }
}

#[inline(always)]
fn check_lpm_trie() -> i32 {
    let trie = unsafe { &*(addr_of!(m_lpm_trie) as *const _ as *const lpm_trie) };
    let map = addr_of!(m_lpm_trie) as *const _ as *const bpf_map;

    verify!(336, check(as_map(trie), map, core::mem::size_of::<lpm_key>() as u32, 4, MAX_ENTRIES) != 0);

    1
}

const INNER_MAX_ENTRIES: u32 = 1234;

// struct inner_map { ARRAY, INNER_MAX_ENTRIES, u32 -> u32 } inner_map: the
// def type carries the map's name in C too.
#[allow(non_camel_case_types)]
#[repr(C)]
struct inner_map {
    r#type: *const [i32; maps::ARRAY],
    max_entries: *const [i32; 1234],
    key: *const u32,
    value: *const u32,
}
unsafe impl Sync for inner_map {}

#[link_section = ".maps"]
#[no_mangle]
static inner_map: inner_map = inner_map {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
};

const ARRAY_OF_MAPS: usize = 12;
const HASH_OF_MAPS: usize = 13;

// .values = { (void *)&inner_map, 0, 0, 0, 0, 0, 0, 0, 0 }: nine slots in
// the C object; scripts/btf_map_slots.py makes the BTF member zero-length.
#[allow(non_camel_case_types)]
#[repr(C)]
struct m_array_of_maps_def {
    r#type: *const [i32; ARRAY_OF_MAPS],
    max_entries: *const [i32; 8],
    key: *const u32,
    value: *const u32,
    values: [*const inner_map; 9],
}
unsafe impl Sync for m_array_of_maps_def {}

#[link_section = ".maps"]
#[no_mangle]
static mut m_array_of_maps: m_array_of_maps_def = m_array_of_maps_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [
        &inner_map,
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
    ],
};

#[inline(always)]
fn check_array_of_maps() -> i32 {
    let array_of_maps = unsafe { &*(addr_of!(m_array_of_maps) as *const _ as *const bpf_array) };
    let map = addr_of!(m_array_of_maps) as *const _ as *const bpf_map;
    let key: i32 = 0;

    verify!(373, check_default(as_map(array_of_maps), map) != 0);
    let inner = bpf_map_lookup_elem(addr_of!(m_array_of_maps), &key) as *const bpf_array;
    verify!(375, !inner.is_null());
    verify!(376, unsafe { rd((*inner).map().max_entries().as_ptr()) } == INNER_MAX_ENTRIES);

    1
}

// .values = { [2] = &inner_map }: three slots.
#[allow(non_camel_case_types)]
#[repr(C)]
struct m_hash_of_maps_def {
    r#type: *const [i32; HASH_OF_MAPS],
    max_entries: *const [i32; 8],
    key: *const u32,
    value: *const u32,
    values: [*const inner_map; 3],
}
unsafe impl Sync for m_hash_of_maps_def {}

#[link_section = ".maps"]
#[no_mangle]
static mut m_hash_of_maps: m_hash_of_maps_def = m_hash_of_maps_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    values: [core::ptr::null(), core::ptr::null(), &inner_map],
};

#[inline(always)]
fn check_hash_of_maps() -> i32 {
    let hash_of_maps = unsafe { &*(addr_of!(m_hash_of_maps) as *const _ as *const bpf_htab) };
    let map = addr_of!(m_hash_of_maps) as *const _ as *const bpf_map;
    let key: i32 = 2;

    verify!(400, check_default(as_map(hash_of_maps), map) != 0);
    let inner = bpf_map_lookup_elem(addr_of!(m_hash_of_maps), &key) as *const bpf_htab;
    verify!(402, !inner.is_null());
    verify!(403, unsafe { rd((*inner).map().max_entries().as_ptr()) } == INNER_MAX_ENTRIES);

    1
}

#[btf]
struct bpf_dtab {
    map: bpf_map,
}

const DEVMAP: usize = 14;

#[link_section = ".maps"]
#[no_mangle]
static mut m_devmap: BpfMap<u32, u32, DEVMAP, 8> = BpfMap::new();

#[inline(always)]
fn check_devmap() -> i32 {
    let devmap = unsafe { &*(addr_of!(m_devmap) as *const _ as *const bpf_dtab) };
    let map = addr_of!(m_devmap) as *const _ as *const bpf_map;

    verify!(424, check_default(as_map(devmap), map) != 0);

    1
}

#[btf]
struct bpf_stab {
    map: bpf_map,
}

const SOCKMAP: usize = 15;

#[link_section = ".maps"]
#[no_mangle]
static mut m_sockmap: BpfMap<u32, u32, SOCKMAP, 8> = BpfMap::new();

#[inline(always)]
fn check_sockmap() -> i32 {
    let sockmap = unsafe { &*(addr_of!(m_sockmap) as *const _ as *const bpf_stab) };
    let map = addr_of!(m_sockmap) as *const _ as *const bpf_map;

    verify!(445, check_default(as_map(sockmap), map) != 0);

    1
}

#[btf]
struct bpf_cpu_map {
    map: bpf_map,
}

const CPUMAP: usize = 16;

#[link_section = ".maps"]
#[no_mangle]
static mut m_cpumap: BpfMap<u32, u32, CPUMAP, 8> = BpfMap::new();

#[inline(always)]
fn check_cpumap() -> i32 {
    let cpumap = unsafe { &*(addr_of!(m_cpumap) as *const _ as *const bpf_cpu_map) };
    let map = addr_of!(m_cpumap) as *const _ as *const bpf_map;

    verify!(466, check_default(as_map(cpumap), map) != 0);

    1
}

#[btf]
struct xsk_map {
    map: bpf_map,
}

const XSKMAP: usize = 17;

#[link_section = ".maps"]
#[no_mangle]
static mut m_xskmap: BpfMap<u32, u32, XSKMAP, 8> = BpfMap::new();

#[inline(always)]
fn check_xskmap() -> i32 {
    let xskmap = unsafe { &*(addr_of!(m_xskmap) as *const _ as *const xsk_map) };
    let map = addr_of!(m_xskmap) as *const _ as *const bpf_map;

    verify!(487, check_default(as_map(xskmap), map) != 0);

    1
}

#[btf]
struct bpf_shtab {
    map: bpf_map,
}

const SOCKHASH: usize = 18;

#[link_section = ".maps"]
#[no_mangle]
static mut m_sockhash: BpfMap<u32, u32, SOCKHASH, 8> = BpfMap::new();

#[inline(always)]
fn check_sockhash() -> i32 {
    let sockhash = unsafe { &*(addr_of!(m_sockhash) as *const _ as *const bpf_shtab) };
    let map = addr_of!(m_sockhash) as *const _ as *const bpf_map;

    verify!(508, check_default(as_map(sockhash), map) != 0);

    1
}

#[btf]
struct bpf_cgroup_storage_map {
    map: bpf_map,
}

// The UAPI key type, only ever a map's declared key: the tail padding is
// never instantiated.
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_cgroup_storage_key {
    cgroup_inode_id: u64,
    attach_type: u32,
}

const CGROUP_STORAGE: usize = 19;

map_def! {
    m_cgroup_storage {
        r#type: *const [i32; CGROUP_STORAGE],
        key: *const bpf_cgroup_storage_key,
        value: *const u32,
    }
}

#[inline(always)]
fn check_cgroup_storage() -> i32 {
    let cgroup_storage = unsafe { &*(addr_of!(m_cgroup_storage) as *const _ as *const bpf_cgroup_storage_map) };
    let map = addr_of!(m_cgroup_storage) as *const _ as *const bpf_map;

    verify!(
        529,
        check(
            as_map(cgroup_storage),
            map,
            core::mem::size_of::<bpf_cgroup_storage_key>() as u32,
            4,
            0
        ) != 0
    );

    1
}

#[btf]
struct reuseport_array {
    map: bpf_map,
}

const REUSEPORT_SOCKARRAY: usize = 20;

#[link_section = ".maps"]
#[no_mangle]
static mut m_reuseport_sockarray: BpfMap<u32, u32, REUSEPORT_SOCKARRAY, 8> = BpfMap::new();

#[inline(always)]
fn check_reuseport_sockarray() -> i32 {
    let reuseport_sockarray =
        unsafe { &*(addr_of!(m_reuseport_sockarray) as *const _ as *const reuseport_array) };
    let map = addr_of!(m_reuseport_sockarray) as *const _ as *const bpf_map;

    verify!(552, check_default(as_map(reuseport_sockarray), map) != 0);

    1
}

const PERCPU_CGROUP_STORAGE: usize = 21;

map_def! {
    m_percpu_cgroup_storage {
        r#type: *const [i32; PERCPU_CGROUP_STORAGE],
        key: *const bpf_cgroup_storage_key,
        value: *const u32,
    }
}

#[inline(always)]
fn check_percpu_cgroup_storage() -> i32 {
    let percpu_cgroup_storage =
        unsafe { &*(addr_of!(m_percpu_cgroup_storage) as *const _ as *const bpf_cgroup_storage_map) };
    let map = addr_of!(m_percpu_cgroup_storage) as *const _ as *const bpf_map;

    verify!(
        569,
        check(
            as_map(percpu_cgroup_storage),
            map,
            core::mem::size_of::<bpf_cgroup_storage_key>() as u32,
            4,
            0
        ) != 0
    );

    1
}

#[btf]
struct bpf_queue_stack {
    map: bpf_map,
}

const QUEUE: usize = 22;
const STACK: usize = 23;

map_def! {
    m_queue {
        r#type: *const [i32; QUEUE],
        max_entries: *const [i32; 8],
        value: *const u32,
    }
}

#[inline(always)]
fn check_queue() -> i32 {
    let queue = unsafe { &*(addr_of!(m_queue) as *const _ as *const bpf_queue_stack) };
    let map = addr_of!(m_queue) as *const _ as *const bpf_map;

    verify!(590, check(as_map(queue), map, 0, 4, MAX_ENTRIES) != 0);

    1
}

map_def! {
    m_stack {
        r#type: *const [i32; STACK],
        max_entries: *const [i32; 8],
        value: *const u32,
    }
}

#[inline(always)]
fn check_stack() -> i32 {
    let stack = unsafe { &*(addr_of!(m_stack) as *const _ as *const bpf_queue_stack) };
    let map = addr_of!(m_stack) as *const _ as *const bpf_map;

    verify!(606, check(as_map(stack), map, 0, 4, MAX_ENTRIES) != 0);

    1
}

#[btf]
struct bpf_local_storage_map {
    map: bpf_map,
}

const SK_STORAGE: usize = 24;

map_def! {
    m_sk_storage {
        r#type: *const [i32; SK_STORAGE],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const u32,
        value: *const u32,
    }
}

#[inline(always)]
fn check_sk_storage() -> i32 {
    let sk_storage = unsafe { &*(addr_of!(m_sk_storage) as *const _ as *const bpf_local_storage_map) };
    let map = addr_of!(m_sk_storage) as *const _ as *const bpf_map;

    verify!(628, check(as_map(sk_storage), map, 4, 4, 0) != 0);

    1
}

const DEVMAP_HASH: usize = 25;

#[link_section = ".maps"]
#[no_mangle]
static mut m_devmap_hash: BpfMap<u32, u32, DEVMAP_HASH, 8> = BpfMap::new();

#[inline(always)]
fn check_devmap_hash() -> i32 {
    let devmap_hash = unsafe { &*(addr_of!(m_devmap_hash) as *const _ as *const bpf_dtab) };
    let map = addr_of!(m_devmap_hash) as *const _ as *const bpf_map;

    verify!(645, check_default(as_map(devmap_hash), map) != 0);

    1
}

#[btf]
struct bpf_ringbuf {
    consumer_pos: u64,
    producer_pos: u64,
}

#[btf]
struct bpf_ringbuf_map {
    map: bpf_map,
    rb: *mut bpf_ringbuf,
}

map_def! {
    m_ringbuf {
        r#type: *const [i32; maps::RINGBUF],
    }
}

#[inline(always)]
fn check_ringbuf() -> i32 {
    let ringbuf = unsafe { &*(addr_of!(m_ringbuf) as *const _ as *const bpf_ringbuf_map) };
    let map = addr_of!(m_ringbuf) as *const _ as *const bpf_map;

    verify!(671, check(as_map(ringbuf), map, 0, 0, unsafe { page_size } as u32) != 0);

    let ptr = bpf_ringbuf_reserve(addr_of!(m_ringbuf), 128, 0);
    verify!(674, !ptr.is_null());

    bpf_ringbuf_discard(ptr, 0);
    let rb = unsafe { rd(ringbuf.rb().as_ptr()) };
    verify!(678, !rb.is_null());
    let rb = unsafe { &*rb };
    verify!(679, unsafe { rd(rb.consumer_pos().as_ptr()) } == 0);
    verify!(680, unsafe { rd(rb.producer_pos().as_ptr()) } == 128 + BPF_RINGBUF_HDR_SZ);

    1
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn cg_skb(_ctx: *const c_void) -> i32 {
    verify_type!(BPF_MAP_TYPE_HASH, check_hash);
    verify_type!(BPF_MAP_TYPE_ARRAY, check_array);
    verify_type!(BPF_MAP_TYPE_PROG_ARRAY, check_prog_array);
    verify_type!(BPF_MAP_TYPE_PERF_EVENT_ARRAY, check_perf_event_array);
    verify_type!(BPF_MAP_TYPE_PERCPU_HASH, check_percpu_hash);
    verify_type!(BPF_MAP_TYPE_PERCPU_ARRAY, check_percpu_array);
    verify_type!(BPF_MAP_TYPE_STACK_TRACE, check_stack_trace);
    verify_type!(BPF_MAP_TYPE_CGROUP_ARRAY, check_cgroup_array);
    verify_type!(BPF_MAP_TYPE_LRU_HASH, check_lru_hash);
    verify_type!(BPF_MAP_TYPE_LRU_PERCPU_HASH, check_lru_percpu_hash);
    verify_type!(BPF_MAP_TYPE_LPM_TRIE, check_lpm_trie);
    verify_type!(BPF_MAP_TYPE_ARRAY_OF_MAPS, check_array_of_maps);
    verify_type!(BPF_MAP_TYPE_HASH_OF_MAPS, check_hash_of_maps);
    verify_type!(BPF_MAP_TYPE_DEVMAP, check_devmap);
    verify_type!(BPF_MAP_TYPE_SOCKMAP, check_sockmap);
    verify_type!(BPF_MAP_TYPE_CPUMAP, check_cpumap);
    verify_type!(BPF_MAP_TYPE_XSKMAP, check_xskmap);
    verify_type!(BPF_MAP_TYPE_SOCKHASH, check_sockhash);
    verify_type!(BPF_MAP_TYPE_CGROUP_STORAGE, check_cgroup_storage);
    verify_type!(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY, check_reuseport_sockarray);
    verify_type!(BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE, check_percpu_cgroup_storage);
    verify_type!(BPF_MAP_TYPE_QUEUE, check_queue);
    verify_type!(BPF_MAP_TYPE_STACK, check_stack);
    verify_type!(BPF_MAP_TYPE_SK_STORAGE, check_sk_storage);
    verify_type!(BPF_MAP_TYPE_DEVMAP_HASH, check_devmap_hash);
    verify_type!(BPF_MAP_TYPE_RINGBUF, check_ringbuf);

    1
}

bpf_object!("GPL");
