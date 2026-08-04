#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/timer_mim_reject.c
// (bpf-rs-core idiom).
//
// This is a negative-verifier-load test consumed by prog_tests/timer_mim.c's
// serial_test_timer_mim(): timer_mim_reject__open_and_load() must fail
// (ASSERT_ERR_PTR), because test1 initializes a timer stored in the map
// value looked up from outer_arr[ARRAY_KEY] (inner_htab) but passes
// inner_map2 (looked up from outer_arr[ARRAY_KEY2]) as the owning map to
// bpf_timer_init() — a map-identity mismatch the verifier must reject at
// load time, independent of the null checks' runtime reachability.
//
// outer_arr is BPF_MAP_TYPE_ARRAY_OF_MAPS with a static
// `.values = {[ARRAY_KEY] = &inner_htab}` designated initializer; rustc
// can't replicate Clang's divergent codegen/debuginfo sizing for that
// flexible-array-member trick (see prog-array-static-values-init-unfixable
// memory), so the values array here stays zero-length and the slots go
// unpopulated at load time — same workaround as inner_array_lookup.rs /
// update_map_in_htab.rs.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_map_update_elem, bpf_timer_init, bpf_timer_set_callback,
    bpf_timer_start,
};
use bpf_rs_core::maps::{self, BpfMap};

const CLOCK_MONOTONIC: u64 = 1;
const ARRAY_KEY: i32 = 1;
const ARRAY_KEY2: i32 = 2;
const HASH_KEY: i32 = 1234;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

// struct hmap_elem { int pad; struct bpf_timer timer; };
#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct hmap_elem {
    pad: i32,
    timer: bpf_timer,
}

// struct inner_map { __uint(type, HASH); __uint(max_entries, 1024);
// __type(key, int); __type(value, struct hmap_elem); } inner_htab SEC(".maps");
type InnerMap = BpfMap<i32, hmap_elem, { maps::HASH }, 1024>;

#[link_section = ".maps"]
#[no_mangle]
static inner_htab: InnerMap = InnerMap::new();

// struct outer_arr { __uint(type, ARRAY_OF_MAPS); __uint(max_entries, 2);
// __uint(key_size, sizeof(int)); __uint(value_size, sizeof(int));
// __array(values, struct inner_map); } outer_arr SEC(".maps") = {
//     .values = { [ARRAY_KEY] = &inner_htab },
// };
#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_arr_def {
    r#type: *const [i32; 12], // BPF_MAP_TYPE_ARRAY_OF_MAPS
    max_entries: *const [i32; 2],
    key_size: *const [i32; 4],
    value_size: *const [i32; 4],
    values: [*const InnerMap; 0],
}
unsafe impl Sync for outer_arr_def {}

#[link_section = ".maps"]
#[no_mangle]
static outer_arr: outer_arr_def = outer_arr_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    value_size: core::ptr::null(),
    values: [],
};

#[no_mangle]
static mut err: u64 = 0;
#[no_mangle]
static mut ok: u64 = 0;
#[no_mangle]
static mut cnt: u64 = 0;

/// callback for inner hash map
extern "C" fn timer_cb(_map: *mut InnerMap, _key: *mut i32, _val: *mut hmap_elem) -> i64 {
    0
}

/// BPF_PROG(test1, int a)
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(_ctx: *const u64) -> i32 {
    let init = hmap_elem {
        pad: 0,
        timer: bpf_timer { __opaque: [0; 2] },
    };
    let array_key: i32 = ARRAY_KEY;
    let array_key2: i32 = ARRAY_KEY2;
    let hash_key: i32 = HASH_KEY;

    let inner_map = bpf_map_lookup_elem(&outer_arr, &array_key) as *mut InnerMap;
    if inner_map.is_null() {
        return 0;
    }

    let inner_map2 = bpf_map_lookup_elem(&outer_arr, &array_key2) as *mut InnerMap;
    if inner_map2.is_null() {
        return 0;
    }
    bpf_map_update_elem(inner_map, &hash_key, &init, 0);
    let val = bpf_map_lookup_elem(inner_map, &hash_key) as *mut hmap_elem;
    if val.is_null() {
        return 0;
    }

    unsafe {
        bpf_timer_init(
            core::ptr::addr_of_mut!((*val).timer),
            inner_map2,
            CLOCK_MONOTONIC,
        );
        if bpf_timer_set_callback(core::ptr::addr_of_mut!((*val).timer), timer_cb) != 0 {
            err |= 4;
        }
        if bpf_timer_start(core::ptr::addr_of_mut!((*val).timer), 0, 0) != 0 {
            err |= 8;
        }
    }
    0
}

bpf_object!("GPL");
