#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_btf_newkv.c
// (bpf-rs-core idiom).
//
// prog_tests/btf.c's do_test_file() loads this object directly (not via a
// generated skeleton) and asserts: btf_map's BTF key/value type ids are
// both nonzero, and info.nr_func_info == 3 with func names
// {_dummy_tracepoint, test_long_fname_1, test_long_fname_2} (the latter two
// may appear in either order). That means test_long_fname_1/2 must stay
// distinct, non-inlined, named BPF subprograms exactly like C's
// __attribute__((noinline)) -- #[inline(never)] extern "C" fn, same idiom
// as test_btf_ext.rs's f0().

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_lookup_elem;
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

#[repr(C)]
struct ipv_counts {
    v4: u32,
    v6: u32,
}

#[link_section = ".maps"]
#[no_mangle]
static btf_map: BpfMap<i32, ipv_counts, { maps::ARRAY }, 4> = BpfMap::new();

#[no_mangle]
#[inline(never)]
extern "C" fn test_long_fname_2() -> i32 {
    let key: i32 = 0;
    let counts = bpf_map_lookup_elem(&btf_map, &key) as *mut ipv_counts;
    if counts.is_null() {
        return 0;
    }

    unsafe {
        (*counts).v6 += 1;
    }

    0
}

#[no_mangle]
#[inline(never)]
extern "C" fn test_long_fname_1() -> i32 {
    test_long_fname_2()
}

#[link_section = "dummy_tracepoint"]
#[no_mangle]
extern "C" fn _dummy_tracepoint(_arg: *const c_void) -> i32 {
    test_long_fname_1()
}

bpf_object!("GPL");
