#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_subskeleton_lib2.c (bpf-rs-core
// idiom). No programs: one global and one map, both read back through the
// subskeleton by prog_tests/subskeleton.c.

#![allow(non_upper_case_globals)]

use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::bpf_object;

#[no_mangle]
static mut var6: i32 = 6;

#[link_section = ".maps"]
#[no_mangle]
static map2: BpfMap<u32, u32, { maps::HASH }, 16> = BpfMap::new();

bpf_object!("GPL");
