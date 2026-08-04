#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_btf_decl_tag.c
// (bpf-rs-core idiom).
//
// The C source is guarded by `#if __has_attribute(btf_decl_tag)`: when the
// compiler can emit BTF_KIND_DECL_TAG it tags skip_tests/key_t.b/value_t/foo
// with __tag1/__tag2 and leaves skip_tests false; otherwise it falls back to
// `bool skip_tests = true;` with no tags at all, and prog_tests/btf_tag.c's
// test_btf_decl_tag() SKIPs on skip_tests. rustc cannot emit
// BTF_KIND_DECL_TAG (see TRANSLATING.md), so this takes that same fallback
// path: no tag attributes, skip_tests = true. The map/struct/program shapes
// still need to load cleanly since the test does open_and_load() before
// checking skip_tests.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_update_elem;
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;

#[link_section = ".rodata"]
#[no_mangle]
static skip_tests: bool = true;

#[repr(C)]
struct key_t {
    a: i32,
    b: i32,
    c: i32,
}

#[repr(C)]
struct value_t {
    a: i32,
    b: i32,
}

#[link_section = ".maps"]
#[no_mangle]
static hashmap1: BpfMap<key_t, value_t, { maps::HASH }, 3> = BpfMap::new();

#[inline(never)]
fn foo(x: i32) -> i32 {
    let key = key_t { a: x, b: x, c: x };
    let val = value_t { a: 0, b: 0 };
    bpf_map_update_elem(&hashmap1, &key, &val, 0);
    0
}

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn sub(ctx: *const u64) -> i32 {
    let x = arg(ctx, 0) as i32;
    foo(x)
}

bpf_object!("GPL");
