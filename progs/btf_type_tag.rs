#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/btf_type_tag.c
//
// The C source's btf_type_tag attribute chain (`int __tag1 * __tag1 __tag2
// *p`) only exists to exercise BTF_KIND_TYPE_TAG emission; rustc cannot
// emit that BTF kind (see memory: btf-type-tag-uptr-kptr-unfixable), so
// this is always the `#else` branch: skip_tests = true and `g.p` is a
// plain `int **` with no tags. prog_tests/btf_tag.c's test_btf_type_tag()
// only asserts open_and_load succeeds and then checks skip_tests to decide
// whether to skip further (tag-dependent) assertions, so this still
// satisfies the contract.

use bpf_rs_core::bpf_object;

#[link_section = ".rodata"]
#[no_mangle]
static skip_tests: bool = true;

struct btf_type_tag_test {
    p: *mut *mut i32,
}

#[no_mangle]
static mut g: btf_type_tag_test = btf_type_tag_test {
    p: core::ptr::null_mut(),
};

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn sub(_ctx: *const u64) -> i32 {
    0
}

bpf_object!("GPL");
