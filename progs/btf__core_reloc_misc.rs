#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/btf__core_reloc_misc.c, bpf-rs-core
// idiom.
//
// This object is never loaded/run: prog_tests/core_reloc.c's "misc" case
// only opens it as a `btf_src_file` (btf__parse) to source CO-RE candidate
// types by name for the real program in test_core_reloc_misc.bpf.o. So the
// only requirement is that the compiled object's BTF contains
// core_reloc_misc___a/___b/_extensible with the exact field layout below,
// referenced from global functions (matching the C original's plain,
// SEC()-less functions, which just force clang/rustc to emit the types).
//
// core_reloc_types.h (`#include`d by the C source) also defines a shared
// `preserce_ptr_sz_fn(long x)` used across the whole btf__core_reloc_*
// family to force BTF emission of `long`; reproduced here for the same
// reason (isize -> btf_rename -> "long", see TRANSLATING.md).

use bpf_rs_core::bpf_object;

#[allow(unused_variables)]
#[no_mangle]
extern "C" fn preserce_ptr_sz_fn(x: isize) {}

#[allow(non_camel_case_types)]
#[repr(C)]
struct core_reloc_misc___a {
    a1: i32,
    a2: i32,
}

#[allow(unused_variables)]
#[no_mangle]
extern "C" fn f1(x: core_reloc_misc___a) {}

#[allow(non_camel_case_types)]
#[repr(C)]
struct core_reloc_misc___b {
    b1: i32,
    b2: i32,
}

#[allow(unused_variables)]
#[no_mangle]
extern "C" fn f2(x: core_reloc_misc___b) {}

#[allow(non_camel_case_types)]
#[repr(C)]
struct core_reloc_misc_extensible {
    a: i32,
    b: i32,
    c: i32,
    d: i32,
}

#[allow(unused_variables)]
#[no_mangle]
extern "C" fn f3(x: core_reloc_misc_extensible) {}

bpf_object!("GPL");
