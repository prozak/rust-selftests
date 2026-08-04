#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/btf_dump_test_case_syntax.c
// (bpf-rs-core idiom).
//
// UNFIXABLE. This file has no SEC() program at all: it exists purely so
// prog_tests/btf_dump.c can btf__parse_elf() the compiled object, walk
// every BTF type ID from 1..type_cnt with btf_dump__dump_type(), and
// byte-diff the resulting C-syntax text against the START/END-EXPECTED-
// OUTPUT comment blocks embedded in the *original* .c source (the test
// always reads progs/btf_dump_test_case_syntax.c from the kernel tree for
// the expected text, never this file, so the .rs translation is scored
// purely on its BTF shape).
//
// Confirmed by direct experiment (see bld/ build of trial versions of this
// file): rustc's DWARF->BTF pipeline (shared LLVM BTFDebug backend, same
// as clang) never emits:
//   - BTF_KIND_TYPEDEF for a Rust `type X = Y;` alias. Rust resolves type
//     aliases entirely at the front end; no distinct debuginfo node
//     survives to codegen for it, with or without the alias being used as
//     a field/parameter type. Verified: `type crazy_ptr_t = *const i32;`
//     used as a struct field compiles to a bare PTR->INT chain, with no
//     TYPEDEF node anywhere in the object's BTF.
//   - BTF_KIND_CONST / BTF_KIND_VOLATILE wrapping a pointee. Rust has no
//     type-level cv-qualification independent of pointer kind (`*const T`
//     is a distinct pointer *kind*, not a qualified-T pointee) and no
//     `restrict` concept at all. Verified: a `&'static i32` field (the
//     closest Rust has to a "const pointer") also compiles to a bare
//     PTR->INT chain with no CONST node.
// This single file's entire premise (per its own top comment, "BTF-to-C
// dumper test for majority of C syntax quirks") is dumping ~30 `typedef`
// declarations, most wrapped in multiple layers of const/volatile/restrict
// (e.g. `typedef volatile const we_need_to_go_deeper_ptr_t * restrict *
// volatile * const * restrict volatile * restrict const * volatile const *
// restrict volatile const how_about_this_ptr_t;`), plus C-only
// `__attribute__((mode(byte/word)))` enum backing-size overrides, `struct
// struct_fwd;` opaque forward declarations, and anonymous struct/union
// *named* fields (`struct { int a; } not_so_hard_as_well;` – Rust field
// types must be nominal, so any Rust struct standing in for one carries a
// name and shows up as a named STRUCT, not `(anon)`). None of these BTF
// kinds/shapes are reachable from Rust source through this pipeline; there
// is no bpf-rs-core/btf-macros escape hatch for hand-authoring fresh local
// BTF (the `#[btf]` macro only lowers to CO-RE *relocations* against
// already-existing kernel BTF, it cannot synthesize new TYPEDEF/CONST/
// VOLATILE/FWD entries in this object's own .BTF). The very first typedef
// (`typedef enum e2 e2_t;`, right after `enum e1`/`enum e2`) already
// diverges, so the exact-text diff cannot pass regardless of how faithfully
// the rest of the type graph is reproduced structurally below.

use bpf_rs_core::bpf_object;

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum e1 {
    A = 0,
    B = 1,
}

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum e2 {
    C = 100,
    D = 4294967295,
    E = 0,
}

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum e3 {
    F = 0,
    G = 1,
    H = 2,
}

#[allow(non_camel_case_types)]
#[repr(i8)]
pub enum e_byte {
    EBYTE_1 = 0,
    EBYTE_2 = 1,
}

#[allow(non_camel_case_types)]
#[repr(i64)]
pub enum e_word {
    EWORD_1 = 0,
    EWORD_2 = 1,
}

#[allow(non_camel_case_types)]
#[repr(u64)]
pub enum e_big {
    EBIG_1 = 1_000_000_000_000,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct anon_struct_t {
    pub x: i32,
    pub y: i32,
    pub z: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct struct_fwd {
    _unused: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct union_fwd {
    _unused: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct struct_empty {}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct anon_val_enum {
    _unused: [u8; 0],
}

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum anon_val {
    ANON_VAL1 = 1,
    ANON_VAL2 = 2,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct struct_simple {
    pub a: i32,
    pub b: i8,
    pub p: *const i32,
    pub s: struct_empty,
    pub e: e2,
    pub f: anon_val,
    pub arr1: [i32; 13],
    pub arr2: [e2; 5],
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub union union_empty {
    _unused: u8,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub union union_simple {
    pub ptr: *mut core::ffi::c_void,
    pub num: i32,
    pub num2: i32,
    pub u: core::mem::ManuallyDrop<union_empty>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct not_so_hard_as_well {
    pub a: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub union anon_union_is_good {
    pub b: i32,
    pub c: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct struct_in_struct {
    pub simple: struct_simple,
    pub also_simple: union_simple,
    pub not_so_hard_as_well: not_so_hard_as_well,
    pub anon_union_is_good: core::mem::ManuallyDrop<anon_union_is_good>,
    pub d: i32,
    pub e: i32,
    pub f: i32,
    pub g: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct struct_in_array {}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct struct_in_array_typed {}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct float_struct {
    pub f: f32,
    pub d: *const f64,
    pub ld: *mut u128,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct nested_e {
    pub c: *mut struct_with_embedded_stuff,
    pub d: *const i8,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub union nested_fg {
    pub f: i64,
    pub g: *mut core::ffi::c_void,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct nested_b {
    pub b: i32,
    pub e: nested_e,
    pub fg: core::mem::ManuallyDrop<nested_fg>,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub union nested_hi {
    pub h: *const i32,
    pub i: extern "C" fn(i8, i32, *mut core::ffi::c_void),
}

#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum nested_m {
    K = 100,
    L = 200,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct nested_r {
    pub o: i8,
    pub p: i32,
    pub q: extern "C" fn(i32),
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct struct_with_embedded_stuff {
    pub a: i32,
    pub nested_b: nested_b,
    pub j: core::mem::ManuallyDrop<nested_hi>,
    pub m: nested_m,
    pub n: [i8; 16],
    pub r: [nested_r; 5],
    pub s: [struct_in_struct; 10],
    pub t: [i32; 11],
    pub u: *mut [struct_in_array; 2],
    pub v: *mut [struct_in_array_typed; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct struct_w_typedefs {
    pub a: i32,
    pub b: *const i32,
    pub c: *const *const *const *const *const i32,
    pub d: *const *const *const *const *const *const i32,
    pub e: [*mut i32; 10],
    pub f: extern "C" fn(i32),
    pub g: extern "C" fn(*const i8),
    pub h: extern "C" fn(not_so_hard_as_well, extern "C" fn(i32)) -> *const *mut i8,
    pub i: extern "C" fn(nested_fg, not_so_hard_as_well) -> nested_b,
    pub j: extern "C" fn(i32, extern "C" fn(i32)) -> extern "C" fn(i32),
    pub k: [extern "C" fn(*mut *mut i32) -> *mut i8; 10],
    pub l: [extern "C" fn() -> extern "C" fn(extern "C" fn(i32) -> *mut i8) -> *mut i8; 5],
}

#[repr(C)]
pub struct root_struct {
    pub _1: e1,
    pub _2: e2,
    pub _2_1: e2,
    pub _2_2: e3,
    pub _100: e_byte,
    pub _101: e_word,
    pub _102: e_big,
    pub _3: struct_w_typedefs,
    pub _7: anon_struct_t,
    pub _8: *mut struct_fwd,
    pub _9: *mut struct_fwd,
    pub _10: *mut struct_fwd,
    pub _11: *mut union_fwd,
    pub _12: *mut union_fwd,
    pub _13: *mut union_fwd,
    pub _14: struct_with_embedded_stuff,
    pub _15: float_struct,
}

#[no_mangle]
extern "C" fn f(s: *mut root_struct) -> i32 {
    let _ = s;
    0
}

bpf_object!("GPL");
