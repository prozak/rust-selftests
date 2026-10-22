// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of progs/test_core_reloc_type_id.c (bpf-rs-core idiom).
//
// The C's bpf_core_type_id_local() / bpf_core_type_id_kernel() on bare types
// are TYPE_ID_LOCAL / TYPE_ID_TARGET CO-RE relocations; prog_tests/core_reloc.c
// checks every local id against the object's own BTF (the FIRST type of that
// name and kind, or the LAST anonymous type of that shape) and every target
// id against the case's target BTF. Each is a `// BTF_TYPE_ID:` extern below.
// The Rust object defines none of these types itself: every local one is a
// full copy of the C object's type (`(copy)`), so each name / shape occurs
// exactly once in the BTF; `int` reuses rustc's own 32-bit integer, which is
// the first `int` in the table (the program's return type).
// BTF_TYPE_ID: local_anon_struct local struct struct { int marker_field; } (copy)
// BTF_TYPE_ID: local_anon_union local union union { int marker_field; } (copy)
// BTF_TYPE_ID: local_anon_enum local enum enum { MARKER_ENUM_VAL } (copy)
// BTF_TYPE_ID: local_anon_func_proto_ptr local ptr _Bool (*)(int) (copy)
// BTF_TYPE_ID: local_anon_void_ptr local ptr void * (copy)
// BTF_TYPE_ID: local_anon_arr local array _Bool[47] (copy)
// BTF_TYPE_ID: local_struct local struct a_struct (copy)
// BTF_TYPE_ID: local_union local union a_union (copy)
// BTF_TYPE_ID: local_enum local enum an_enum (copy)
// BTF_TYPE_ID: local_int local int int
// BTF_TYPE_ID: local_struct_typedef local typedef named_struct_typedef (copy)
// BTF_TYPE_ID: local_func_proto_typedef local typedef func_proto_typedef (copy)
// BTF_TYPE_ID: local_arr_typedef local typedef arr_typedef (copy)
// BTF_TYPE_ID: targ_struct struct a_struct
// BTF_TYPE_ID: targ_union union a_union
// BTF_TYPE_ID: targ_enum enum an_enum
// BTF_TYPE_ID: targ_int int int
// BTF_TYPE_ID: targ_struct_typedef typedef named_struct_typedef
// BTF_TYPE_ID: targ_func_proto_typedef typedef func_proto_typedef
// BTF_TYPE_ID: targ_arr_typedef typedef arr_typedef

use bpf_rs_core::bpf_object;

extern "C" {
    fn local_anon_struct() -> u64;
    fn local_anon_union() -> u64;
    fn local_anon_enum() -> u64;
    fn local_anon_func_proto_ptr() -> u64;
    fn local_anon_void_ptr() -> u64;
    fn local_anon_arr() -> u64;
    fn local_struct() -> u64;
    fn local_union() -> u64;
    fn local_enum() -> u64;
    fn local_int() -> u64;
    fn local_struct_typedef() -> u64;
    fn local_func_proto_typedef() -> u64;
    fn local_arr_typedef() -> u64;
    fn targ_struct() -> u64;
    fn targ_union() -> u64;
    fn targ_enum() -> u64;
    fn targ_int() -> u64;
    fn targ_struct_typedef() -> u64;
    fn targ_func_proto_typedef() -> u64;
    fn targ_arr_typedef() -> u64;
}

#[repr(C)]
struct Data {
    input: [u8; 256],
    output: [u8; 256],
    skip: bool,
}

#[no_mangle]
static mut data: Data = Data {
    input: [0; 256],
    output: [0; 256],
    skip: false,
};

#[repr(C)]
struct Output {
    local_anon_struct: i32,
    local_anon_union: i32,
    local_anon_enum: i32,
    local_anon_func_proto_ptr: i32,
    local_anon_void_ptr: i32,
    local_anon_arr: i32,

    local_struct: i32,
    local_union: i32,
    local_enum: i32,
    local_int: i32,
    local_struct_typedef: i32,
    local_func_proto_typedef: i32,
    local_arr_typedef: i32,

    targ_struct: i32,
    targ_union: i32,
    targ_enum: i32,
    targ_int: i32,
    targ_struct_typedef: i32,
    targ_func_proto_typedef: i32,
    targ_arr_typedef: i32,
}

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn test_core_type_id(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        let out = core::ptr::addr_of_mut!(data.output) as *mut Output;
        (*out).local_anon_struct = local_anon_struct() as i32;
        (*out).local_anon_union = local_anon_union() as i32;
        (*out).local_anon_enum = local_anon_enum() as i32;
        (*out).local_anon_func_proto_ptr = local_anon_func_proto_ptr() as i32;
        (*out).local_anon_void_ptr = local_anon_void_ptr() as i32;
        (*out).local_anon_arr = local_anon_arr() as i32;

        (*out).local_struct = local_struct() as i32;
        (*out).local_union = local_union() as i32;
        (*out).local_enum = local_enum() as i32;
        (*out).local_int = local_int() as i32;
        (*out).local_struct_typedef = local_struct_typedef() as i32;
        (*out).local_func_proto_typedef = local_func_proto_typedef() as i32;
        (*out).local_arr_typedef = local_arr_typedef() as i32;

        (*out).targ_struct = targ_struct() as i32;
        (*out).targ_union = targ_union() as i32;
        (*out).targ_enum = targ_enum() as i32;
        (*out).targ_int = targ_int() as i32;
        (*out).targ_struct_typedef = targ_struct_typedef() as i32;
        (*out).targ_func_proto_typedef = targ_func_proto_typedef() as i32;
        (*out).targ_arr_typedef = targ_arr_typedef() as i32;
    }
    0
}

bpf_object!("GPL");
