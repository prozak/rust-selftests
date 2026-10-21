// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of progs/test_core_reloc_type_based.c (bpf-rs-core idiom).
//
// The C's bpf_core_type_exists() / bpf_core_type_matches() /
// bpf_core_type_size() on bare type names are TYPE_EXISTS / TYPE_MATCHES /
// TYPE_SIZE CO-RE relocations the loader resolves against whatever target
// BTF prog_tests/core_reloc.c attaches (six variants of this one object).
// Each is a `// BTF_TYPE_INFO:` extern below: scripts/type_id.py replaces
// the call by LLVM's preserve.type.info intrinsic on a full copy of the C
// object's local type (members, func protos, qualifiers), so the Rust
// object carries the same 37 relocations on the same type shapes.
// BTF_TYPE_INFO: struct_exists exists struct a_struct
// BTF_TYPE_INFO: complex_struct_exists exists struct a_complex_struct
// BTF_TYPE_INFO: union_exists exists union a_union
// BTF_TYPE_INFO: enum_exists exists enum an_enum
// BTF_TYPE_INFO: typedef_named_struct_exists exists typedef named_struct_typedef
// BTF_TYPE_INFO: typedef_anon_struct_exists exists typedef anon_struct_typedef
// BTF_TYPE_INFO: typedef_struct_ptr_exists exists typedef struct_ptr_typedef
// BTF_TYPE_INFO: typedef_int_exists exists typedef int_typedef
// BTF_TYPE_INFO: typedef_enum_exists exists typedef enum_typedef
// BTF_TYPE_INFO: typedef_void_ptr_exists exists typedef void_ptr_typedef
// BTF_TYPE_INFO: typedef_restrict_ptr_exists exists typedef restrict_ptr_typedef
// BTF_TYPE_INFO: typedef_func_proto_exists exists typedef func_proto_typedef
// BTF_TYPE_INFO: typedef_arr_exists exists typedef arr_typedef
// BTF_TYPE_INFO: struct_matches matches struct a_struct
// BTF_TYPE_INFO: complex_struct_matches matches struct a_complex_struct
// BTF_TYPE_INFO: union_matches matches union a_union
// BTF_TYPE_INFO: enum_matches matches enum an_enum
// BTF_TYPE_INFO: typedef_named_struct_matches matches typedef named_struct_typedef
// BTF_TYPE_INFO: typedef_anon_struct_matches matches typedef anon_struct_typedef
// BTF_TYPE_INFO: typedef_struct_ptr_matches matches typedef struct_ptr_typedef
// BTF_TYPE_INFO: typedef_int_matches matches typedef int_typedef
// BTF_TYPE_INFO: typedef_enum_matches matches typedef enum_typedef
// BTF_TYPE_INFO: typedef_void_ptr_matches matches typedef void_ptr_typedef
// BTF_TYPE_INFO: typedef_restrict_ptr_matches matches typedef restrict_ptr_typedef
// BTF_TYPE_INFO: typedef_func_proto_matches matches typedef func_proto_typedef
// BTF_TYPE_INFO: typedef_arr_matches matches typedef arr_typedef
// BTF_TYPE_INFO: struct_sz size struct a_struct
// BTF_TYPE_INFO: union_sz size union a_union
// BTF_TYPE_INFO: enum_sz size enum an_enum
// BTF_TYPE_INFO: typedef_named_struct_sz size typedef named_struct_typedef
// BTF_TYPE_INFO: typedef_anon_struct_sz size typedef anon_struct_typedef
// BTF_TYPE_INFO: typedef_struct_ptr_sz size typedef struct_ptr_typedef
// BTF_TYPE_INFO: typedef_int_sz size typedef int_typedef
// BTF_TYPE_INFO: typedef_enum_sz size typedef enum_typedef
// BTF_TYPE_INFO: typedef_void_ptr_sz size typedef void_ptr_typedef
// BTF_TYPE_INFO: typedef_func_proto_sz size typedef func_proto_typedef
// BTF_TYPE_INFO: typedef_arr_sz size typedef arr_typedef

use bpf_rs_core::bpf_object;

extern "C" {
    fn struct_exists() -> u32;
    fn complex_struct_exists() -> u32;
    fn union_exists() -> u32;
    fn enum_exists() -> u32;
    fn typedef_named_struct_exists() -> u32;
    fn typedef_anon_struct_exists() -> u32;
    fn typedef_struct_ptr_exists() -> u32;
    fn typedef_int_exists() -> u32;
    fn typedef_enum_exists() -> u32;
    fn typedef_void_ptr_exists() -> u32;
    fn typedef_restrict_ptr_exists() -> u32;
    fn typedef_func_proto_exists() -> u32;
    fn typedef_arr_exists() -> u32;
    fn struct_matches() -> u32;
    fn complex_struct_matches() -> u32;
    fn union_matches() -> u32;
    fn enum_matches() -> u32;
    fn typedef_named_struct_matches() -> u32;
    fn typedef_anon_struct_matches() -> u32;
    fn typedef_struct_ptr_matches() -> u32;
    fn typedef_int_matches() -> u32;
    fn typedef_enum_matches() -> u32;
    fn typedef_void_ptr_matches() -> u32;
    fn typedef_restrict_ptr_matches() -> u32;
    fn typedef_func_proto_matches() -> u32;
    fn typedef_arr_matches() -> u32;
    fn struct_sz() -> u32;
    fn union_sz() -> u32;
    fn enum_sz() -> u32;
    fn typedef_named_struct_sz() -> u32;
    fn typedef_anon_struct_sz() -> u32;
    fn typedef_struct_ptr_sz() -> u32;
    fn typedef_int_sz() -> u32;
    fn typedef_enum_sz() -> u32;
    fn typedef_void_ptr_sz() -> u32;
    fn typedef_func_proto_sz() -> u32;
    fn typedef_arr_sz() -> u32;
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
    struct_exists: bool,
    complex_struct_exists: bool,
    union_exists: bool,
    enum_exists: bool,
    typedef_named_struct_exists: bool,
    typedef_anon_struct_exists: bool,
    typedef_struct_ptr_exists: bool,
    typedef_int_exists: bool,
    typedef_enum_exists: bool,
    typedef_void_ptr_exists: bool,
    typedef_restrict_ptr_exists: bool,
    typedef_func_proto_exists: bool,
    typedef_arr_exists: bool,

    struct_matches: bool,
    complex_struct_matches: bool,
    union_matches: bool,
    enum_matches: bool,
    typedef_named_struct_matches: bool,
    typedef_anon_struct_matches: bool,
    typedef_struct_ptr_matches: bool,
    typedef_int_matches: bool,
    typedef_enum_matches: bool,
    typedef_void_ptr_matches: bool,
    typedef_restrict_ptr_matches: bool,
    typedef_func_proto_matches: bool,
    typedef_arr_matches: bool,

    struct_sz: i32,
    union_sz: i32,
    enum_sz: i32,
    typedef_named_struct_sz: i32,
    typedef_anon_struct_sz: i32,
    typedef_struct_ptr_sz: i32,
    typedef_int_sz: i32,
    typedef_enum_sz: i32,
    typedef_void_ptr_sz: i32,
    typedef_func_proto_sz: i32,
    typedef_arr_sz: i32,
}

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn test_core_type_based(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        let out = core::ptr::addr_of_mut!(data.output) as *mut Output;
        (*out).struct_exists = struct_exists() != 0;
        (*out).complex_struct_exists = complex_struct_exists() != 0;
        (*out).union_exists = union_exists() != 0;
        (*out).enum_exists = enum_exists() != 0;
        (*out).typedef_named_struct_exists = typedef_named_struct_exists() != 0;
        (*out).typedef_anon_struct_exists = typedef_anon_struct_exists() != 0;
        (*out).typedef_struct_ptr_exists = typedef_struct_ptr_exists() != 0;
        (*out).typedef_int_exists = typedef_int_exists() != 0;
        (*out).typedef_enum_exists = typedef_enum_exists() != 0;
        (*out).typedef_void_ptr_exists = typedef_void_ptr_exists() != 0;
        (*out).typedef_restrict_ptr_exists = typedef_restrict_ptr_exists() != 0;
        (*out).typedef_func_proto_exists = typedef_func_proto_exists() != 0;
        (*out).typedef_arr_exists = typedef_arr_exists() != 0;
        (*out).struct_matches = struct_matches() != 0;
        (*out).complex_struct_matches = complex_struct_matches() != 0;
        (*out).union_matches = union_matches() != 0;
        (*out).enum_matches = enum_matches() != 0;
        (*out).typedef_named_struct_matches = typedef_named_struct_matches() != 0;
        (*out).typedef_anon_struct_matches = typedef_anon_struct_matches() != 0;
        (*out).typedef_struct_ptr_matches = typedef_struct_ptr_matches() != 0;
        (*out).typedef_int_matches = typedef_int_matches() != 0;
        (*out).typedef_enum_matches = typedef_enum_matches() != 0;
        (*out).typedef_void_ptr_matches = typedef_void_ptr_matches() != 0;
        (*out).typedef_restrict_ptr_matches = typedef_restrict_ptr_matches() != 0;
        (*out).typedef_func_proto_matches = typedef_func_proto_matches() != 0;
        (*out).typedef_arr_matches = typedef_arr_matches() != 0;
        (*out).struct_sz = struct_sz() as i32;
        (*out).union_sz = union_sz() as i32;
        (*out).enum_sz = enum_sz() as i32;
        (*out).typedef_named_struct_sz = typedef_named_struct_sz() as i32;
        (*out).typedef_anon_struct_sz = typedef_anon_struct_sz() as i32;
        (*out).typedef_struct_ptr_sz = typedef_struct_ptr_sz() as i32;
        (*out).typedef_int_sz = typedef_int_sz() as i32;
        (*out).typedef_enum_sz = typedef_enum_sz() as i32;
        (*out).typedef_void_ptr_sz = typedef_void_ptr_sz() as i32;
        (*out).typedef_func_proto_sz = typedef_func_proto_sz() as i32;
        (*out).typedef_arr_sz = typedef_arr_sz() as i32;
    }
    0
}

bpf_object!("GPL");
