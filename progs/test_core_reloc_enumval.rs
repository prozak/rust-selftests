// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of progs/test_core_reloc_enumval.c (bpf-rs-core idiom).
//
// bpf_core_enum_value_exists() / bpf_core_enum_value() are ENUMVAL_EXISTS /
// ENUMVAL_VALUE CO-RE relocations the loader resolves against the target
// BTF prog_tests/core_reloc.c attaches (four variants of this one object).
// Each is a `// BTF_ENUM_VALUE:` extern below (scripts/type_id.py, the
// relocation on a full copy of the C object's enum; anon_enum is a typedef
// of an anonymous enum in the C and the relocation's root is the typedef).
// BTF_ENUM_VALUE: named_val1_exists exists enum named_enum NAMED_ENUM_VAL1
// BTF_ENUM_VALUE: named_val2_exists exists enum named_enum NAMED_ENUM_VAL2
// BTF_ENUM_VALUE: named_val3_exists exists enum named_enum NAMED_ENUM_VAL3
// BTF_ENUM_VALUE: anon_val1_exists exists typedef anon_enum ANON_ENUM_VAL1
// BTF_ENUM_VALUE: anon_val2_exists exists typedef anon_enum ANON_ENUM_VAL2
// BTF_ENUM_VALUE: anon_val3_exists exists typedef anon_enum ANON_ENUM_VAL3
// BTF_ENUM_VALUE: named_val1 value enum named_enum NAMED_ENUM_VAL1
// BTF_ENUM_VALUE: named_val2 value enum named_enum NAMED_ENUM_VAL2
// BTF_ENUM_VALUE: anon_val1 value typedef anon_enum ANON_ENUM_VAL1
// BTF_ENUM_VALUE: anon_val2 value typedef anon_enum ANON_ENUM_VAL2

use bpf_rs_core::bpf_object;

extern "C" {
    fn named_val1_exists() -> u64;
    fn named_val2_exists() -> u64;
    fn named_val3_exists() -> u64;
    fn anon_val1_exists() -> u64;
    fn anon_val2_exists() -> u64;
    fn anon_val3_exists() -> u64;
    fn named_val1() -> u64;
    fn named_val2() -> u64;
    fn anon_val1() -> u64;
    fn anon_val2() -> u64;
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
    named_val1_exists: bool,
    named_val2_exists: bool,
    named_val3_exists: bool,
    anon_val1_exists: bool,
    anon_val2_exists: bool,
    anon_val3_exists: bool,

    named_val1: i32,
    named_val2: i32,
    anon_val1: i32,
    anon_val2: i32,
}

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn test_core_enumval(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        let out = core::ptr::addr_of_mut!(data.output) as *mut Output;
        (*out).named_val1_exists = named_val1_exists() != 0;
        (*out).named_val2_exists = named_val2_exists() != 0;
        (*out).named_val3_exists = named_val3_exists() != 0;
        (*out).anon_val1_exists = anon_val1_exists() != 0;
        (*out).anon_val2_exists = anon_val2_exists() != 0;
        (*out).anon_val3_exists = anon_val3_exists() != 0;
        (*out).named_val1 = named_val1() as i32;
        (*out).named_val2 = named_val2() as i32;
        // NAMED_ENUM_VAL3 value is optional
        (*out).anon_val1 = anon_val1() as i32;
        (*out).anon_val2 = anon_val2() as i32;
        // ANON_ENUM_VAL3 value is optional
    }
    0
}

bpf_object!("GPL");
