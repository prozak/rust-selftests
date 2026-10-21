// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of progs/test_core_reloc_enum64val.c (bpf-rs-core idiom):
// test_core_reloc_enumval.rs on 64-bit enums (BTF ENUM64, one signed and
// one unsigned); the harness loads this one object against four target
// BTF variants. `// BTF_ENUM_VALUE:` externs (scripts/type_id.py).
// BTF_ENUM_VALUE: unsigned_val1_exists exists enum named_unsigned_enum64 UNSIGNED_ENUM64_VAL1
// BTF_ENUM_VALUE: unsigned_val2_exists exists enum named_unsigned_enum64 UNSIGNED_ENUM64_VAL2
// BTF_ENUM_VALUE: unsigned_val3_exists exists enum named_unsigned_enum64 UNSIGNED_ENUM64_VAL3
// BTF_ENUM_VALUE: signed_val1_exists exists enum named_signed_enum64 SIGNED_ENUM64_VAL1
// BTF_ENUM_VALUE: signed_val2_exists exists enum named_signed_enum64 SIGNED_ENUM64_VAL2
// BTF_ENUM_VALUE: signed_val3_exists exists enum named_signed_enum64 SIGNED_ENUM64_VAL3
// BTF_ENUM_VALUE: unsigned_val1 value enum named_unsigned_enum64 UNSIGNED_ENUM64_VAL1
// BTF_ENUM_VALUE: unsigned_val2 value enum named_unsigned_enum64 UNSIGNED_ENUM64_VAL2
// BTF_ENUM_VALUE: signed_val1 value enum named_signed_enum64 SIGNED_ENUM64_VAL1
// BTF_ENUM_VALUE: signed_val2 value enum named_signed_enum64 SIGNED_ENUM64_VAL2

use bpf_rs_core::bpf_object;

extern "C" {
    fn unsigned_val1_exists() -> u64;
    fn unsigned_val2_exists() -> u64;
    fn unsigned_val3_exists() -> u64;
    fn signed_val1_exists() -> u64;
    fn signed_val2_exists() -> u64;
    fn signed_val3_exists() -> u64;
    fn unsigned_val1() -> u64;
    fn unsigned_val2() -> u64;
    fn signed_val1() -> u64;
    fn signed_val2() -> u64;
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
    unsigned_val1_exists: bool,
    unsigned_val2_exists: bool,
    unsigned_val3_exists: bool,
    signed_val1_exists: bool,
    signed_val2_exists: bool,
    signed_val3_exists: bool,

    unsigned_val1: i64,
    unsigned_val2: i64,
    signed_val1: i64,
    signed_val2: i64,
}

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn test_core_enum64val(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        let out = core::ptr::addr_of_mut!(data.output) as *mut Output;
        (*out).unsigned_val1_exists = unsigned_val1_exists() != 0;
        (*out).unsigned_val2_exists = unsigned_val2_exists() != 0;
        (*out).unsigned_val3_exists = unsigned_val3_exists() != 0;
        (*out).signed_val1_exists = signed_val1_exists() != 0;
        (*out).signed_val2_exists = signed_val2_exists() != 0;
        (*out).signed_val3_exists = signed_val3_exists() != 0;
        (*out).unsigned_val1 = unsigned_val1() as i64;
        (*out).unsigned_val2 = unsigned_val2() as i64;
        // UNSIGNED_ENUM64_VAL3 value is optional
        (*out).signed_val1 = signed_val1() as i64;
        (*out).signed_val2 = signed_val2() as i64;
        // SIGNED_ENUM64_VAL3 value is optional
    }
    0
}

bpf_object!("GPL");
