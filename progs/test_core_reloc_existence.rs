#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_core_reloc_existence.c,
// bpf-rs-core idiom.
//
// The userspace test (prog_tests/core_reloc.c) reuses this ONE object
// against three alternate target BTFs (btf_src_file): the full
// `struct core_reloc_existence` (all fields present, matching kinds), a
// `___minimal` variant (only `a` present), and a `___wrong_field_defs`
// variant where every field name is present but with an incompatible BTF
// kind (int vs pointer/array/struct), which `bpf_core_field_exists` must
// report as *not* existing. Each `#[btf]` field access below emits its own
// `field_exists` CO-RE relocation via `.exists()` (matching
// `bpf_core_field_exists(in->x)`); the value read afterwards via `.get()`
// only executes on the branch where the field was proven to exist,
// matching `BPF_CORE_READ(in, x)` guarded by the same check in the C
// source. `s` is a nested struct field (`s.x`) and `arr` is a one-element
// array read at a compile-time-fixed index (`arr[0]`), so no CO-RE
// array-subscript relocation is needed — only the field-level relocation
// for the array/struct's own address.
//
// C's anonymous embedded member (`struct { int b; };`) is matched
// transparently by libbpf's field search regardless of local nesting, so
// `b` is declared as an ordinary top-level field here (see
// test_core_reloc_primitives.rs for the same flattening idiom).

use btf_macros::btf;

#[btf]
struct core_reloc_existence_s {
    x: i32,
}

#[btf]
struct core_reloc_existence {
    a: i32,
    b: i32,
    c: i32,
    arr: [i32; 1],
    s: core_reloc_existence_s,
}

#[repr(C)]
struct CoreRelocExistenceOutput {
    a_exists: i32,
    a_value: i32,
    b_exists: i32,
    b_value: i32,
    c_exists: i32,
    c_value: i32,
    arr_exists: i32,
    arr_value: i32,
    s_exists: i32,
    s_value: i32,
}

#[repr(C)]
struct Data {
    in_: [u8; 256],
    out: [u8; 256],
}

#[no_mangle]
static mut data: Data = Data {
    in_: [0; 256],
    out: [0; 256],
};

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn test_core_existence(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        let in_ptr = core::ptr::addr_of!(data.in_) as *const core_reloc_existence;
        let out_ptr = core::ptr::addr_of_mut!(data.out) as *mut CoreRelocExistenceOutput;
        let inp = &*in_ptr;

        let a = inp.a();
        let a_exists = a.exists();
        (*out_ptr).a_exists = a_exists as i32;
        (*out_ptr).a_value = if a_exists {
            *a.get().unwrap()
        } else {
            0xff000001u32 as i32
        };

        let b = inp.b();
        let b_exists = b.exists();
        (*out_ptr).b_exists = b_exists as i32;
        (*out_ptr).b_value = if b_exists {
            *b.get().unwrap()
        } else {
            0xff000002u32 as i32
        };

        let c = inp.c();
        let c_exists = c.exists();
        (*out_ptr).c_exists = c_exists as i32;
        (*out_ptr).c_value = if c_exists {
            *c.get().unwrap()
        } else {
            0xff000003u32 as i32
        };

        let arr = inp.arr();
        let arr_exists = arr.exists();
        (*out_ptr).arr_exists = arr_exists as i32;
        (*out_ptr).arr_value = if arr_exists {
            (*arr.get().unwrap())[0]
        } else {
            0xff000004u32 as i32
        };

        let s = inp.s();
        let s_exists = s.exists();
        (*out_ptr).s_exists = s_exists as i32;
        (*out_ptr).s_value = if s_exists {
            *s.x().get().unwrap()
        } else {
            0xff000005u32 as i32
        };
    }

    0
}

bpf_rs_core::bpf_object!("GPL");
