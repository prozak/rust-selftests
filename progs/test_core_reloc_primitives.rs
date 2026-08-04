#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_core_reloc_primitives.c,
// bpf-rs-core idiom.
//
// The userspace test (prog_tests/core_reloc.c) reuses this ONE object
// against several alternate target BTFs (btf_src_file) describing
// structurally different `struct core_reloc_primitives` layouts (reordered
// fields, an anonymous enum def, a different function-pointer proto, a
// different pointer type). Only the CO-RE relocated SOURCE address
// (`&in->x`) must adapt; the destination (`&out->x`) is an ordinary,
// compile-time-fixed member access in this translation unit, exactly like
// the C macro `bpf_core_read(dst, sizeof(*(dst)), src)` only wraps `src`
// in `__builtin_preserve_access_index`.
//
// libbpf's field-relocation compat check (`bpf_core_fields_are_compat` in
// tools/lib/bpf/relo_core.c) requires the LOCAL field's BTF *kind* to match
// the target's: INT<->INT, PTR<->PTR (any pointee), ENUM<->ENUM (any name,
// since our local enum is unnamed-equivalent for matching purposes here).
// So `c` must carry a real BTF_KIND_ENUM locally (not a plain integer) or
// the primitives/err_non_enum cases would resolve incorrectly; `d`/`f` only
// need PTR kind, so a plain byte pointer stands in for the C function
// pointer and `void *` fields.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_probe_read_kernel;
use btf::{BtfType, Field};
use btf_macros::btf;

#[repr(i32)]
#[allow(non_camel_case_types, dead_code)]
enum core_reloc_primitives_enum {
    A = 0,
    B = 1,
}

impl BtfType for core_reloc_primitives_enum {
    type Carrier = Self;

    type View<'a, Root, Path, Mode>
        = Field<'a, Root, Self, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a;

    #[inline(always)]
    fn __btf_view<'a, Root, Path, Mode>(
        field: Field<'a, Root, Self, Path, Mode>,
    ) -> Self::View<'a, Root, Path, Mode>
    where
        Self: 'a,
        Root: BtfType + 'a,
    {
        field
    }
}

#[btf]
struct core_reloc_primitives {
    a: i8,
    b: i32,
    c: core_reloc_primitives_enum,
    d: *const u8,
    f: *const u8,
}

#[repr(C)]
struct CoreRelocPrimitivesOut {
    a: i8,
    b: i32,
    c: i32,
    d: *const u8,
    f: *const u8,
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
extern "C" fn test_core_primitives(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        let in_ptr = core::ptr::addr_of!(data.in_) as *const core_reloc_primitives;
        let out_ptr = core::ptr::addr_of_mut!(data.out) as *mut CoreRelocPrimitivesOut;
        let inp = &*in_ptr;

        let mut a: i8 = 0;
        if bpf_probe_read_kernel(
            &mut a,
            core::mem::size_of::<i8>() as u32,
            inp.a().as_ptr() as *const core::ffi::c_void,
        ) != 0
        {
            return 1;
        }
        (*out_ptr).a = a;

        let mut b: i32 = 0;
        if bpf_probe_read_kernel(
            &mut b,
            core::mem::size_of::<i32>() as u32,
            inp.b().as_ptr() as *const core::ffi::c_void,
        ) != 0
        {
            return 1;
        }
        (*out_ptr).b = b;

        let mut c: i32 = 0;
        if bpf_probe_read_kernel(
            &mut c,
            core::mem::size_of::<i32>() as u32,
            inp.c().as_ptr() as *const core::ffi::c_void,
        ) != 0
        {
            return 1;
        }
        (*out_ptr).c = c;

        let mut d: *const u8 = core::ptr::null();
        if bpf_probe_read_kernel(
            &mut d,
            core::mem::size_of::<*const u8>() as u32,
            inp.d().as_ptr() as *const core::ffi::c_void,
        ) != 0
        {
            return 1;
        }
        (*out_ptr).d = d;

        let mut f: *const u8 = core::ptr::null();
        if bpf_probe_read_kernel(
            &mut f,
            core::mem::size_of::<*const u8>() as u32,
            inp.f().as_ptr() as *const core::ffi::c_void,
        ) != 0
        {
            return 1;
        }
        (*out_ptr).f = f;
    }

    0
}

bpf_object!("GPL");
