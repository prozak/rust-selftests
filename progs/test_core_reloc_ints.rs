#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_core_reloc_ints.c, bpf-rs-core
// idiom.
//
// The C source declares a local `struct core_reloc_ints` and, for each
// field, does `bpf_core_read(&out->field, sizeof(out->field), &in->field)`
// i.e. `__builtin_preserve_access_index(&in->field)` fused with a
// bpf_probe_read_kernel of `sizeof(*(dst))` (the LOCAL field's byte width)
// bytes. prog_tests/core_reloc.c's INTS_CASE loads this SAME compiled
// object against several different target BTF files (plain `ints`,
// `ints___bool` where u8_field becomes `bool`, `ints___reverse_sign` where
// every field's signedness flips) — every field keeps the same byte width
// across variants, so the byte-copy read is width-preserving and the CO-RE
// field-byte-offset relocation (matched by field name, stripping the
// `___suffix`) is all that's needed; no TYPE_SIZE/array relocation
// involved, so this is not affected by the ptr_as_arr limitation.
//
// `in`/`out` live in one .bss global `data` (same layout as C's
// `struct { char in[256]; char out[256]; } data`), found and mmap'd by
// the userspace test harness directly — byte layout, not BTF, is what's
// load-bearing there. Reads from `in` go through the `#[btf]`-generated
// CO-RE view; writes to `out` use the local (non-relocated) struct layout,
// matching C's `struct core_reloc_ints *out = (void *)&data.out` cast.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_probe_read_kernel;
use btf_macros::btf;

#[btf]
struct core_reloc_ints {
    u8_field: u8,
    s8_field: i8,
    u16_field: u16,
    s16_field: i16,
    u32_field: u32,
    s32_field: i32,
    u64_field: u64,
    s64_field: i64,
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

macro_rules! core_read_field {
    ($in_view:expr, $out_base:expr, $field:ident, $ty:ty, $off:expr) => {{
        let mut val: $ty = 0;
        let ok = bpf_probe_read_kernel(
            &mut val,
            core::mem::size_of::<$ty>() as u32,
            $in_view.$field().as_ptr() as *const core::ffi::c_void,
        ) == 0;
        if !ok {
            return 1;
        }
        unsafe { ($out_base.add($off) as *mut $ty).write_unaligned(val) };
    }};
}

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn test_core_ints(_ctx: *const core::ffi::c_void) -> i32 {
    let in_ptr = unsafe { core::ptr::addr_of_mut!(data.in_) } as *const core_reloc_ints;
    let in_view: &core_reloc_ints = unsafe { &*in_ptr };
    let out_base = unsafe { core::ptr::addr_of_mut!(data.out) } as *mut u8;

    core_read_field!(in_view, out_base, u8_field, u8, 0);
    core_read_field!(in_view, out_base, s8_field, i8, 1);
    core_read_field!(in_view, out_base, u16_field, u16, 2);
    core_read_field!(in_view, out_base, s16_field, i16, 4);
    core_read_field!(in_view, out_base, u32_field, u32, 8);
    core_read_field!(in_view, out_base, s32_field, i32, 12);
    core_read_field!(in_view, out_base, u64_field, u64, 16);
    core_read_field!(in_view, out_base, s64_field, i64, 24);

    0
}

bpf_object!("GPL");
