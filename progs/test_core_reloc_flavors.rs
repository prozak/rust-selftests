#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_core_reloc_flavors.c, bpf-rs-core
// idiom.
//
// The C source declares THREE local "flavor" views of the same logical
// struct -- `core_reloc_flavors` (canonical a,b,c layout), the
// `___reversed` suffix flavor (c,b,a layout) and the `___weird` suffix
// flavor (b in an anon struct, a/c overlapping in an anon union) -- and
// reads one field through each: `out->a <- in_weird->a`,
// `out->b <- in_rev->b`, `out->c <- in_orig->c`. libbpf's CO-RE relocation
// strips the `___suffix` from each local type name before matching against
// the (single, canonical) target type, so all three reads resolve against
// the same target `core_reloc_flavors { a; b; c; }` regardless of the local
// flavor's own field order/nesting.
//
// `#[btf]`-generated views are pure address markers (see
// test_core_reloc_ints.rs): the local field's declared position/nesting
// inside its Rust struct has no bearing on the emitted byte-offset
// relocation, which is resolved purely by walking the LOCAL BTF composite
// by field NAME to find the accessed member, then matching that name
// against the TARGET type. So the anon struct/union nesting in the C
// `___weird` variant (which the `#[btf]` macro cannot express -- it only
// supports flat named-field structs) isn't needed for correctness here:
// declaring `core_reloc_flavors___weird` as a flat struct with fields named
// a/b/c reproduces the same CO-RE relocation for the single field (`a`)
// this program actually reads through it.
//
// Each local struct's Rust identifier is written with the literal
// `___suffix` C uses; `bpf-postproc`'s `FieldRelocPass` strips only the
// generated `__BtfCarrierFor` prefix off the local BTF name, so the
// resulting local BTF type is named exactly as in the C source
// (`core_reloc_flavors___reversed`, `core_reloc_flavors___weird`), which is
// what libbpf's flavor-suffix matching requires.
//
// `in`/`out` live in one .bss global `data`, found and mmap'd by the
// userspace test harness directly by byte layout, same as
// test_core_reloc_ints.rs.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_probe_read_kernel;
use btf_macros::btf;

#[btf]
struct core_reloc_flavors {
    a: i32,
    b: i32,
    c: i32,
}

#[btf]
struct core_reloc_flavors___reversed {
    c: i32,
    b: i32,
    a: i32,
}

#[btf]
struct core_reloc_flavors___weird {
    b: i32,
    a: i32,
    c: i32,
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
extern "C" fn test_core_flavors(_ctx: *const core::ffi::c_void) -> i32 {
    let in_ptr = unsafe { core::ptr::addr_of_mut!(data.in_) } as *const u8;
    let out_base = unsafe { core::ptr::addr_of_mut!(data.out) } as *mut u8;

    let in_weird: &core_reloc_flavors___weird =
        unsafe { &*(in_ptr as *const core_reloc_flavors___weird) };
    let in_rev: &core_reloc_flavors___reversed =
        unsafe { &*(in_ptr as *const core_reloc_flavors___reversed) };
    let in_orig: &core_reloc_flavors = unsafe { &*(in_ptr as *const core_reloc_flavors) };

    // read a using weird layout
    core_read_field!(in_weird, out_base, a, i32, 0);
    // read b using reversed layout
    core_read_field!(in_rev, out_base, b, i32, 4);
    // read c using original layout
    core_read_field!(in_orig, out_base, c, i32, 8);

    0
}

bpf_object!("GPL");
