#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_core_reloc_nesting.c,
// bpf-rs-core idiom.
//
// C's `CORE_READ(dst, src)` is `bpf_core_read(dst, sizeof(*dst), src)` =
// `bpf_probe_read_kernel(dst, sz, __builtin_preserve_access_index(src))`:
// only `src` (the `in` side) goes through CO-RE field relocation against
// whatever target BTF the harness loads for a given nesting-flavor test
// case; `dst` (the `out` side) is a plain compile-time offset into our own
// local struct, unaffected by the target BTF swap. So `in` is read through
// the `#[btf]` CO-RE view, while `out` is addressed through an ordinary
// `#[repr(C)]` struct that reproduces the same local byte layout (each
// nesting level here wraps exactly one int, so the flattened offsets match:
// a.a.a at 0, b.b.b at 4).
//
// CO-RE field matching for anonymous struct/union nesting works purely off
// the member-name chain (a/a/a, b/b/b); the corpus even has a
// `nesting___struct_union_mixup` target variant that swaps struct<->union at
// these levels, so declaring every local level with `#[btf] struct` (rather
// than trying to model the C unions) is faithful either way.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_probe_read_kernel;
use btf_macros::btf;
use core::ffi::c_void;

#[btf]
struct core_reloc_nesting_substruct {
    a: i32,
}

#[btf]
struct core_reloc_nesting_subunion {
    b: i32,
}

#[btf]
struct core_reloc_nesting_a {
    a: core_reloc_nesting_substruct,
}

#[btf]
struct core_reloc_nesting_b {
    b: core_reloc_nesting_subunion,
}

#[btf]
struct core_reloc_nesting {
    a: core_reloc_nesting_a,
    b: core_reloc_nesting_b,
}

#[repr(C)]
struct NestingOut {
    a: i32,
    b: i32,
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
extern "C" fn test_core_nesting(_ctx: *const c_void) -> i32 {
    let in_view = unsafe { core::ptr::addr_of!(data.in_) } as *const core_reloc_nesting;
    let out_view = unsafe { core::ptr::addr_of_mut!(data.out) } as *mut NestingOut;

    let src_a = unsafe { &*in_view }.a().a().a().as_ptr();
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out_view).a },
        core::mem::size_of::<i32>() as u32,
        src_a as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    let src_b = unsafe { &*in_view }.b().b().b().as_ptr();
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out_view).b },
        core::mem::size_of::<i32>() as u32,
        src_b as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    0
}

bpf_object!("GPL");
