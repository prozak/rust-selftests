#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_core_reloc_misc.c,
// bpf-rs-core idiom.
//
// The first two CORE_READs are genuine field relocations: two differently
// named local views (core_reloc_misc___a / ___b) over the same `data.in`
// bytes, each reading their first member (accessor "0:0"). `#[btf]` on each
// gives us the field-name-matched, relocated address via `.a1()`/`.b1()`.
//
// The third CORE_READ(&out->c, &in_ext[2]) is a pure array-index accessor
// (no field access), which upstream clang does NOT resize for a differently
// laid-out target type (core_reloc_types.h's core_reloc_misc_extensible
// gained `c`/`d` members) — the test's expected output (`c == 0`, annotated
// "BUG in clang, should be 3") documents this. Plain local-stride pointer
// arithmetic over our own `core_reloc_misc_extensible { a, b }` reproduces
// that exact behavior, so no `#[btf]`/relocation is needed for this step.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_probe_read_kernel;
use btf_macros::btf;
use core::ffi::c_void;

#[btf]
struct core_reloc_misc___a {
    a1: i32,
    a2: i32,
}

#[btf]
struct core_reloc_misc___b {
    b1: i32,
    b2: i32,
}

#[repr(C)]
struct core_reloc_misc_extensible {
    a: i32,
    b: i32,
}

#[repr(C)]
struct core_reloc_misc_output {
    a: i32,
    b: i32,
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

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn test_core_misc(_ctx: *const c_void) -> i32 {
    let in_a = unsafe { core::ptr::addr_of!(data.in_) } as *const core_reloc_misc___a;
    let in_b = unsafe { core::ptr::addr_of!(data.in_) } as *const core_reloc_misc___b;
    let in_ext = unsafe { core::ptr::addr_of!(data.in_) } as *const core_reloc_misc_extensible;
    let out = unsafe { core::ptr::addr_of_mut!(data.out) } as *mut core_reloc_misc_output;

    let src_a1 = unsafe { &*in_a }.a1().as_ptr();
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out).a },
        core::mem::size_of::<i32>() as u32,
        src_a1 as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    let src_b1 = unsafe { &*in_b }.b1().as_ptr();
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out).b },
        core::mem::size_of::<i32>() as u32,
        src_b1 as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    let src_ext2 = unsafe { in_ext.add(2) };
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out).c },
        core::mem::size_of::<i32>() as u32,
        src_ext2 as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    0
}

bpf_object!("GPL");
