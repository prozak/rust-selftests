#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_core_reloc_mods.c,
// bpf-rs-core idiom.
//
// C's `CORE_READ(dst, src)` is `bpf_core_read(dst, sizeof(*dst), src)` =
// `bpf_probe_read_kernel(dst, sz, __builtin_preserve_access_index(src))`:
// only `src` (the `in` side) goes through CO-RE field relocation against
// whichever target BTF flavor the harness loads (`mods`, `___mod_swap`,
// `___typedefs` — permuted field order, swapped/renamed struct types,
// deeper typedef chains, all still resolving to the same underlying `int`
// / pointer / substruct shapes). `dst` (`out`) is a plain compile-time
// offset into our own local output struct.
//
// `e`/`f` are read at a fixed literal index (`e[2]`, `f[1]`): the element
// type is `int` in every target flavor, so `.e().as_ptr()` (one
// byte-offset relocation for the array field itself, by name) followed by
// ordinary pointer arithmetic reproduces clang's `&in->e[2]` exactly,
// without needing an indexed CO-RE path (this crate's `#[btf]` only
// supports named-field chains, see btf/src/lib.rs's array `BtfType` impl).
// `g`/`h` are struct fields read one member down (`g.x`, `h.y`), an
// ordinary two-step named-field chain.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_probe_read_kernel;
use btf_macros::btf;
use core::ffi::c_void;

#[btf]
struct core_reloc_mods_substruct {
    x: i32,
    y: i32,
}

#[btf]
struct core_reloc_mods {
    a: i32,
    b: i32,
    c: *const u8,
    d: *const u8,
    e: [i32; 3],
    f: [i32; 7],
    g: core_reloc_mods_substruct,
    h: core_reloc_mods_substruct,
}

#[repr(C)]
struct core_reloc_mods_output {
    a: i32,
    b: i32,
    c: i32,
    d: i32,
    e: i32,
    f: i32,
    g: i32,
    h: i32,
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
extern "C" fn test_core_mods(_ctx: *const c_void) -> i32 {
    let in_view = unsafe { core::ptr::addr_of!(data.in_) } as *const core_reloc_mods;
    let out_view = unsafe { core::ptr::addr_of_mut!(data.out) } as *mut core_reloc_mods_output;
    let in_ref = unsafe { &*in_view };

    let src_a = in_ref.a().as_ptr();
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out_view).a },
        core::mem::size_of::<i32>() as u32,
        src_a as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    let src_b = in_ref.b().as_ptr();
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out_view).b },
        core::mem::size_of::<i32>() as u32,
        src_b as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    let src_c = in_ref.c().as_ptr();
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out_view).c },
        core::mem::size_of::<i32>() as u32,
        src_c as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    let src_d = in_ref.d().as_ptr();
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out_view).d },
        core::mem::size_of::<i32>() as u32,
        src_d as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    let src_e = unsafe { (in_ref.e().as_ptr() as *const i32).add(2) };
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out_view).e },
        core::mem::size_of::<i32>() as u32,
        src_e as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    let src_f = unsafe { (in_ref.f().as_ptr() as *const i32).add(1) };
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out_view).f },
        core::mem::size_of::<i32>() as u32,
        src_f as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    let src_g = in_ref.g().x().as_ptr();
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out_view).g },
        core::mem::size_of::<i32>() as u32,
        src_g as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    let src_h = in_ref.h().y().as_ptr();
    let ret = bpf_probe_read_kernel(
        unsafe { &mut (*out_view).h },
        core::mem::size_of::<i32>() as u32,
        src_h as *const c_void,
    );
    if ret != 0 {
        return 1;
    }

    0
}

bpf_object!("GPL");
