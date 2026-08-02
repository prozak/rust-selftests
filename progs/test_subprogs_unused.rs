#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_subprogs_unused.c (bpf-rs-core
// idiom). Exercises libbpf's handling of an object that carries an unused
// global subprog alongside its single attached program.
//
// The C original also has a `static __noinline unused2`, but being both
// static and never called it is fully dead-code-eliminated by clang (it
// has no symbol in the compiled object at all — verified against the
// pristine C .bpf.o: only `unused1`, `main_prog` and `LICENSE` survive as
// global symbols). `unused1` is global, so it is kept as a real function
// regardless of being unreferenced; matching the C object's keep-list
// requires translating that one and dropping unused2 entirely.

use bpf_rs_core::bpf_object;

#[no_mangle]
pub extern "C" fn unused1(x: i32) -> i32 {
    x + 1
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn main_prog(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

bpf_object!("GPL");
