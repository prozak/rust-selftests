#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_gotox.c,
// bpf-rs-core idiom.
//
// The C source is gated on `#ifdef __BPF_FEATURE_GOTOX`, a clang-only
// builtin macro for its BPF backend's indirect-jump ("gotox") codegen
// (computed goto / address-of-label, driving BPF_JMP|BPF_JA|BPF_X and
// BPF_MAP_TYPE_INSN_ARRAY jump tables). Rust has no computed-goto construct
// and rustc does not define/emit this feature, so every build takes the
// `#else` branch: all 14 programs become `SEC("syscall") { return 0; }`
// stubs (SKIP_TEST macro) and `skip = 1`. This host's clang (18.1.3) also
// lacks __BPF_FEATURE_GOTOX (confirmed via `clang --target=bpf -dM -E`),
// so the canonical C object built by this repo's own Makefile takes the
// identical fallback path — verified against its symbol table: 14
// SEC("syscall") funcs of 16 bytes each (mov r0,0; exit), skip in .data,
// in_user/ret_user/pid in .bss. That set is what test_bpf_gotox.c's
// `__subtest` gate (`if (skel->data->skip) test__skip();`) is built to
// tolerate: skip=1 causes every skeleton-driven subtest to be skipped.
// The two subtests that don't gate on `skip` (check-ldimm64-off,
// check-ldimm64-off-gotox) load their own hand-crafted raw instructions
// against a fresh BPF_MAP_TYPE_INSN_ARRAY map and never touch this
// program's contents, so they pass unconditionally.

use bpf_rs_core::bpf_object;

#[no_mangle]
static mut in_user: u64 = 0;

#[no_mangle]
static mut ret_user: u64 = 0;

#[no_mangle]
static mut pid: i32 = 0;

#[link_section = ".data"]
#[no_mangle]
static skip: u64 = 1;

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn one_switch(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn one_switch_non_zero_sec_off(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn simple_test_other_sec(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn two_switches(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn big_jump_table(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn one_jump_two_maps(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn one_map_two_jumps(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn use_static_global1(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn use_static_global2(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn use_static_global_other_sec(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn use_nonstatic_global1(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn use_nonstatic_global2(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn use_nonstatic_global_other_sec(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn load_with_nonzero_offset(_ctx: *const core::ffi::c_void) -> i32 {
    0
}

bpf_object!("GPL");
