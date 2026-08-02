#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/arena_list.c,
// bpf-rs-core idiom.
//
// The C source's arena-backed linked-list logic (bpf_alloc/bpf_free,
// list_add_head/list_for_each_entry from bpf_arena_list.h) lives entirely
// inside `#ifdef __BPF_FEATURE_ADDR_SPACE_CAST`, and only exists because
// clang/LLVM can type a pointer as `__attribute__((address_space(1)))` and
// emit `addrspacecast` IR (visible in the pristine object's disassembly as
// the `addr_space_cast` insn) whenever such a pointer crosses between the
// arena's user-space view (AS 0) and its BPF-side view (AS 1). rustc has no
// language-level construct for an address-space-qualified pointer type on
// this target (the bpfel-unknown-none-v4 datalayout declares no AS-1
// pointer info, and there is no stable/unstable attribute to request one),
// so `addrspacecast` cannot be emitted from Rust source and the arena
// allocator/list logic is unreachable here. This translation therefore
// takes the C source's own `#else` fallback branch — the one it ships for
// compilers that lack the address-space-cast feature: both programs just
// set `skip = true` and return, and prog_tests/arena_list.c treats that as
// `test__skip()`, never touching the arena/list globals in that run.
//
// The struct + DATASEC shapes below still have to match the clang-built
// object's BTF exactly, because prog_tests/arena_list.c is fixed upstream
// C: it `#include "bpf_arena_list.h"` (defining `struct arena_list_head` /
// `struct arena_list_node`) before `#include "arena_list.skel.h"`, and the
// regenerated skeleton only *uses* those tag names (as a by-value member of
// the arena struct and as a bss pointer) rather than redefining them — so
// the tag names and the by-value member's size must line up, but internal
// field layout is not otherwise load-bearing. `arena_sum` is C `long`:
// per this repo's established gotcha, that must be Rust `isize`, not
// `i64`, or btf_rename renders it "long long" and breaks the regenerated
// skeleton's format strings.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use core::ffi::c_void;

#[allow(non_camel_case_types)]
#[repr(C)]
struct arena_list_node {
    next: *mut arena_list_node,
    pprev: *mut *mut arena_list_node,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct arena_list_head {
    first: *mut arena_list_node,
}

bpf_map! {
    arena {
        r#type: *const [i32; 33],       // BPF_MAP_TYPE_ARENA
        map_flags: *const [i32; 1024],  // BPF_F_MMAPABLE
        max_entries: *const [i32; 100], // number of pages
    }
}

// .bss (all zero-init, matching the C source unconditionally).
#[no_mangle]
static mut list_head: *mut arena_list_head = core::ptr::null_mut();
#[no_mangle]
static mut list_sum: i32 = 0;
#[no_mangle]
static mut cnt: i32 = 0;
#[no_mangle]
static mut skip: bool = false;

// .rodata (const volatile bool nonsleepable = false;) — unread here since
// the skip=true fallback never enters the rcu_read_lock-guarded branch,
// but the symbol must exist: prog_tests writes `skel->rodata->nonsleepable`
// pre-load.
#[link_section = ".rodata"]
#[no_mangle]
static nonsleepable: bool = false;

#[no_mangle]
static mut zero: i32 = 0;

// .addr_space.1 (arena-backed globals): unreachable from program logic in
// this translation, but required so the regenerated skeleton exposes
// `skel->arena->{test_val,arena_sum}` at all — libbpf associates DATASEC
// ".addr_space.1" with whichever single BPF_MAP_TYPE_ARENA map is declared
// in the object, independent of program-body usage.
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut test_val: i32 = 1;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut global_head: arena_list_head = arena_list_head {
    first: core::ptr::null_mut(),
};
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut arena_sum: isize = 0;

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arena_list_add(_ctx: *const c_void) -> i32 {
    unsafe { skip = true };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arena_list_del(_ctx: *const c_void) -> i32 {
    unsafe { skip = true };
    0
}

bpf_object!("GPL");
