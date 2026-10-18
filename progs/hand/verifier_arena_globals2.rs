// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_arena_globals2.c, translated
// by hand; include!d by the generated progs/verifier_arena_globals2.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// Arena pointers: rustc cannot spell an address-space-qualified pointer, so
// an arena pointer is a plain `*mut u8` holding the arena's user address (what
// the kfuncs return and what an `.addr_space.1` global's ld_imm64 yields), and
// every access goes through `cast_kern` (the hand-encoded
// `addr_space_cast(r, 0, 1)` that clang inserts before each `__arena`
// dereference; arena_atomics.rs, stream.rs). `arena_base` is bpf_arena_common.h's:
// the map's user_vm_start through a CO-RE view of the kernel's struct
// bpf_arena. `can_loop` is bpf_may_goto.h's hand-encoded may_goto.

use bpf_rs_core::helpers::sink;
use btf_macros::btf;

const PAGE_SIZE: u64 = 4096;
const NUMA_NO_NODE: i32 = -1;

/// `bpf_addr_space_cast(ptr, 0, 1)`: in-place single-register encoding.
#[inline(always)]
unsafe fn cast_kern(p: *mut u8) -> *mut u8 {
    let mut p = p;
    core::arch::asm!(
        ".byte 0xBF",
        ".ifc {0}, r0", ".byte 0x00", ".endif",
        ".ifc {0}, r1", ".byte 0x11", ".endif",
        ".ifc {0}, r2", ".byte 0x22", ".endif",
        ".ifc {0}, r3", ".byte 0x33", ".endif",
        ".ifc {0}, r4", ".byte 0x44", ".endif",
        ".ifc {0}, r5", ".byte 0x55", ".endif",
        ".ifc {0}, r6", ".byte 0x66", ".endif",
        ".ifc {0}, r7", ".byte 0x77", ".endif",
        ".ifc {0}, r8", ".byte 0x88", ".endif",
        ".ifc {0}, r9", ".byte 0x99", ".endif",
        ".short 1",
        ".long 1",
        inout(reg) p,
        options(nostack, preserves_flags),
    );
    p
}

#[btf]
struct bpf_arena {
    user_vm_start: u64,
}

/// `arena_base(&arena)`: `((struct bpf_arena *)map)->user_vm_start`, a CO-RE
/// read on the map pointer kept in a register.
#[inline(always)]
unsafe fn arena_base() -> u64 {
    let mut ptr = core::ptr::addr_of!(arena) as *mut bpf_arena;
    sink(&mut ptr);
    *(*ptr).user_vm_start().get().unwrap()
}

#[inline(always)]
unsafe fn arena_map() -> *mut c_void {
    core::ptr::addr_of!(arena) as *mut c_void
}

// HAND: check_reserve2 -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int check_reserve2(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       void __arena *guard;
//       int ret;
//
//       guard = (void __arena *)arena_base(&arena);
//
//       /* Make sure the data at offset 0 case is properly handled. */
//       ret = bpf_arena_reserve_pages(&arena, guard, 1);
//       if (!ret)
//           return 1;
//   #endif
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn check_reserve2(_ctx: *mut c_void) -> i32 {
    let guard = unsafe { arena_base() } as *mut u8;

    // Make sure the data at offset 0 case is properly handled.
    let ret = unsafe { bpf_arena_reserve_pages(arena_map(), guard as *mut c_void, 1) };
    if ret == 0 {
        return 1;
    }
    0
}
