// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_arena.c, translated
// by hand; include!d by the generated progs/verifier_arena.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// Arena pointers: rustc cannot spell an address-space-qualified pointer, so
// an arena pointer is a plain raw pointer holding the arena's user address
// (what the kfuncs return) and every access goes through `cast_kern`, the
// hand-encoded `addr_space_cast(r, 0, 1)` clang inserts before each `__arena`
// dereference (arena_atomics.rs); the inline-asm programs spell the cast as
// the C does. `arena_base` is bpf_arena_common.h's: the map's user_vm_start
// through a CO-RE view of the kernel's struct bpf_arena; `bpf_arena___l` is
// the C's own CO-RE flavor of it (libbpf strips the `___l`). The iterator
// context and the kernel's struct bpf_map are CO-RE views too (the generator's
// copies, and the kernel structs behind them, are left out). The C's
// `u32 __arena *` subprogram parameters and returns carry the `arena` BTF type
// tag the verifier reads: the generator writes them into btf_type_tags! from
// the C object (`f.0: arena`, `f.ret: arena`). arena_word_pair returns a
// struct of two such pointers in R0:R2, which no Rust call convention can
// consume (rustc would return it through memory): it is the C object's
// instructions verbatim (`// BPF_NAKED:`), and its caller calls it from asm
// and reads R0 and R2, as arena_kfunc.rs does for the kernel's aggregate
// returns.
// GEN_SKIP_TYPE: bpf_iter__bpf_map
// GEN_SKIP_TYPE: bpf_iter_meta
// GEN_SKIP_TYPE: bpf_map

use bpf_rs_core::helpers::{bpf_get_prandom_u32, bpf_spin_lock, bpf_spin_unlock, sink};
use btf_macros::btf;

const PAGE_SIZE: u64 = 4096;
const NUMA_NO_NODE: i32 = -1;
const EBUSY: i32 = 16;
const EINVAL: i32 = 22;
/// `(1ull << 44) | (~0u - __PAGE_SIZE * 2 + 1)`: the map's map_extra
const ARENA_VM_START: u64 = (1 << 44) | (0xffff_ffff - PAGE_SIZE * 2 + 1);

/// `bpf_addr_space_cast(ptr, 0, 1)`: in-place single-register encoding.
#[inline(always)]
unsafe fn cast_kern<T>(p: *mut T) -> *mut T {
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

#[inline(always)]
unsafe fn alloc<T>(addr: *mut T, cnt: u32) -> *mut T {
    bpf_arena_alloc_pages(arena_map(), addr as *mut c_void, cnt, NUMA_NO_NODE, 0) as *mut T
}

#[inline(always)]
unsafe fn free<T>(ptr: *mut T, cnt: u32) {
    bpf_arena_free_pages(arena_map(), ptr as *mut c_void, cnt)
}

#[inline(always)]
unsafe fn reserve<T>(ptr: *mut T, cnt: u32) -> i32 {
    bpf_arena_reserve_pages(arena_map(), ptr as *mut c_void, cnt)
}

#[inline(always)]
unsafe fn vload<T: Copy>(p: *mut T) -> T {
    core::ptr::read_volatile(cast_kern(p))
}

#[inline(always)]
unsafe fn vstore<T>(p: *mut T, v: T) {
    core::ptr::write_volatile(cast_kern(p), v)
}

/// The kernel's struct bpf_map, the members the C reads with CO-RE.
#[btf]
struct bpf_map {
    max_entries: u32,
    inner_map_meta: *mut bpf_map,
}

#[btf]
struct seq_file {}

#[btf]
struct bpf_iter_meta {
    seq: *mut seq_file,
}

#[btf]
struct bpf_iter__bpf_map {
    meta: *mut bpf_iter_meta,
    map: *mut bpf_map,
}

/// The C's `struct bpf_arena___l { struct bpf_map map; }`, a CO-RE flavor.
#[allow(non_camel_case_types)]
#[btf]
struct bpf_arena___l {
    map: bpf_map,
}

/// The C's `struct arena_word_pair { u32 __arena *first, *second; }`, the
/// R0:R2 aggregate arena_word_pair returns.
#[allow(non_camel_case_types)]
#[repr(C)]
struct arena_word_pair {
    first: *mut u32,
    second: *mut u32,
}

// HAND: basic_alloc1_nosleep -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(0)
//   int basic_alloc1_nosleep(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       volatile int __arena *page1, *page2, *no_page;
//
//       page1 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!page1)
//           return 1;
//       *page1 = 1;
//       page2 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!page2)
//           return 2;
//       *page2 = 2;
//       no_page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (no_page)
//           return 3;
//       if (*page1 != 1)
//           return 4;
//       if (*page2 != 2)
//           return 5;
//       bpf_arena_free_pages(&arena, (void __arena *)page2, 1);
//       if (*page1 != 1)
//           return 6;
//       if (*page2 != 0 && *page2 != 2) /* use-after-free should return 0 or the stored value */
//           return 7;
//   #endif
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn basic_alloc1_nosleep(_ctx: *mut c_void) -> i32 {
    unsafe {
    let page1 = alloc(core::ptr::null_mut::<u32>(), 1);
    if page1.is_null() {
        return 1;
    }
    vstore(page1, 1);
    let page2 = alloc(core::ptr::null_mut::<u32>(), 1);
    if page2.is_null() {
        return 2;
    }
    vstore(page2, 2);
    let no_page = alloc(core::ptr::null_mut::<u32>(), 1);
    if !no_page.is_null() {
        return 3;
    }
    if vload(page1) != 1 {
        return 4;
    }
    if vload(page2) != 2 {
        return 5;
    }
    free(page2, 1);
    if vload(page1) != 1 {
        return 6;
    }
    if vload(page2) != 0 && vload(page2) != 2 {
        // use-after-free should return 0 or the stored value
        return 7;
    }
    0
    }
}

// HAND: basic_alloc1 -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int basic_alloc1(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       volatile int __arena *page1, *page2, *no_page, *page3;
//
//       page1 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!page1)
//           return 1;
//       *page1 = 1;
//       page2 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!page2)
//           return 2;
//       *page2 = 2;
//       no_page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (no_page)
//           return 3;
//       if (*page1 != 1)
//           return 4;
//       if (*page2 != 2)
//           return 5;
//       bpf_arena_free_pages(&arena, (void __arena *)page2, 1);
//       if (*page1 != 1)
//           return 6;
//       if (*page2 != 0) /* use-after-free should return 0 */
//           return 7;
//       page3 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!page3)
//           return 8;
//       *page3 = 3;
//       if (page2 != page3)
//           return 9;
//       if (*page1 != 1)
//           return 10;
//   #endif
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn basic_alloc1(_ctx: *mut c_void) -> i32 {
    unsafe {
    let page1 = alloc(core::ptr::null_mut::<u32>(), 1);
    if page1.is_null() {
        return 1;
    }
    vstore(page1, 1);
    let page2 = alloc(core::ptr::null_mut::<u32>(), 1);
    if page2.is_null() {
        return 2;
    }
    vstore(page2, 2);
    let no_page = alloc(core::ptr::null_mut::<u32>(), 1);
    if !no_page.is_null() {
        return 3;
    }
    if vload(page1) != 1 {
        return 4;
    }
    if vload(page2) != 2 {
        return 5;
    }
    free(page2, 1);
    if vload(page1) != 1 {
        return 6;
    }
    if vload(page2) != 0 {
        // use-after-free should return 0
        return 7;
    }
    let page3 = alloc(core::ptr::null_mut::<u32>(), 1);
    if page3.is_null() {
        return 8;
    }
    vstore(page3, 3);
    if page2 != page3 {
        return 9;
    }
    if vload(page1) != 1 {
        return 10;
    }
    0
    }
}

// HAND: free_scalar_below_arena -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int free_scalar_below_arena(void *ctx)
//   {
//       void __arena *page1, *page2, *page3;
//       __u64 bad_addr = ARENA_VM_START - __PAGE_SIZE;
//
//       page1 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!page1)
//           return 1;
//
//       page2 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!page2)
//           return 2;
//
//       page3 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (page3)
//           return 3;
//
//       bpf_arena_free_pages(&arena, (void __arena *)bad_addr, 1);
//
//       page3 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (page3)
//           return 4;
//
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn free_scalar_below_arena(_ctx: *mut c_void) -> i32 {
    unsafe {
    let bad_addr: u64 = ARENA_VM_START - PAGE_SIZE;

    let page1 = alloc(core::ptr::null_mut::<u8>(), 1);
    if page1.is_null() {
        return 1;
    }

    let page2 = alloc(core::ptr::null_mut::<u8>(), 1);
    if page2.is_null() {
        return 2;
    }

    let page3 = alloc(core::ptr::null_mut::<u8>(), 1);
    if !page3.is_null() {
        return 3;
    }

    free(bad_addr as *mut u8, 1);

    let page3 = alloc(core::ptr::null_mut::<u8>(), 1);
    if !page3.is_null() {
        return 4;
    }

    0
    }
}

// HAND: basic_alloc2_nosleep -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(0)
//   int basic_alloc2_nosleep(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       volatile char __arena *page1, *page2, *page3, *page4;
//
//       page1 = bpf_arena_alloc_pages(&arena, NULL, 2, NUMA_NO_NODE, 0);
//       if (!page1)
//           return 1;
//       page2 = page1 + __PAGE_SIZE;
//       page3 = page1 + __PAGE_SIZE * 2;
//       page4 = page1 - __PAGE_SIZE;
//       *page1 = 1;
//       *page2 = 2;
//       *page3 = 3;
//       *page4 = 4;
//       if (*page1 != 1)
//           return 1;
//       if (*page2 != 2)
//           return 2;
//       if (*page3 != 0)
//           return 3;
//       if (*page4 != 0)
//           return 4;
//       bpf_arena_free_pages(&arena, (void __arena *)page1, 2);
//       if (*page1 != 0 && *page1 != 1)
//           return 5;
//       if (*page2 != 0 && *page2 != 2)
//           return 6;
//       if (*page3 != 0)
//           return 7;
//       if (*page4 != 0)
//           return 8;
//   #endif
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn basic_alloc2_nosleep(_ctx: *mut c_void) -> i32 {
    unsafe {
    let page1 = alloc(core::ptr::null_mut::<u8>(), 2);
    if page1.is_null() {
        return 1;
    }
    let page2 = page1.wrapping_add(PAGE_SIZE as usize);
    let page3 = page1.wrapping_add(PAGE_SIZE as usize * 2);
    let page4 = page1.wrapping_sub(PAGE_SIZE as usize);
    vstore(page1, 1);
    vstore(page2, 2);
    vstore(page3, 3);
    vstore(page4, 4);
    if vload(page1) != 1 {
        return 1;
    }
    if vload(page2) != 2 {
        return 2;
    }
    if vload(page3) != 0 {
        return 3;
    }
    if vload(page4) != 0 {
        return 4;
    }
    free(page1, 2);
    if vload(page1) != 0 && vload(page1) != 1 {
        return 5;
    }
    if vload(page2) != 0 && vload(page2) != 2 {
        return 6;
    }
    if vload(page3) != 0 {
        return 7;
    }
    if vload(page4) != 0 {
        return 8;
    }
    0
    }
}

// HAND: basic_alloc2 -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int basic_alloc2(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       volatile char __arena *page1, *page2, *page3, *page4;
//
//       page1 = bpf_arena_alloc_pages(&arena, NULL, 2, NUMA_NO_NODE, 0);
//       if (!page1)
//           return 1;
//       page2 = page1 + __PAGE_SIZE;
//       page3 = page1 + __PAGE_SIZE * 2;
//       page4 = page1 - __PAGE_SIZE;
//       *page1 = 1;
//       *page2 = 2;
//       *page3 = 3;
//       *page4 = 4;
//       if (*page1 != 1)
//           return 1;
//       if (*page2 != 2)
//           return 2;
//       if (*page3 != 0)
//           return 3;
//       if (*page4 != 0)
//           return 4;
//       bpf_arena_free_pages(&arena, (void __arena *)page1, 2);
//       if (*page1 != 0)
//           return 5;
//       if (*page2 != 0)
//           return 6;
//       if (*page3 != 0)
//           return 7;
//       if (*page4 != 0)
//           return 8;
//   #endif
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn basic_alloc2(_ctx: *mut c_void) -> i32 {
    unsafe {
    let page1 = alloc(core::ptr::null_mut::<u8>(), 2);
    if page1.is_null() {
        return 1;
    }
    let page2 = page1.wrapping_add(PAGE_SIZE as usize);
    let page3 = page1.wrapping_add(PAGE_SIZE as usize * 2);
    let page4 = page1.wrapping_sub(PAGE_SIZE as usize);
    vstore(page1, 1);
    vstore(page2, 2);
    vstore(page3, 3);
    vstore(page4, 4);
    if vload(page1) != 1 {
        return 1;
    }
    if vload(page2) != 2 {
        return 2;
    }
    if vload(page3) != 0 {
        return 3;
    }
    if vload(page4) != 0 {
        return 4;
    }
    free(page1, 2);
    if vload(page1) != 0 {
        return 5;
    }
    if vload(page2) != 0 {
        return 6;
    }
    if vload(page3) != 0 {
        return 7;
    }
    if vload(page4) != 0 {
        return 8;
    }
    0
    }
}

// HAND: basic_alloc3_nosleep -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(0) __log_level(2)
//   int basic_alloc3_nosleep(void *ctx)
//   {
//       struct bpf_arena___l *ar = (struct bpf_arena___l *)&arena;
//       volatile char __arena *pages;
//
//       pages = bpf_arena_alloc_pages(&ar->map, NULL, ar->map.max_entries, NUMA_NO_NODE, 0);
//       if (!pages)
//           return 1;
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn basic_alloc3_nosleep(_ctx: *mut c_void) -> i32 {
    unsafe {
    let ar = core::ptr::addr_of!(arena) as *mut bpf_arena___l;

    let pages = bpf_arena_alloc_pages(
        (*ar).map().field.as_ptr() as *mut c_void,
        core::ptr::null_mut(),
        *(*ar).map().max_entries().get().unwrap(),
        NUMA_NO_NODE,
        0,
    );
    if pages.is_null() {
        return 1;
    }
    0
    }
}

// HAND: basic_alloc3 -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0) __log_level(2)
//   int basic_alloc3(void *ctx)
//   {
//       struct bpf_arena___l *ar = (struct bpf_arena___l *)&arena;
//       volatile char __arena *pages;
//
//       pages = bpf_arena_alloc_pages(&ar->map, NULL, ar->map.max_entries, NUMA_NO_NODE, 0);
//       if (!pages)
//           return 1;
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn basic_alloc3(_ctx: *mut c_void) -> i32 {
    unsafe {
    let ar = core::ptr::addr_of!(arena) as *mut bpf_arena___l;

    let pages = bpf_arena_alloc_pages(
        (*ar).map().field.as_ptr() as *mut c_void,
        core::ptr::null_mut(),
        *(*ar).map().max_entries().get().unwrap(),
        NUMA_NO_NODE,
        0,
    );
    if pages.is_null() {
        return 1;
    }
    0
    }
}

// HAND: basic_reserve1_nosleep -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(0)
//   int basic_reserve1_nosleep(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       char __arena *page;
//       int ret;
//
//       page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!page)
//           return 1;
//
//       page += __PAGE_SIZE;
//
//       /* Reserve the second page */
//       ret = bpf_arena_reserve_pages(&arena, page, 1);
//       if (ret)
//           return 2;
//
//       /* Try to explicitly allocate the reserved page. */
//       page = bpf_arena_alloc_pages(&arena, page, 1, NUMA_NO_NODE, 0);
//       if (page)
//           return 3;
//
//       /* Try to implicitly allocate the page (since there's only 2 of them). */
//       page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (page)
//           return 4;
//   #endif
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn basic_reserve1_nosleep(_ctx: *mut c_void) -> i32 {
    unsafe {
    let mut page = alloc(core::ptr::null_mut::<u8>(), 1);
    if page.is_null() {
        return 1;
    }

    page = page.wrapping_add(PAGE_SIZE as usize);

    // Reserve the second page
    let ret = reserve(page, 1);
    if ret != 0 {
        return 2;
    }

    // Try to explicitly allocate the reserved page.
    page = alloc(page, 1);
    if !page.is_null() {
        return 3;
    }

    // Try to implicitly allocate the page (since there's only 2 of them).
    page = alloc(core::ptr::null_mut::<u8>(), 1);
    if !page.is_null() {
        return 4;
    }
    0
    }
}

// HAND: basic_reserve1 -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int basic_reserve1(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       char __arena *page;
//       int ret;
//
//       page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!page)
//           return 1;
//
//       page += __PAGE_SIZE;
//
//       /* Reserve the second page */
//       ret = bpf_arena_reserve_pages(&arena, page, 1);
//       if (ret)
//           return 2;
//
//       /* Try to explicitly allocate the reserved page. */
//       page = bpf_arena_alloc_pages(&arena, page, 1, NUMA_NO_NODE, 0);
//       if (page)
//           return 3;
//
//       /* Try to implicitly allocate the page (since there's only 2 of them). */
//       page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (page)
//           return 4;
//   #endif
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn basic_reserve1(_ctx: *mut c_void) -> i32 {
    unsafe {
    let mut page = alloc(core::ptr::null_mut::<u8>(), 1);
    if page.is_null() {
        return 1;
    }

    page = page.wrapping_add(PAGE_SIZE as usize);

    // Reserve the second page
    let ret = reserve(page, 1);
    if ret != 0 {
        return 2;
    }

    // Try to explicitly allocate the reserved page.
    page = alloc(page, 1);
    if !page.is_null() {
        return 3;
    }

    // Try to implicitly allocate the page (since there's only 2 of them).
    page = alloc(core::ptr::null_mut::<u8>(), 1);
    if !page.is_null() {
        return 4;
    }
    0
    }
}

// HAND: basic_reserve2_nosleep -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(0)
//   int basic_reserve2_nosleep(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       char __arena *page;
//       int ret;
//
//       page = arena_base(&arena);
//       ret = bpf_arena_reserve_pages(&arena, page, 1);
//       if (ret)
//           return 1;
//
//       page = bpf_arena_alloc_pages(&arena, page, 1, NUMA_NO_NODE, 0);
//       if ((u64)page)
//           return 2;
//   #endif
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn basic_reserve2_nosleep(_ctx: *mut c_void) -> i32 {
    unsafe {
    let page = arena_base() as *mut u8;
    let ret = reserve(page, 1);
    if ret != 0 {
        return 1;
    }

    let page = alloc(page, 1);
    if page as u64 != 0 {
        return 2;
    }
    0
    }
}

// HAND: basic_reserve2 -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int basic_reserve2(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       char __arena *page;
//       int ret;
//
//       page = arena_base(&arena);
//       ret = bpf_arena_reserve_pages(&arena, page, 1);
//       if (ret)
//           return 1;
//
//       page = bpf_arena_alloc_pages(&arena, page, 1, NUMA_NO_NODE, 0);
//       if ((u64)page)
//           return 2;
//   #endif
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn basic_reserve2(_ctx: *mut c_void) -> i32 {
    unsafe {
    let page = arena_base() as *mut u8;
    let ret = reserve(page, 1);
    if ret != 0 {
        return 1;
    }

    let page = alloc(page, 1);
    if page as u64 != 0 {
        return 2;
    }
    0
    }
}

// HAND: reserve_twice_nosleep -- translate the C below (see the file comment)
//   /* Reserve the same page twice, should return -EBUSY. */
//   SEC("socket")
//   __success __retval(0)
//   int reserve_twice_nosleep(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       char __arena *page;
//       int ret;
//
//       page = arena_base(&arena);
//
//       ret = bpf_arena_reserve_pages(&arena, page, 1);
//       if (ret)
//           return 1;
//
//       ret = bpf_arena_reserve_pages(&arena, page, 1);
//       if (ret != -EBUSY)
//           return 2;
//   #endif
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn reserve_twice_nosleep(_ctx: *mut c_void) -> i32 {
    unsafe {
    let page = arena_base() as *mut u8;

    let ret = reserve(page, 1);
    if ret != 0 {
        return 1;
    }

    let ret = reserve(page, 1);
    if ret != -EBUSY {
        return 2;
    }
    0
    }
}

// HAND: reserve_twice -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int reserve_twice(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       char __arena *page;
//       int ret;
//
//       page = arena_base(&arena);
//
//       ret = bpf_arena_reserve_pages(&arena, page, 1);
//       if (ret)
//           return 1;
//
//       ret = bpf_arena_reserve_pages(&arena, page, 1);
//       if (ret != -EBUSY)
//           return 2;
//   #endif
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn reserve_twice(_ctx: *mut c_void) -> i32 {
    unsafe {
    let page = arena_base() as *mut u8;

    let ret = reserve(page, 1);
    if ret != 0 {
        return 1;
    }

    let ret = reserve(page, 1);
    if ret != -EBUSY {
        return 2;
    }
    0
    }
}

// HAND: reserve_invalid_region_nosleep -- translate the C below (see the file comment)
//   /* Try to reserve past the end of the arena. */
//   SEC("socket")
//   __success __retval(0)
//   int reserve_invalid_region_nosleep(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       char __arena *page;
//       int ret;
//
//       /* Try a NULL pointer. */
//       ret = bpf_arena_reserve_pages(&arena, NULL, 3);
//       if (ret != -EINVAL)
//           return 1;
//
//       page = arena_base(&arena);
//
//       ret = bpf_arena_reserve_pages(&arena, page, 3);
//       if (ret != -EINVAL)
//           return 2;
//
//       ret = bpf_arena_reserve_pages(&arena, page, 4096);
//       if (ret != -EINVAL)
//           return 3;
//
//       ret = bpf_arena_reserve_pages(&arena, page, (1ULL << 32) - 1);
//       if (ret != -EINVAL)
//           return 4;
//   #endif
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn reserve_invalid_region_nosleep(_ctx: *mut c_void) -> i32 {
    unsafe {
    // Try a NULL pointer.
    let ret = reserve(core::ptr::null_mut::<u8>(), 3);
    if ret != -EINVAL {
        return 1;
    }

    let page = arena_base() as *mut u8;

    let ret = reserve(page, 3);
    if ret != -EINVAL {
        return 2;
    }

    let ret = reserve(page, 4096);
    if ret != -EINVAL {
        return 3;
    }

    let ret = reserve(page, ((1u64 << 32) - 1) as u32);
    if ret != -EINVAL {
        return 4;
    }
    0
    }
}

// HAND: reserve_invalid_region -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int reserve_invalid_region(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       char __arena *page;
//       int ret;
//
//       /* Try a NULL pointer. */
//       ret = bpf_arena_reserve_pages(&arena, NULL, 3);
//       if (ret != -EINVAL)
//           return 1;
//
//       page = arena_base(&arena);
//
//       ret = bpf_arena_reserve_pages(&arena, page, 3);
//       if (ret != -EINVAL)
//           return 2;
//
//       ret = bpf_arena_reserve_pages(&arena, page, 4096);
//       if (ret != -EINVAL)
//           return 3;
//
//       ret = bpf_arena_reserve_pages(&arena, page, (1ULL << 32) - 1);
//       if (ret != -EINVAL)
//           return 4;
//   #endif
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn reserve_invalid_region(_ctx: *mut c_void) -> i32 {
    unsafe {
    // Try a NULL pointer.
    let ret = reserve(core::ptr::null_mut::<u8>(), 3);
    if ret != -EINVAL {
        return 1;
    }

    let page = arena_base() as *mut u8;

    let ret = reserve(page, 3);
    if ret != -EINVAL {
        return 2;
    }

    let ret = reserve(page, 4096);
    if ret != -EINVAL {
        return 3;
    }

    let ret = reserve(page, ((1u64 << 32) - 1) as u32);
    if ret != -EINVAL {
        return 4;
    }
    0
    }
}

// HAND: iter_maps1 -- translate the C below (see the file comment)
//   SEC("iter.s/bpf_map")
//   __success __log_level(2)
//   int iter_maps1(struct bpf_iter__bpf_map *ctx)
//   {
//       struct bpf_map *map = ctx->map;
//
//       if (!map)
//           return 0;
//       bpf_arena_alloc_pages(map, NULL, map->max_entries, 0, 0);
//       return 0;
//   }
#[link_section = "iter.s/bpf_map"]
#[no_mangle]
extern "C" fn iter_maps1(ctx: *mut bpf_iter__bpf_map) -> i32 {
    unsafe {
    let map: *mut bpf_map = *(*ctx).map().get().unwrap();

    if map.is_null() {
        return 0;
    }
    bpf_arena_alloc_pages(map as *mut c_void, core::ptr::null_mut(), *(*map).max_entries().get().unwrap(), 0, 0);
    0
    }
}

// HAND: iter_maps2 -- translate the C below (see the file comment)
//   SEC("iter.s/bpf_map")
//   __failure __msg("expected pointer to STRUCT bpf_map")
//   int iter_maps2(struct bpf_iter__bpf_map *ctx)
//   {
//       struct seq_file *seq = ctx->meta->seq;
//
//       bpf_arena_alloc_pages((void *)seq, NULL, 1, 0, 0);
//       return 0;
//   }
#[link_section = "iter.s/bpf_map"]
#[no_mangle]
extern "C" fn iter_maps2(ctx: *mut bpf_iter__bpf_map) -> i32 {
    unsafe {
    let meta: *mut bpf_iter_meta = *(*ctx).meta().get().unwrap();
    let seq: *mut seq_file = *(*meta).seq().get().unwrap();

    bpf_arena_alloc_pages(seq as *mut c_void, core::ptr::null_mut(), 1, 0, 0);
    0
    }
}

// HAND: iter_maps3 -- translate the C below (see the file comment)
//   SEC("iter.s/bpf_map")
//   __failure __msg("untrusted_ptr_bpf_map")
//   int iter_maps3(struct bpf_iter__bpf_map *ctx)
//   {
//       struct bpf_map *map = ctx->map;
//
//       if (!map)
//           return 0;
//       bpf_arena_alloc_pages(map->inner_map_meta, NULL, map->max_entries, 0, 0);
//       return 0;
//   }
#[link_section = "iter.s/bpf_map"]
#[no_mangle]
extern "C" fn iter_maps3(ctx: *mut bpf_iter__bpf_map) -> i32 {
    unsafe {
    let map: *mut bpf_map = *(*ctx).map().get().unwrap();

    if map.is_null() {
        return 0;
    }
    bpf_arena_alloc_pages(
        *(*map).inner_map_meta().get().unwrap() as *mut c_void,
        core::ptr::null_mut(),
        *(*map).max_entries().get().unwrap(),
        0,
        0,
    );
    0
    }
}

// HAND: arena_kfuncs_under_bpf_lock -- translate the C below (see the file comment)
//   /* Use the arena kfunc API while under a BPF lock. */
//   SEC("syscall")
//   __success __retval(0)
//   int arena_kfuncs_under_bpf_lock(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       char __arena *page;
//       int ret;
//
//       bpf_spin_lock(&arena_bpf_test_lock);
//
//       /* Get a separate region of the arena. */
//       page = arena_base(&arena);
//       ret = bpf_arena_reserve_pages(&arena, page, 1);
//       if (ret) {
//           bpf_spin_unlock(&arena_bpf_test_lock);
//           return 1;
//       }
//
//       bpf_arena_free_pages(&arena, page, 1);
//
//       page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!page) {
//           bpf_spin_unlock(&arena_bpf_test_lock);
//           return 2;
//       }
//
//       bpf_arena_free_pages(&arena, page, 1);
//
//       bpf_spin_unlock(&arena_bpf_test_lock);
//   #endif
//
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arena_kfuncs_under_bpf_lock(_ctx: *mut c_void) -> i32 {
    unsafe {
    bpf_spin_lock(core::ptr::addr_of_mut!(arena_bpf_test_lock));

    // Get a separate region of the arena.
    let page = arena_base() as *mut u8;
    let ret = reserve(page, 1);
    if ret != 0 {
        bpf_spin_unlock(core::ptr::addr_of_mut!(arena_bpf_test_lock));
        return 1;
    }

    free(page, 1);

    let page = alloc(core::ptr::null_mut::<u8>(), 1);
    if page.is_null() {
        bpf_spin_unlock(core::ptr::addr_of_mut!(arena_bpf_test_lock));
        return 2;
    }

    free(page, 1);

    bpf_spin_unlock(core::ptr::addr_of_mut!(arena_bpf_test_lock));
    }

    0
}

// HAND: scalar_add_arena_ptr -- translate the C below (see the file comment)
//   /*
//    * Test that scalar += PTR_TO_ARENA correctly upgrades the
//    * destination register to a PTR_TO_ARENA.
//    */
//   SEC("syscall")
//   __success __retval(0)
//   int scalar_add_arena_ptr(void *ctx)
//   {
//       int __arena *scalar, *arena_ptr;
//
//       volatile char __arena *base = arena_base(&arena);
//
//       asm volatile (
//           "%[arena_ptr] = 8192;"
//           "%[arena_ptr] = addr_space_cast(%[arena_ptr], 0x0, 0x1);"
//           "%[scalar] = 12;"
//           "%[scalar] += %[arena_ptr];"
//           : [scalar] "=r"(scalar),
//             [arena_ptr] "=&r"(arena_ptr)
//           : "r"(base)
//           :
//       );
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn scalar_add_arena_ptr(_ctx: *mut c_void) -> i32 {
    // Test that scalar += PTR_TO_ARENA correctly upgrades the
    // destination register to a PTR_TO_ARENA.
    let base = unsafe { arena_base() };

    unsafe {
        core::arch::asm!(
            "{arena_ptr} = 8192",
            "{arena_ptr} = addr_space_cast({arena_ptr}, 0x0, 0x1)",
            "{scalar} = 12",
            "{scalar} += {arena_ptr}",
            "/* {base} */",
            scalar = out(reg) _,
            arena_ptr = out(reg) _,
            base = in(reg) base,
            options(nostack),
        );
    }
    0
}

// HAND: arena_ptr_add_arena_ptr -- translate the C below (see the file comment)
//   /*
//    * Tests that PTR_TO_ARENA + PTR_TO_ARENA is allowed.
//    */
//   SEC("syscall")
//   __success __retval(0)
//   int arena_ptr_add_arena_ptr(void *ctx)
//   {
//       int __arena *arena_ptr2, *arena_ptr1;
//
//       /* Needed for the verifier to link the arena to the subprog. */
//       volatile char __arena *base = arena_base(&arena);
//
//       asm volatile (
//           "%[arena_ptr1] = 8192;"
//           "%[arena_ptr1] = addr_space_cast(%[arena_ptr1], 0x0, 0x1);"
//           "%[arena_ptr2] = 4096;"
//           "%[arena_ptr2] = addr_space_cast(%[arena_ptr2], 0x0, 0x1);"
//           "%[arena_ptr2] += %[arena_ptr1];"
//           : [arena_ptr2] "=r"(arena_ptr2),
//             [arena_ptr1] "=&r"(arena_ptr1)
//           : "r"(base)
//           :
//       );
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arena_ptr_add_arena_ptr(_ctx: *mut c_void) -> i32 {
    // Tests that PTR_TO_ARENA + PTR_TO_ARENA is allowed.
    // Needed for the verifier to link the arena to the subprog.
    let base = unsafe { arena_base() };

    unsafe {
        core::arch::asm!(
            "{arena_ptr1} = 8192",
            "{arena_ptr1} = addr_space_cast({arena_ptr1}, 0x0, 0x1)",
            "{arena_ptr2} = 4096",
            "{arena_ptr2} = addr_space_cast({arena_ptr2}, 0x0, 0x1)",
            "{arena_ptr2} += {arena_ptr1}",
            "/* {base} */",
            arena_ptr2 = out(reg) _,
            arena_ptr1 = out(reg) _,
            base = in(reg) base,
            options(nostack),
        );
    }
    0
}

// HAND: mixed_arena_scalar_alu64_scalar_first -- translate the C below (see the file comment)
//   SEC("syscall")
//   __failure __msg("same insn cannot be used with and without arena pointer")
//   int mixed_arena_scalar_alu64_scalar_first(void *ctx)
//   {
//       volatile register __u64 reg asm("r3");
//       __u32 pick_arena = bpf_get_prandom_u32();
//
//       reg = 1ULL << 32;
//
//       if (pick_arena) {
//           asm volatile (
//               "r9 = %[arena] ll;"
//               "%[reg] = 0;"
//               "%[reg] = addr_space_cast(%[reg], 0x0, 0x1);"
//               : [reg] "=r"(reg)
//               : __imm_addr(arena)
//               : "r9"
//           );
//       }
//
//       reg += 1;
//
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn mixed_arena_scalar_alu64_scalar_first(_ctx: *mut c_void) -> i32 {
    // `volatile register __u64 reg asm("r3")`: clang keeps it in a stack
    // slot, where both the scalar and the arena pointer land
    let mut reg = core::mem::MaybeUninit::<u64>::uninit();
    let pick_arena = bpf_get_prandom_u32();

    unsafe { core::ptr::write_volatile(reg.as_mut_ptr(), 1u64 << 32) };

    if pick_arena != 0 {
        let v: u64;
        unsafe {
            core::arch::asm!(
                "r9 = {arena} ll",
                "r3 = 0",
                "r3 = addr_space_cast(r3, 0x0, 0x1)",
                arena = sym arena,
                out("r3") v,
                out("r9") _,
                options(nostack),
            );
            core::ptr::write_volatile(reg.as_mut_ptr(), v);
        }
    }

    unsafe {
        let v = core::ptr::read_volatile(reg.as_ptr());
        core::ptr::write_volatile(reg.as_mut_ptr(), v.wrapping_add(1));
    }

    0
}

// HAND: mixed_arena_scalar_alu64_arena_first -- translate the C below (see the file comment)
//   SEC("syscall")
//   __failure __msg("same insn cannot be used with and without arena pointer")
//   int mixed_arena_scalar_alu64_arena_first(void *ctx)
//   {
//       volatile register __u64 reg asm("r3");
//       __u32 pick_scalar = bpf_get_prandom_u32();
//
//       asm volatile (
//           "r9 = %[arena] ll;"
//           "%[reg] = 0;"
//           "%[reg] = addr_space_cast(%[reg], 0x0, 0x1);"
//           : [reg] "=r"(reg)
//           : __imm_addr(arena)
//           : "r9"
//       );
//
//       if (pick_scalar)
//           reg = 1ULL << 32;
//
//       reg += 1;
//
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn mixed_arena_scalar_alu64_arena_first(_ctx: *mut c_void) -> i32 {
    let mut reg = core::mem::MaybeUninit::<u64>::uninit();
    let pick_scalar = bpf_get_prandom_u32();

    unsafe {
        let v: u64;
        core::arch::asm!(
            "r9 = {arena} ll",
            "r3 = 0",
            "r3 = addr_space_cast(r3, 0x0, 0x1)",
            arena = sym arena,
            out("r3") v,
            out("r9") _,
            options(nostack),
        );
        core::ptr::write_volatile(reg.as_mut_ptr(), v);
    }

    if pick_scalar != 0 {
        unsafe { core::ptr::write_volatile(reg.as_mut_ptr(), 1u64 << 32) };
    }

    unsafe {
        let v = core::ptr::read_volatile(reg.as_ptr());
        core::ptr::write_volatile(reg.as_mut_ptr(), v.wrapping_add(1));
    }

    0
}

// HAND: scalar_xor_arena_ptr -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int scalar_xor_arena_ptr(void *ctx)
//   {
//       int __arena *scalar, *arena_ptr;
//
//       volatile char __arena *base = arena_base(&arena);
//
//       asm volatile (
//           "%[arena_ptr] = 8192;"
//           "%[arena_ptr] = addr_space_cast(%[arena_ptr], 0x0, 0x1);"
//           "%[scalar] = 12;"
//           "%[scalar] ^= %[arena_ptr];"
//           : [scalar] "=r"(scalar),
//             [arena_ptr] "=&r"(arena_ptr)
//           : "r"(base)
//           :
//       );
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn scalar_xor_arena_ptr(_ctx: *mut c_void) -> i32 {
    let base = unsafe { arena_base() };

    unsafe {
        core::arch::asm!(
            "{arena_ptr} = 8192",
            "{arena_ptr} = addr_space_cast({arena_ptr}, 0x0, 0x1)",
            "{scalar} = 12",
            "{scalar} ^= {arena_ptr}",
            "/* {base} */",
            scalar = out(reg) _,
            arena_ptr = out(reg) _,
            base = in(reg) base,
            options(nostack),
        );
    }
    0
}

// HAND: arena_ptr_add_to_non_arena_ptr -- translate the C below (see the file comment)
//   /*
//    * Tests that PTR_TO_ARENA and non-arena pointers can be added.
//    */
//   SEC("syscall")
//   __success __retval(0)
//   int arena_ptr_add_to_non_arena_ptr(void *ctx)
//   {
//       register int __arena *arena_ptr asm("r3");
//       register void *dst asm("r4");
//
//       volatile char __arena *base = arena_base(&arena);
//
//       asm volatile (
//           "%[arena_ptr] = 8192;"
//           "%[arena_ptr] = addr_space_cast(%[arena_ptr], 0x0, 0x1);"
//           "%[dst] = %[ctx];"
//           "%[dst] += %[arena_ptr];"
//           : [arena_ptr] "=&r"(arena_ptr),
//             [dst] "=&r"(dst)
//           : [ctx] "r"(ctx), "r"(base)
//           :
//       );
//
//       (void)ctx;
//
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arena_ptr_add_to_non_arena_ptr(ctx: *mut c_void) -> i32 {
    // Tests that PTR_TO_ARENA and non-arena pointers can be added.
    let base = unsafe { arena_base() };

    unsafe {
        core::arch::asm!(
            "r3 = 8192",
            "r3 = addr_space_cast(r3, 0x0, 0x1)",
            "r4 = {ctx}",
            "r4 += r3",
            "/* {base} */",
            ctx = in(reg) ctx,
            base = in(reg) base,
            out("r3") _,
            out("r4") _,
            options(nostack),
        );
    }
    0
}

// HAND: non_arena_ptr_add_to_arena_ptr -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int non_arena_ptr_add_to_arena_ptr(void *ctx)
//   {
//       register int __arena *arena_ptr asm("r3");
//       register void *src asm("r4");
//
//       volatile char __arena *base = arena_base(&arena);
//
//       asm volatile (
//           "%[arena_ptr] = 8192;"
//           "%[arena_ptr] = addr_space_cast(%[arena_ptr], 0x0, 0x1);"
//           "%[src] = %[ctx];"
//           "%[arena_ptr] += %[src];"
//           : [arena_ptr] "=&r"(arena_ptr),
//             [src] "=&r"(src)
//           : [ctx] "r"(ctx), "r"(base)
//           :
//       );
//
//       (void)ctx;
//
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn non_arena_ptr_add_to_arena_ptr(ctx: *mut c_void) -> i32 {
    let base = unsafe { arena_base() };

    unsafe {
        core::arch::asm!(
            "r3 = 8192",
            "r3 = addr_space_cast(r3, 0x0, 0x1)",
            "r4 = {ctx}",
            "r3 += r4",
            "/* {base} */",
            ctx = in(reg) ctx,
            base = in(reg) base,
            out("r3") _,
            out("r4") _,
            options(nostack),
        );
    }
    0
}

// HAND: check_arena_arg_nonglobal -- translate the C below (see the file comment)
//   static __noinline
//   u32 __arena *check_arena_arg_nonglobal(u32 __arena *arg)
//   {
//       volatile u32 val = *arg;
//
//       *arg = val + 1;
//
//       return arg;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn check_arena_arg_nonglobal(arg: *mut u32) -> *mut u32 {
    unsafe {
    let p = cast_kern(arg);
    // volatile u32 val = *arg
    let mut val = core::mem::MaybeUninit::<u32>::uninit();
    core::ptr::write_volatile(val.as_mut_ptr(), *p);

    *p = core::ptr::read_volatile(val.as_ptr()).wrapping_add(1);

    arg
    }
}

// HAND: check_arena_arg_global -- translate the C below (see the file comment)
//   __weak
//   u32 __arena *check_arena_arg_global(u32 __arena *arg)
//   {
//       volatile u32 val = *arg;
//
//       *arg = val + 1;
//
//       return arg;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn check_arena_arg_global(arg: *mut u32) -> *mut u32 {
    unsafe {
    let p = cast_kern(arg);
    // volatile u32 val = *arg
    let mut val = core::mem::MaybeUninit::<u32>::uninit();
    core::ptr::write_volatile(val.as_mut_ptr(), *p);

    *p = core::ptr::read_volatile(val.as_ptr()).wrapping_add(1);

    arg
    }
}

// HAND: check_arena_arg_quals1 -- translate the C below (see the file comment)
//   __weak
//   u32 volatile __arena *check_arena_arg_quals1(u32 volatile __arena *arg1, u32 __arena volatile *arg2)
//   {
//       *arg1 = *arg1 + 1;
//       *arg2 = *arg1 + 1;
//
//       return arg2;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn check_arena_arg_quals1(arg1: *mut u32, arg2: *mut u32) -> *mut u32 {
    unsafe {
    let p1 = cast_kern(arg1);
    let p2 = cast_kern(arg2);
    core::ptr::write_volatile(p1, core::ptr::read_volatile(p1).wrapping_add(1));
    core::ptr::write_volatile(p2, core::ptr::read_volatile(p1).wrapping_add(1));

    arg2
    }
}

// HAND: check_arena_arg_quals2 -- translate the C below (see the file comment)
//   __weak
//   u32 __arena volatile *check_arena_arg_quals2(u32 volatile __arena *arg1, u32 __arena volatile *arg2)
//   {
//       *arg1 = *arg1 + 1;
//       *arg2 = *arg2 + 1;
//
//       return arg2;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn check_arena_arg_quals2(arg1: *mut u32, arg2: *mut u32) -> *mut u32 {
    unsafe {
    let p1 = cast_kern(arg1);
    let p2 = cast_kern(arg2);
    core::ptr::write_volatile(p1, core::ptr::read_volatile(p1).wrapping_add(1));
    core::ptr::write_volatile(p2, core::ptr::read_volatile(p2).wrapping_add(1));

    arg2
    }
}

// HAND: check_arena_arg_ret -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int check_arena_arg_ret(void *ctx)
//   {
//       u32 __arena *page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       u32 __arena *arg = page;
//       u32 __arena volatile *arg1;
//       u32 __arena volatile *ret1;
//       u32 volatile __arena *arg2;
//       u32 volatile __arena *ret2;
//
//       if (!arg)
//           return 1;
//
//       /* Make sure we use {arg, ret}{1, 2}. */
//
//       arg = check_arena_arg_nonglobal(page);
//       arg = check_arena_arg_global(arg);
//
//       arg1 = arg2 = page;
//       ret1 = check_arena_arg_quals1(arg1, arg2);
//       ret2 = check_arena_arg_quals2(arg1, arg2);
//
//       if (!(*ret1 ||*ret2))
//           return -EINVAL;
//
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn check_arena_arg_ret(_ctx: *mut c_void) -> i32 {
    unsafe {
    let page = alloc(core::ptr::null_mut::<u32>(), 1);
    let mut arg = page;

    if arg.is_null() {
        return 1;
    }

    // Make sure we use {arg, ret}{1, 2}.

    arg = check_arena_arg_nonglobal(page);
    arg = check_arena_arg_global(arg);
    let _ = arg;

    let arg1 = page;
    let arg2 = page;
    let ret1 = check_arena_arg_quals1(arg1, arg2);
    let ret2 = check_arena_arg_quals2(arg1, arg2);

    if !(vload(ret1) != 0 || vload(ret2) != 0) {
        return -EINVAL;
    }

    0
    }
}

// HAND: arena_word_pair -- translate the C below (see the file comment)
//   __weak struct arena_word_pair arena_word_pair(u32 __arena *page)
//   {
//       struct arena_word_pair pair;
//
//       pair.first = page;
//       pair.second = page + 1;
//
//       return pair;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: arena_word_pair
extern "C" fn arena_word_pair(_page: *mut u32) -> arena_word_pair {
    unsafe {
        core::arch::asm!("r0 = r1;", "r2 = r0;", "r2 += 4;", "exit;", options(noreturn));
    }
}

// HAND: check_arena_struct_ret -- translate the C below (see the file comment)
//   SEC("syscall")
//   __load_if_JITed()
//   __success __retval(0)
//   int check_arena_struct_ret(void *ctx)
//   {
//       u32 __arena *page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       u32 volatile __arena *first, *second;
//       struct arena_word_pair pair;
//
//       if (!page)
//           return 1;
//
//       pair = arena_word_pair(page);
//       if (!pair.first || !pair.second)
//           return 2;
//
//       /* Both halves of the pair must still be usable as arena pointers. */
//       first = pair.first;
//       second = pair.second;
//       *first = 1;
//       *second = 2;
//       if (*first != 1)
//           return 3;
//       if (*second != 2)
//           return 4;
//
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn check_arena_struct_ret(_ctx: *mut c_void) -> i32 {
    unsafe {
    let page = alloc(core::ptr::null_mut::<u32>(), 1);

    if page.is_null() {
        return 1;
    }

    // pair = arena_word_pair(page): the struct comes back in R0:R2
    let first: *mut u32;
    let second: *mut u32;
    core::arch::asm!(
        "call {f}",
        f = sym arena_word_pair,
        inout("r1") page => _,
        out("r0") first,
        out("r2") second,
        out("r3") _,
        out("r4") _,
        out("r5") _,
        options(nostack),
    );
    if first.is_null() || second.is_null() {
        return 2;
    }

    // Both halves of the pair must still be usable as arena pointers.
    vstore(first, 1);
    vstore(second, 2);
    if vload(first) != 1 {
        return 3;
    }
    if vload(second) != 2 {
        return 4;
    }

    0
    }
}
