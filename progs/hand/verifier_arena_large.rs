// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_arena_large.c, translated
// by hand; include!d by the generated progs/verifier_arena_large.rs (scripts/naked_gen.py
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

/// bpf_may_goto.h's `can_loop` / `cond_break`: a hand-encoded may_goto.
#[inline(always)]
unsafe fn can_loop() -> bool {
    let mut ret = true;
    core::arch::asm!(
        "1:",
        ".byte 0xe5",
        ".byte 0",
        ".long (({0} - 1b - 8) / 8) & 0xffff",
        ".short 0",
        label {
            ret = false;
        },
    );
    ret
}

const ARENA_SIZE: u64 = 1 << 32;
const LARGE_PAGE_CNT: u64 = 1025;
const PAGE_CNT: i32 = 100;

#[inline(always)]
unsafe fn alloc(addr: *mut u8, cnt: u32) -> *mut u8 {
    bpf_arena_alloc_pages(arena_map(), addr as *mut c_void, cnt, NUMA_NO_NODE, 0) as *mut u8
}

#[inline(always)]
unsafe fn free(ptr: *mut u8, cnt: u32) {
    bpf_arena_free_pages(arena_map(), ptr as *mut c_void, cnt)
}

/// `&page[i]`, the arena global array of arena pointers, as a kernel pointer.
#[inline(always)]
unsafe fn page_slot(i: i32) -> *mut *mut u8 {
    (cast_kern(core::ptr::addr_of_mut!(page) as *mut u8) as *mut *mut u8).add(i as usize)
}

// HAND: big_alloc1 -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int big_alloc1(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       volatile char __arena *page1, *page2, *no_page, *page3;
//       u64 base;
//
//       base = (u64)arena_base(&arena);
//
//       page1 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!page1)
//           return 1;
//
//       if ((u64)page1 != base)
//           return 15;
//
//       *page1 = 1;
//       page2 = bpf_arena_alloc_pages(&arena, (void __arena *)(ARENA_SIZE - 2 * PAGE_SIZE),
//                         1, NUMA_NO_NODE, 0);
//       if (!page2)
//           return 2;
//       *page2 = 2;
//
//       /* Test for the guard region at the end of the arena. */
//       no_page = bpf_arena_alloc_pages(&arena, (void __arena *)ARENA_SIZE - PAGE_SIZE,
//                       1, NUMA_NO_NODE, 0);
//       if (no_page)
//           return 16;
//
//       no_page = bpf_arena_alloc_pages(&arena, (void __arena *)ARENA_SIZE,
//                       1, NUMA_NO_NODE, 0);
//       if (no_page)
//           return 3;
//       if (*page1 != 1)
//           return 4;
//       if (*page2 != 2)
//           return 5;
//       bpf_arena_free_pages(&arena, (void __arena *)page1, 1);
//       if (*page2 != 2)
//           return 6;
//       if (*page1 != 0) /* use-after-free should return 0 */
//           return 7;
//       page3 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!page3)
//           return 8;
//       *page3 = 3;
//       if (page1 != page3)
//           return 9;
//       if (*page2 != 2)
//           return 10;
//       if (*(page1 + PAGE_SIZE) != 0)
//           return 11;
//       if (*(page1 - PAGE_SIZE) != 0)
//           return 12;
//       if (*(page2 + PAGE_SIZE) != 0)
//           return 13;
//       if (*(page2 - PAGE_SIZE) != 0)
//           return 14;
//   #endif
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn big_alloc1(_ctx: *mut c_void) -> i32 {
    let base_ = unsafe { arena_base() }; // the C's local `base`, beside the global

    let page1 = unsafe { alloc(core::ptr::null_mut(), 1) };
    if page1.is_null() {
        return 1;
    }

    if page1 as u64 != base_ {
        return 15;
    }

    unsafe { core::ptr::write_volatile(cast_kern(page1), 1) };
    let page2 = unsafe { alloc((ARENA_SIZE - 2 * PAGE_SIZE) as *mut u8, 1) };
    if page2.is_null() {
        return 2;
    }
    unsafe { core::ptr::write_volatile(cast_kern(page2), 2) };

    // Test for the guard region at the end of the arena.
    let no_page = unsafe { alloc((ARENA_SIZE - PAGE_SIZE) as *mut u8, 1) };
    if !no_page.is_null() {
        return 16;
    }

    let no_page = unsafe { alloc(ARENA_SIZE as *mut u8, 1) };
    if !no_page.is_null() {
        return 3;
    }
    if unsafe { core::ptr::read_volatile(cast_kern(page1)) } != 1 {
        return 4;
    }
    if unsafe { core::ptr::read_volatile(cast_kern(page2)) } != 2 {
        return 5;
    }
    unsafe { free(page1, 1) };
    if unsafe { core::ptr::read_volatile(cast_kern(page2)) } != 2 {
        return 6;
    }
    if unsafe { core::ptr::read_volatile(cast_kern(page1)) } != 0 {
        // use-after-free should return 0
        return 7;
    }
    let page3 = unsafe { alloc(core::ptr::null_mut(), 1) };
    if page3.is_null() {
        return 8;
    }
    unsafe { core::ptr::write_volatile(cast_kern(page3), 3) };
    if page1 != page3 {
        return 9;
    }
    if unsafe { core::ptr::read_volatile(cast_kern(page2)) } != 2 {
        return 10;
    }
    if unsafe { core::ptr::read_volatile(cast_kern(page1).add(PAGE_SIZE as usize)) } != 0 {
        return 11;
    }
    if unsafe { core::ptr::read_volatile(cast_kern(page1).sub(PAGE_SIZE as usize)) } != 0 {
        return 12;
    }
    if unsafe { core::ptr::read_volatile(cast_kern(page2).add(PAGE_SIZE as usize)) } != 0 {
        return 13;
    }
    if unsafe { core::ptr::read_volatile(cast_kern(page2).sub(PAGE_SIZE as usize)) } != 0 {
        return 14;
    }
    0
}

// HAND: access_reserved -- translate the C below (see the file comment)
//   /* Try to access a reserved page. Behavior should be identical with accessing unallocated pages. */
//   SEC("syscall")
//   __success __retval(0)
//   int access_reserved(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       volatile char __arena *page;
//       char __arena *base;
//       const size_t len = 4;
//       int ret, i;
//
//       /* Get a separate region of the arena. */
//       page = base = arena_base(&arena) + 16384 * PAGE_SIZE;
//
//       ret = bpf_arena_reserve_pages(&arena, base, len);
//       if (ret)
//           return 1;
//
//       /* Try to dirty reserved memory. */
//       for (i = 0; i < len && can_loop; i++)
//           *page = 0x5a;
//
//       for (i = 0; i < len && can_loop; i++) {
//           page = (volatile char __arena *)(base + i * PAGE_SIZE);
//
//           /*
//            * Error out in case either the write went through,
//            * or the address has random garbage.
//            */
//           if (*page == 0x5a)
//               return 2 + 2 * i;
//
//           if (*page)
//               return 2 + 2 * i + 1;
//       }
//   #endif
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn access_reserved(_ctx: *mut c_void) -> i32 {
    const LEN: u64 = 4;

    // Get a separate region of the arena.
    let base_ = (unsafe { arena_base() } + 16384 * PAGE_SIZE) as *mut u8; // the C's local `base`
    let page_ = base_;

    let ret = unsafe { bpf_arena_reserve_pages(arena_map(), base_ as *mut c_void, LEN as u32) };
    if ret != 0 {
        return 1;
    }

    // Try to dirty reserved memory.
    let mut i: u64 = 0;
    while i < LEN && unsafe { can_loop() } {
        unsafe { core::ptr::write_volatile(cast_kern(page_), 0x5a) };
        i += 1;
    }

    let mut i: u64 = 0;
    while i < LEN && unsafe { can_loop() } {
        let page_ = unsafe { cast_kern(base_.add((i * PAGE_SIZE) as usize)) };

        // Error out in case either the write went through,
        // or the address has random garbage.
        if unsafe { core::ptr::read_volatile(page_) } == 0x5a {
            return (2 + 2 * i) as i32;
        }

        if unsafe { core::ptr::read_volatile(page_) } != 0 {
            return (2 + 2 * i + 1) as i32;
        }
        i += 1;
    }
    0
}

// HAND: request_partially_reserved -- translate the C below (see the file comment)
//   /* Try to allocate a region overlapping with a reservation. */
//   SEC("syscall")
//   __success __retval(0)
//   int request_partially_reserved(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       volatile char __arena *page;
//       char __arena *base;
//       int ret;
//
//       /* Add an arbitrary page offset. */
//       page = base = arena_base(&arena) + 4096 * __PAGE_SIZE;
//
//       ret = bpf_arena_reserve_pages(&arena, base + 3 * __PAGE_SIZE, 4);
//       if (ret)
//           return 1;
//
//       page = bpf_arena_alloc_pages(&arena, base, 5, NUMA_NO_NODE, 0);
//       if ((u64)page != 0ULL)
//           return 2;
//   #endif
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn request_partially_reserved(_ctx: *mut c_void) -> i32 {
    // Add an arbitrary page_ offset.
    let base_ = (unsafe { arena_base() } + 4096 * PAGE_SIZE) as *mut u8; // the C's local `base`

    let ret = unsafe { bpf_arena_reserve_pages(arena_map(), base_.add((3 * PAGE_SIZE) as usize) as *mut c_void, 4) };
    if ret != 0 {
        return 1;
    }

    let page_ = unsafe { alloc(base_, 5) };
    if page_ as u64 != 0 {
        return 2;
    }
    0
}

// HAND: free_reserved -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int free_reserved(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       char __arena *addr;
//       char __arena *page;
//       int ret;
//
//       /* Add an arbitrary page offset. */
//       addr = arena_base(&arena) + 32768 * __PAGE_SIZE;
//
//       page = bpf_arena_alloc_pages(&arena, addr, 2, NUMA_NO_NODE, 0);
//       if (!page)
//           return 1;
//
//       ret = bpf_arena_reserve_pages(&arena, addr + 2 * __PAGE_SIZE, 2);
//       if (ret)
//           return 2;
//
//       /*
//        * Reserved and allocated pages should be interchangeable for
//        * bpf_arena_free_pages(). Free a reserved and an allocated
//        * page with a single call.
//        */
//       bpf_arena_free_pages(&arena, addr + __PAGE_SIZE , 2);
//
//       /* The free call above should have succeeded, so this allocation should too. */
//       page = bpf_arena_alloc_pages(&arena, addr + __PAGE_SIZE, 2, NUMA_NO_NODE, 0);
//       if (!page)
//           return 3;
//   #endif
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn free_reserved(_ctx: *mut c_void) -> i32 {
    // Add an arbitrary page_ offset.
    let addr = (unsafe { arena_base() } + 32768 * PAGE_SIZE) as *mut u8;

    let page_ = unsafe { alloc(addr, 2) };
    if page_.is_null() {
        return 1;
    }

    let ret = unsafe { bpf_arena_reserve_pages(arena_map(), addr.add((2 * PAGE_SIZE) as usize) as *mut c_void, 2) };
    if ret != 0 {
        return 2;
    }

    // Reserved and allocated pages should be interchangeable for
    // bpf_arena_free_pages(). Free a reserved and an allocated
    // page_ with a single call.
    unsafe { free(addr.add(PAGE_SIZE as usize), 2) };

    // The free call above should have succeeded, so this allocation should too.
    let page_ = unsafe { alloc(addr.add(PAGE_SIZE as usize), 2) };
    if page_.is_null() {
        return 3;
    }
    0
}

// HAND: alloc_pages -- translate the C below (see the file comment)
//   /*
//    * Check that arena's range_tree algorithm allocates pages sequentially
//    * on the first pass and then fills in all gaps on the second pass.
//    */
//   __noinline int alloc_pages(int page_cnt, int pages_atonce, bool first_pass,
//           int max_idx, int step)
//   {
//       __u8 __arena *pg;
//       int i, pg_idx;
//
//       for (i = 0; i < page_cnt; i++) {
//           pg = bpf_arena_alloc_pages(&arena, NULL, pages_atonce,
//                          NUMA_NO_NODE, 0);
//           if (!pg)
//               return step;
//           pg_idx = (unsigned long) (pg - base) / PAGE_SIZE;
//           if (first_pass) {
//               /* Pages must be allocated sequentially */
//               if (pg_idx != i)
//                   return step + 100;
//           } else {
//               /* Allocator must fill into gaps */
//               if (pg_idx >= max_idx || (pg_idx & 1))
//                   return step + 200;
//           }
//           *pg = pg_idx;
//           page[pg_idx] = pg;
//           cond_break;
//       }
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn alloc_pages(page_cnt: i32, pages_atonce: i32, first_pass: bool, max_idx: i32, step: i32) -> i32 {
    let mut i: i32 = 0;
    while i < page_cnt {
        let pg = unsafe { alloc(core::ptr::null_mut(), pages_atonce as u32) };
        if pg.is_null() {
            return step;
        }
        let pg_idx = ((pg as u64).wrapping_sub(unsafe { base } as u64) / PAGE_SIZE) as i32;
        if first_pass {
            // Pages must be allocated sequentially
            if pg_idx != i {
                return step + 100;
            }
        } else {
            // Allocator must fill into gaps
            if pg_idx >= max_idx || (pg_idx & 1) != 0 {
                return step + 200;
            }
        }
        unsafe {
            *cast_kern(pg) = pg_idx as u8;
            *(cast_kern(core::ptr::addr_of_mut!(page) as *mut u8) as *mut *mut u8).add(pg_idx as usize) = pg;
        }
        if !unsafe { can_loop() } {
            break; // cond_break
        }
        i += 1;
    }
    0
}

// HAND: big_alloc2 -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success __retval(0)
//   int big_alloc2(void *ctx)
//   {
//       __u8 __arena *pg;
//       int i, err;
//
//       base = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//       if (!base)
//           return 1;
//       bpf_arena_free_pages(&arena, (void __arena *)base, 1);
//
//       err = alloc_pages(PAGE_CNT, 1, true, PAGE_CNT, 2);
//       if (err)
//           return err;
//
//       /* Clear all even pages */
//       for (i = 0; i < PAGE_CNT; i += 2) {
//           pg = page[i];
//           if (*pg != i)
//               return 3;
//           bpf_arena_free_pages(&arena, (void __arena *)pg, 1);
//           page[i] = NULL;
//           cond_break;
//       }
//
//       /* Allocate into freed gaps */
//       err = alloc_pages(PAGE_CNT / 2, 1, false, PAGE_CNT, 4);
//       if (err)
//           return err;
//
//       /* Free pairs of pages */
//       for (i = 0; i < PAGE_CNT; i += 4) {
//           pg = page[i];
//           if (*pg != i)
//               return 5;
//           bpf_arena_free_pages(&arena, (void __arena *)pg, 2);
//           page[i] = NULL;
//           barrier();
//           page[i + 1] = NULL;
//           cond_break;
//       }
//
//       /* Allocate 2 pages at a time into freed gaps */
//       err = alloc_pages(PAGE_CNT / 4, 2, false, PAGE_CNT, 6);
//       if (err)
//           return err;
//
//       /* Check pages without freeing */
//       for (i = 0; i < PAGE_CNT; i += 2) {
//           pg = page[i];
//           if (*pg != i)
//               return 7;
//           cond_break;
//       }
//
//       pg = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
//
//       if (!pg)
//           return 8;
//       /*
//        * The first PAGE_CNT pages are occupied. The new page
//        * must be above.
//        */
//       if ((pg - base) / PAGE_SIZE < PAGE_CNT)
//           return 9;
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn big_alloc2(_ctx: *mut c_void) -> i32 {
    unsafe { base = alloc(core::ptr::null_mut(), 1) };
    if unsafe { base }.is_null() {
        return 1;
    }
    unsafe { free(base, 1) };

    let err = alloc_pages(PAGE_CNT, 1, true, PAGE_CNT, 2);
    if err != 0 {
        return err;
    }

    // Clear all even pages
    let mut i: i32 = 0;
    while i < PAGE_CNT {
        let pg = unsafe { *page_slot(i) };
        if unsafe { *cast_kern(pg) } as i32 != i {
            return 3;
        }
        unsafe {
            free(pg, 1);
            *page_slot(i) = core::ptr::null_mut();
        }
        if !unsafe { can_loop() } {
            break; // cond_break
        }
        i += 2;
    }

    // Allocate into freed gaps
    let err = alloc_pages(PAGE_CNT / 2, 1, false, PAGE_CNT, 4);
    if err != 0 {
        return err;
    }

    // Free pairs of pages
    let mut i: i32 = 0;
    while i < PAGE_CNT {
        let pg = unsafe { *page_slot(i) };
        if unsafe { *cast_kern(pg) } as i32 != i {
            return 5;
        }
        unsafe {
            free(pg, 2);
            *page_slot(i) = core::ptr::null_mut();
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst); // barrier()
            *page_slot(i + 1) = core::ptr::null_mut();
        }
        if !unsafe { can_loop() } {
            break; // cond_break
        }
        i += 4;
    }

    // Allocate 2 pages at a time into freed gaps
    let err = alloc_pages(PAGE_CNT / 4, 2, false, PAGE_CNT, 6);
    if err != 0 {
        return err;
    }

    // Check pages without freeing
    let mut i: i32 = 0;
    while i < PAGE_CNT {
        let pg = unsafe { *page_slot(i) };
        if unsafe { *cast_kern(pg) } as i32 != i {
            return 7;
        }
        if !unsafe { can_loop() } {
            break; // cond_break
        }
        i += 2;
    }

    let pg = unsafe { alloc(core::ptr::null_mut(), 1) };

    if pg.is_null() {
        return 8;
    }
    // The first PAGE_CNT pages are occupied. The new page
    // must be above.
    if (pg as u64).wrapping_sub(unsafe { base } as u64) / PAGE_SIZE < PAGE_CNT as u64 {
        return 9;
    }
    0
}

// HAND: big_alloc3 -- translate the C below (see the file comment)
//   /* Nonsleepable because it binds to a socket program. */
//   SEC("socket")
//   __success __retval(0)
//   int big_alloc3(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       char __arena *pages;
//       u64 i;
//       int err = 0;
//
//       /* Verify that a nonsleepable allocation larger than 1024 pages succeeds. */
//       pages = bpf_arena_alloc_pages(&arena, NULL, LARGE_PAGE_CNT, NUMA_NO_NODE, 0);
//       if (!pages)
//           return 1;
//
//       for (i = zero; i < LARGE_PAGE_CNT && can_loop; i++)
//           pages[i * PAGE_SIZE] = 123;
//
//       for (i = zero; i < LARGE_PAGE_CNT && can_loop; i++) {
//           if (pages[i * PAGE_SIZE] == 123)
//               continue;
//           err = 2;
//           break;
//       }
//
//       bpf_arena_free_pages(&arena, pages, LARGE_PAGE_CNT);
//       return err;
//   #endif
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn big_alloc3(_ctx: *mut c_void) -> i32 {
    let mut err: i32 = 0;

    // Verify that a nonsleepable allocation larger than 1024 pages succeeds.
    let pages = unsafe { alloc(core::ptr::null_mut(), LARGE_PAGE_CNT as u32) };
    if pages.is_null() {
        return 1;
    }

    let mut i: u64 = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(zero)) } as u64;
    while i < LARGE_PAGE_CNT && unsafe { can_loop() } {
        unsafe { *cast_kern(pages).add((i * PAGE_SIZE) as usize) = 123 };
        i += 1;
    }

    let mut i: u64 = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(zero)) } as u64;
    while i < LARGE_PAGE_CNT && unsafe { can_loop() } {
        if unsafe { *cast_kern(pages).add((i * PAGE_SIZE) as usize) } == 123 {
            i += 1;
            continue;
        }
        err = 2;
        break;
    }

    unsafe { free(pages, LARGE_PAGE_CNT as u32) };
    err
}

// HAND: big_alloc4 -- translate the C below (see the file comment)
//   /* SYSCALL programs are always sleepable. */
//   SEC("syscall")
//   __success __retval(0)
//   int big_alloc4(void *ctx)
//   {
//   #if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
//       char __arena *pages;
//       u64 i;
//       int err = 0;
//
//       /* Verify that a sleepable allocation larger than 1024 pages succeeds. */
//       pages = bpf_arena_alloc_pages(&arena, NULL, LARGE_PAGE_CNT, NUMA_NO_NODE, 0);
//       if (!pages)
//           return 1;
//
//       for (i = zero; i < LARGE_PAGE_CNT && can_loop; i++)
//           pages[i * PAGE_SIZE] = 123;
//
//       for (i = zero; i < LARGE_PAGE_CNT && can_loop; i++) {
//           if (pages[i * PAGE_SIZE] == 123)
//               continue;
//           err = 2;
//           break;
//       }
//
//       bpf_arena_free_pages(&arena, pages, LARGE_PAGE_CNT);
//       return err;
//   #endif
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn big_alloc4(_ctx: *mut c_void) -> i32 {
    let mut err: i32 = 0;

    // Verify that a sleepable allocation larger than 1024 pages succeeds.
    let pages = unsafe { alloc(core::ptr::null_mut(), LARGE_PAGE_CNT as u32) };
    if pages.is_null() {
        return 1;
    }

    let mut i: u64 = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(zero)) } as u64;
    while i < LARGE_PAGE_CNT && unsafe { can_loop() } {
        unsafe { *cast_kern(pages).add((i * PAGE_SIZE) as usize) = 123 };
        i += 1;
    }

    let mut i: u64 = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(zero)) } as u64;
    while i < LARGE_PAGE_CNT && unsafe { can_loop() } {
        if unsafe { *cast_kern(pages).add((i * PAGE_SIZE) as usize) } == 123 {
            i += 1;
            continue;
        }
        err = 2;
        break;
    }

    unsafe { free(pages, LARGE_PAGE_CNT as u32) };
    err
}
