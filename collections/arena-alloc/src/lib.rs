#![no_std]
#![feature(asm_experimental_arch)]

//! BPF-arena-backed `GlobalAlloc` over libarena's buddy allocator.
//!
//! libarena (vendored under collections/vendor/libarena, linked in at the
//! LLVM-bitcode level) provides `arena_malloc_internal(size) -> u64` and
//! (via glue/arena_glue.bpf.c) `arena_free_u64(u64)`. Those u64 values are
//! arena addresses in their user-space form (map_extra base + offset). The
//! allocator casts each fresh allocation to the kernel view once with the
//! `addr_space_cast` instruction — hand-encoded inline asm, same idiom as
//! progs/arena_atomics.rs, byte-for-byte what clang emits for
//! `bpf_addr_space_cast()` — so Rust collections only ever hold and deref
//! plain kernel-view pointers. `dealloc` casts back before freeing.
//!
//! Alignment: buddy blocks are power-of-two sized and aligned, so
//! allocating max(size, align) guarantees the requested alignment.

use core::alloc::{GlobalAlloc, Layout};

extern "C" {
    fn arena_malloc_internal(size: usize) -> u64;
    fn arena_free_u64(ptr: u64);
}

/// addr_space_cast dst_as=0 src_as=1: arena (user) address -> kernel view.
#[inline(always)]
pub fn cast_kern(addr: u64) -> u64 {
    let mut a = addr;
    unsafe {
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
            inout(reg) a,
            options(nostack, preserves_flags),
        );
    }
    a
}

/// addr_space_cast dst_as=1 src_as=0: kernel view -> arena (user) address.
#[inline(always)]
pub fn cast_user(addr: u64) -> u64 {
    let mut a = addr;
    unsafe {
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
            ".long 65536", // imm: dst_as=1 in the upper 16 bits
            inout(reg) a,
            options(nostack, preserves_flags),
        );
    }
    a
}

pub struct ArenaAlloc;

unsafe impl GlobalAlloc for ArenaAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let sz = layout.size().max(layout.align()).max(1);
        let ua = arena_malloc_internal(sz);
        if ua == 0 {
            return core::ptr::null_mut();
        }
        cast_kern(ua) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        arena_free_u64(cast_user(ptr as u64));
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[alloc_error_handler]
fn oom(_: Layout) -> ! {
    loop {}
}
