// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/jit_insns_arena.c
// (bpf-rs-core idiom). The two programs are the arena cases of
// prog_tests/jit_insns.c (RUN_TESTS(jit_insns_arena)): each allocates one
// arena page and runs its instruction sequence as inline assembly, with the
// C's register choices and clobbers, and returns whether the accumulated
// XOR of the results and the expected values is non-zero. The "i" operands
// are the little-endian constants of the C (this build is little-endian).

use core::ffi::c_void;

use bpf_rs_core::{bpf_map, bpf_object, test_tags};

bpf_map! {
    arena {
        r#type: *const [i32; 33],       // BPF_MAP_TYPE_ARENA
        map_flags: *const [i32; 1024],  // BPF_F_MMAPABLE
        max_entries: *const [i32; 1],
    }
}

const NUMA_NO_NODE: i32 = -1;

extern "C" {
    fn bpf_arena_alloc_pages(
        map: *mut c_void,
        addr: *mut c_void,
        page_cnt: u32,
        node_id: i32,
        flags: u64,
    ) -> *mut c_void;
}

test_tags! {
    arena_zero_off: __description("arena access with zero offset"), __success, __retval(0);
    cast_to_user: __description("cast to a user address"), __success, __retval(0);
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arena_zero_off(_ctx: *mut c_void) -> i32 {
    let page = unsafe {
        bpf_arena_alloc_pages(
            &arena as *const arena as *mut c_void,
            core::ptr::null_mut(),
            1,
            NUMA_NO_NODE,
            0,
        )
    };
    if page.is_null() {
        return 1;
    }
    let mut res: u64 = page as u64 as u32 as u64;
    /* Accesses through two base registers */
    unsafe {
        core::arch::asm!(
            "r7 = {res}",
            "r7 = addr_space_cast(r7, 0x0, 0x1)",
            "r1 = r7",
            "r8 = 0x1122334455667788 ll",
            "*(u64 *)(r7 + 0) = r8",
            "r9 = *(u64 *)(r7 + 0)",
            "r9 ^= r8",
            "*(u64 *)(r1 + 0) = r8",
            "r2 = *(u64 *)(r1 + 0)",
            "r2 ^= r8",
            "r9 |= r2",
            "r3 = *(u8 *)(r1 + 0)",
            "r3 ^= 0x88",
            "r9 |= r3",
            "r4 = *(u16 *)(r1 + 0)",
            "r4 ^= 0x7788",
            "r9 |= r4",
            "r5 = *(u32 *)(r1 + 0)",
            "r5 ^= 0x55667788",
            "r9 |= r5",
            "*(u32 *)(r1 + 0) = 0x1234",
            "lock *(u64 *)(r7 + 0) += r8",
            "r2 = *(u64 *)(r1 + 0)",
            "r8 = 0x22446688556689bc ll",
            "r2 ^= r8",
            "r9 |= r2",
            "{res} = r9",
            res = inout(reg) res,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r4") _,
            out("r5") _,
            out("r7") _,
            out("r8") _,
            out("r9") _,
            options(nostack, preserves_flags),
        );
    }
    (res != 0) as i32
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn cast_to_user(_ctx: *mut c_void) -> i32 {
    let page = unsafe {
        bpf_arena_alloc_pages(
            &arena as *const arena as *mut c_void,
            core::ptr::null_mut(),
            1,
            NUMA_NO_NODE,
            0,
        )
    };
    if page.is_null() {
        return 1;
    }
    let res: u64;
    /* The user address comes back from the kernel one, NULL stays NULL */
    unsafe {
        core::arch::asm!(
            "r7 = {page}",
            "r1 = addr_space_cast(r7, 0x0, 0x1)",
            "r1 = addr_space_cast(r1, 0x1, 0x0)",
            "r9 = r1",
            "r9 ^= r7",
            "r2 = 0",
            "r2 = addr_space_cast(r2, 0x1, 0x0)",
            "r9 |= r2",
            "{res} = r9",
            page = in(reg) page,
            res = out(reg) res,
            out("r1") _,
            out("r2") _,
            out("r7") _,
            out("r9") _,
            options(nostack, preserves_flags),
        );
    }
    (res != 0) as i32
}

bpf_object!("GPL");
