// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/arena_atomics.c
// (bpf-rs-core idiom).
//
// Unlike arena_list.c/dmabuf_iter.c (see [[arena-programs-blocked-by-addrspace-and-kfunc-proto]]),
// this harness's reference object (SELFTESTS_OUTPUT/arena_atomics.bpf.o,
// built with -DENABLE_ATOMICS_TESTS for __TARGET_ARCH_x86) has
// skip_all_tests == skip_lacq_srel_tests == 0: ENABLE_ATOMICS_TESTS and
// __BPF_FEATURE_ADDR_SPACE_CAST are both live in this environment, so the
// real atomics-on-arena-globals logic is exercised, not the C source's
// skip fallback. That logic is reachable from Rust after all:
//
// - `uaf`'s real body is gated `#if ... && !defined(__TARGET_ARCH_arm64) &&
//   !defined(__TARGET_ARCH_x86)` in the C source itself, so on this target
//   (x86) it is *already* excluded upstream — no bpf_arena_alloc_pages/
//   bpf_arena_free_pages kfunc calls are needed here at all, sidestepping
//   the kfunc void-proto blocker entirely for this file.
// - The remaining blocker was emitting `addrspacecast` (AS1 arena-global
//   address -> AS0 kernel-usable address) from Rust source, which has no
//   language-level construct for it. But libbpf's part of the mechanism
//   (recognizing DATASEC ".addr_space.1" members and relocating their
//   ld_imm64 loads against the object's single BPF_MAP_TYPE_ARENA map) is
//   orthogonal to the compiler; only the actual `addr_space_cast`
//   instruction bytes are needed at the call site, and those are directly
//   encodable via inline asm using the exact register-name-sniffing trick
//   upstream's own `bpf_addr_space_cast()` macro (bpf_experimental.h) uses
//   for compilers lacking the feature: an opcode/off/imm byte sequence with
//   `.ifc {0}, rN` / `.byte` picking the dst|src register-pair byte for
//   whichever physical register the compiler assigned the operand to. See
//   `cast_kern` below — confirmed byte-for-byte against the reference
//   object's disassembly (`bf 11 01 00 01 00 00 00`: opcode 0xBF, regs
//   0x11 i.e. same reg in/out, off=1=BPF_ADDR_SPACE_CAST, imm=1 i.e.
//   dst_as=0/src_as=1, matching upstream's `cast_kern(ptr) =
//   bpf_addr_space_cast(ptr, 0, 1)`).
//
// `load_acquire`/`store_release` use the same `cast_kern` plus ordinary
// `core::sync::atomic` load/store (SeqCst) rather than hand-encoding the
// dedicated BPF_LOAD_ACQ/BPF_STORE_REL opcodes the C source reaches for via
// raw asm: this test only asserts on final values in a single-threaded,
// non-concurrent run (`bpf_prog_test_run_opts`), so plain atomic load/store
// through the arena-cast pointer is observationally identical for the
// oracle, and avoids a second, riskier hand-rolled instruction encoding
// (dst_reg/src_reg both compiler-chosen, needing a two-register nibble
// combination instead of `cast_kern`'s single in-place register).
//
// All other ops (add/sub/and/or/xor/cmpxchg/xchg) go through
// `core::sync::atomic::Atomic*` on the `cast_kern`-ed pointer, the same
// idiom this crate already uses for plain (non-arena) globals in
// `helpers::sync_fetch_and_add` — confirmed by the reference disassembly
// using ordinary `atomic_fetch_add`/`lock ... +=`/`cmpxchg_64`/exchange
// instructions after the cast, no different from atomics on any other
// pointer once the register is verifier-typed PTR_TO_ARENA.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

bpf_map! {
    arena {
        r#type: *const [i32; 33],       // BPF_MAP_TYPE_ARENA
        map_flags: *const [i32; 1024],  // BPF_F_MMAPABLE
        max_entries: *const [i32; 10],  // number of pages
    }
}

// .data (explicit section, matching the C source's
// `__attribute((__section__(".data")))` override that keeps these in
// .data even though their value is zero/false in this environment).
#[link_section = ".data"]
#[no_mangle]
static mut skip_all_tests: bool = false;
#[link_section = ".data"]
#[no_mangle]
static mut skip_lacq_srel_tests: bool = false;

// .bss
#[no_mangle]
static mut pid: u32 = 0;

/// `bpf_addr_space_cast(ptr, 0, 1)` a.k.a. upstream's `cast_kern`: converts
/// the raw ld_imm64 address of a DATASEC ".addr_space.1" (arena) global
/// (AS1) into the kernel-usable pointer (AS0) the verifier/JIT special-case
/// as PTR_TO_ARENA. In-place single-register encoding so only one physical
/// register's name needs sniffing via `.ifc`, same trick as
/// `helpers::sink`'s `"{0} = {0}"` barrier.
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

#[link_section = ".addr_space.1"]
#[no_mangle]
static mut add64_value: u64 = 1;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut add64_result: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut add32_value: u32 = 1;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut add32_result: u32 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut add_stack_value_copy: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut add_stack_result: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut add_noreturn_value: u64 = 1;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn add(_ctx: *const c_void) -> i32 {
    unsafe {
        if (bpf_get_current_pid_tgid() >> 32) != pid as u64 {
            return 0;
        }

        let mut add_stack_value: u64 = 1;

        let r = (*(cast_kern(core::ptr::addr_of_mut!(add64_value)) as *mut AtomicU64))
            .fetch_add(2, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(add64_result)) = r;

        let r = (*(cast_kern(core::ptr::addr_of_mut!(add32_value)) as *mut AtomicU32))
            .fetch_add(2, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(add32_result)) = r;

        let r = (*(core::ptr::addr_of_mut!(add_stack_value) as *mut AtomicU64))
            .fetch_add(2, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(add_stack_result)) = r;
        *cast_kern(core::ptr::addr_of_mut!(add_stack_value_copy)) = add_stack_value;

        (*(cast_kern(core::ptr::addr_of_mut!(add_noreturn_value)) as *mut AtomicU64))
            .fetch_add(2, Ordering::SeqCst);
    }
    0
}

#[link_section = ".addr_space.1"]
#[no_mangle]
static mut sub64_value: i64 = 1;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut sub64_result: i64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut sub32_value: i32 = 1;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut sub32_result: i32 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut sub_stack_value_copy: i64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut sub_stack_result: i64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut sub_noreturn_value: i64 = 1;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn sub(_ctx: *const c_void) -> i32 {
    unsafe {
        if (bpf_get_current_pid_tgid() >> 32) != pid as u64 {
            return 0;
        }

        let mut sub_stack_value: i64 = 1;

        let r = (*(cast_kern(core::ptr::addr_of_mut!(sub64_value)) as *mut AtomicI64))
            .fetch_sub(2, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(sub64_result)) = r;

        let r = (*(cast_kern(core::ptr::addr_of_mut!(sub32_value)) as *mut AtomicI32))
            .fetch_sub(2, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(sub32_result)) = r;

        let r = (*(core::ptr::addr_of_mut!(sub_stack_value) as *mut AtomicI64))
            .fetch_sub(2, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(sub_stack_result)) = r;
        *cast_kern(core::ptr::addr_of_mut!(sub_stack_value_copy)) = sub_stack_value;

        (*(cast_kern(core::ptr::addr_of_mut!(sub_noreturn_value)) as *mut AtomicI64))
            .fetch_sub(2, Ordering::SeqCst);
    }
    0
}

// A relaxed fetch whose result is discarded is what selects the
// non-fetching insn, so each operation keeps a *_noreturn_value of each
// width to cover that lowering as well.
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut and64_value: u64 = 0x110u64 << 32;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut and64_result: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut and64_noreturn_value: u64 = 0x110u64 << 32;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut and32_value: u32 = 0x110;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut and32_result: u32 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut and32_noreturn_value: u32 = 0x110;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn and(_ctx: *const c_void) -> i32 {
    unsafe {
        if (bpf_get_current_pid_tgid() >> 32) != pid as u64 {
            return 0;
        }

        let r = (*(cast_kern(core::ptr::addr_of_mut!(and64_value)) as *mut AtomicU64))
            .fetch_and(0x011u64 << 32, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(and64_result)) = r;
        let r = (*(cast_kern(core::ptr::addr_of_mut!(and32_value)) as *mut AtomicU32))
            .fetch_and(0x011, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(and32_result)) = r;
        // __sync_fetch_and_*() is seq_cst; a relaxed 32-bit atomicrmw whose
        // result is used made LLVM 22 emit the non-fetching insn and store
        // the operand. A discarded relaxed fetch is what selects the
        // non-fetching insn, as the C's __c11_atomic_fetch_*() does.
        (*(cast_kern(core::ptr::addr_of_mut!(and64_noreturn_value)) as *mut AtomicU64))
            .fetch_and(0x011u64 << 32, Ordering::Relaxed);
        (*(cast_kern(core::ptr::addr_of_mut!(and32_noreturn_value)) as *mut AtomicU32))
            .fetch_and(0x011, Ordering::Relaxed);
    }
    0
}

// u32s first: .addr_space.1 must not have holes, as in the C.
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut or32_value: u32 = 0x110;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut or32_result: u32 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut or32_noreturn_value: u32 = 0x110;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut or64_value: u64 = 0x110u64 << 32;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut or64_result: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut or64_noreturn_value: u64 = 0x110u64 << 32;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn or(_ctx: *const c_void) -> i32 {
    unsafe {
        if (bpf_get_current_pid_tgid() >> 32) != pid as u64 {
            return 0;
        }

        let r = (*(cast_kern(core::ptr::addr_of_mut!(or64_value)) as *mut AtomicU64))
            .fetch_or(0x011u64 << 32, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(or64_result)) = r;
        let r = (*(cast_kern(core::ptr::addr_of_mut!(or32_value)) as *mut AtomicU32))
            .fetch_or(0x011, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(or32_result)) = r;
        // __sync_fetch_and_*() is seq_cst; a relaxed 32-bit atomicrmw whose
        // result is used made LLVM 22 emit the non-fetching insn and store
        // the operand. A discarded relaxed fetch is what selects the
        // non-fetching insn, as the C's __c11_atomic_fetch_*() does.
        (*(cast_kern(core::ptr::addr_of_mut!(or64_noreturn_value)) as *mut AtomicU64))
            .fetch_or(0x011u64 << 32, Ordering::Relaxed);
        (*(cast_kern(core::ptr::addr_of_mut!(or32_noreturn_value)) as *mut AtomicU32))
            .fetch_or(0x011, Ordering::Relaxed);
    }
    0
}

#[link_section = ".addr_space.1"]
#[no_mangle]
static mut xor64_value: u64 = 0x110u64 << 32;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut xor64_result: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut xor64_noreturn_value: u64 = 0x110u64 << 32;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut xor32_value: u32 = 0x110;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut xor32_result: u32 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut xor32_noreturn_value: u32 = 0x110;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn xor(_ctx: *const c_void) -> i32 {
    unsafe {
        if (bpf_get_current_pid_tgid() >> 32) != pid as u64 {
            return 0;
        }

        let r = (*(cast_kern(core::ptr::addr_of_mut!(xor64_value)) as *mut AtomicU64))
            .fetch_xor(0x011u64 << 32, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(xor64_result)) = r;
        let r = (*(cast_kern(core::ptr::addr_of_mut!(xor32_value)) as *mut AtomicU32))
            .fetch_xor(0x011, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(xor32_result)) = r;
        // __sync_fetch_and_*() is seq_cst; a relaxed 32-bit atomicrmw whose
        // result is used made LLVM 22 emit the non-fetching insn and store
        // the operand. A discarded relaxed fetch is what selects the
        // non-fetching insn, as the C's __c11_atomic_fetch_*() does.
        (*(cast_kern(core::ptr::addr_of_mut!(xor64_noreturn_value)) as *mut AtomicU64))
            .fetch_xor(0x011u64 << 32, Ordering::Relaxed);
        (*(cast_kern(core::ptr::addr_of_mut!(xor32_noreturn_value)) as *mut AtomicU32))
            .fetch_xor(0x011, Ordering::Relaxed);
    }
    0
}

#[link_section = ".addr_space.1"]
#[no_mangle]
static mut cmpxchg32_value: u32 = 1;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut cmpxchg32_result_fail: u32 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut cmpxchg32_result_succeed: u32 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut cmpxchg64_value: u64 = 1;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut cmpxchg64_result_fail: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut cmpxchg64_result_succeed: u64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn cmpxchg(_ctx: *const c_void) -> i32 {
    unsafe {
        if (bpf_get_current_pid_tgid() >> 32) != pid as u64 {
            return 0;
        }

        let p64 = cast_kern(core::ptr::addr_of_mut!(cmpxchg64_value)) as *mut AtomicU64;
        let r = (*p64)
            .compare_exchange(0, 3, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap_or_else(|v| v);
        *cast_kern(core::ptr::addr_of_mut!(cmpxchg64_result_fail)) = r;
        let r = (*p64)
            .compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap_or_else(|v| v);
        *cast_kern(core::ptr::addr_of_mut!(cmpxchg64_result_succeed)) = r;

        let p32 = cast_kern(core::ptr::addr_of_mut!(cmpxchg32_value)) as *mut AtomicU32;
        let r = (*p32)
            .compare_exchange(0, 3, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap_or_else(|v| v);
        *cast_kern(core::ptr::addr_of_mut!(cmpxchg32_result_fail)) = r;
        let r = (*p32)
            .compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap_or_else(|v| v);
        *cast_kern(core::ptr::addr_of_mut!(cmpxchg32_result_succeed)) = r;
    }
    0
}

#[link_section = ".addr_space.1"]
#[no_mangle]
static mut xchg64_value: u64 = 1;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut xchg64_result: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut xchg32_value: u32 = 1;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut xchg32_result: u32 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn xchg(_ctx: *const c_void) -> i32 {
    unsafe {
        if (bpf_get_current_pid_tgid() >> 32) != pid as u64 {
            return 0;
        }

        let r = (*(cast_kern(core::ptr::addr_of_mut!(xchg64_value)) as *mut AtomicU64))
            .swap(2, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(xchg64_result)) = r;

        let r = (*(cast_kern(core::ptr::addr_of_mut!(xchg32_value)) as *mut AtomicU32))
            .swap(2, Ordering::SeqCst);
        *cast_kern(core::ptr::addr_of_mut!(xchg32_result)) = r;
    }
    0
}

extern "C" {
    fn bpf_arena_alloc_pages(map: *const c_void, addr: *mut c_void, count: u32, node: i32, flags: u64) -> *mut u64;
    fn bpf_arena_free_pages(map: *const c_void, addr: *mut c_void, count: u32);
}
const NUMA_NO_NODE: i32 = -1;

#[link_section = ".addr_space.1"]
#[no_mangle]
static mut fetch_src_r0_value: u64 = 0x11000000110;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut fetch_src_r0_result: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut fetch_dst_r0_value: u64 = 0x11000000110;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut fetch_dst_r0_result: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut fetch_dst_r0_readback: u64 = 0;

// BPF_ATOMIC_OP(BPF_DW, BPF_OR | BPF_FETCH, dst, src, 0): opcode 0xdb
// (BPF_STX | BPF_DW | BPF_ATOMIC), regs byte src << 4 | dst, off 0,
// imm 0x41 (BPF_OR | BPF_FETCH). The old value lands in src.
macro_rules! fetch_or_dw {
    (r0, r1) => { ".byte 0xdb, 0x10, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00" }; // dst r0, src r1
    (r1, r0) => { ".byte 0xdb, 0x01, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00" }; // dst r1, src r0
}

// A fetching OR with the operand in r0, and one with the arena pointer in r0.
// The x86 JIT needs RAX for its CMPXCHG loop and substitutes BPF_REG_AX for
// whichever of the two is r0, so both have to keep working. Hand-written
// because the compiler picks its own registers and will not reliably emit
// either. The arena addresses are cast to kernel pointers outside the asm
// (the C spells the addr_space_cast inside it); the atomic and its registers
// are what the test is about.
#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn fetch_r0(_ctx: *const c_void) -> i32 {
    unsafe {
        if (bpf_get_current_pid_tgid() >> 32) != pid as u64 {
            return 0;
        }

        let value = cast_kern(core::ptr::addr_of_mut!(fetch_src_r0_value));
        let result = cast_kern(core::ptr::addr_of_mut!(fetch_src_r0_result));
        core::arch::asm!(
            "r0 = 0x1100000011 ll",
            fetch_or_dw!(r1, r0),
            "*(u64 *)({result} + 0) = r0",
            in("r1") value,
            out("r0") _,
            result = in(reg) result,
            options(nostack, preserves_flags),
        );

        let value = cast_kern(core::ptr::addr_of_mut!(fetch_dst_r0_value));
        let result = cast_kern(core::ptr::addr_of_mut!(fetch_dst_r0_result));
        let readback = cast_kern(core::ptr::addr_of_mut!(fetch_dst_r0_readback));
        core::arch::asm!(
            "r1 = 0x1100000011 ll",
            fetch_or_dw!(r0, r1),
            "*(u64 *)({result} + 0) = r1",
            // r0 is only read by the atomic, so it must still be the pointer.
            "r3 = *(u64 *)(r0 + 0)",
            "*(u64 *)({readback} + 0) = r3",
            in("r0") value,
            out("r1") _,
            out("r3") _,
            result = in(reg) result,
            readback = in(reg) readback,
            options(nostack, preserves_flags),
        );
    }
    0
}

#[link_section = ".addr_space.1"]
#[no_mangle]
static mut uaf_sink: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut uaf_recovery_fails: u64 = 0;
// Register state after the r0 forms below fault, checked by the test
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut uaf_r1_after_dst_r0: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut uaf_r0_before_dst_r0: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut uaf_r0_after_dst_r0: u64 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut uaf_r0_after_src_r0: u64 = 0;
// What reading the faulted address again gives, see the end of uaf()
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut uaf_reread: u64 = 0;

// volatile __u64 uaf_recovery_fails: every decrement is its own store.
#[inline(always)]
unsafe fn uaf_fail_dec() {
    let p = cast_kern(core::ptr::addr_of_mut!(uaf_recovery_fails));
    core::ptr::write_volatile(p, core::ptr::read_volatile(p).wrapping_sub(1));
}

#[inline(always)]
unsafe fn uaf_sink_add(v: u64) {
    let p = cast_kern(core::ptr::addr_of_mut!(uaf_sink));
    *p = (*p).wrapping_add(v);
}

// Every atomic below touches a freed arena page; the JIT's exception table
// recovers each fault and the program keeps going, which is what the
// uaf_recovery_fails countdown records. The C compiles this body on x86 since
// __BPF_FEATURE_ADDR_SPACE_CAST (LLVM 19) and 645f5fcf.
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn uaf(_ctx: *const c_void) -> i32 {
    unsafe {
        if (bpf_get_current_pid_tgid() >> 32) != pid as u64 {
            return 0;
        }

        let page = bpf_arena_alloc_pages(
            &arena as *const _ as *const c_void,
            core::ptr::null_mut(),
            1,
            NUMA_NO_NODE,
            0,
        );
        bpf_arena_free_pages(&arena as *const _ as *const c_void, page.cast(), 1);
        *cast_kern(core::ptr::addr_of_mut!(uaf_recovery_fails)) = 26;
        *cast_kern(core::ptr::addr_of_mut!(uaf_r1_after_dst_r0)) = 1;
        *cast_kern(core::ptr::addr_of_mut!(uaf_r0_after_dst_r0)) = 1;
        *cast_kern(core::ptr::addr_of_mut!(uaf_r0_after_src_r0)) = 1;
        *cast_kern(core::ptr::addr_of_mut!(uaf_reread)) = 1;

        let page32 = cast_kern(page as *mut u32) as *mut AtomicU32;
        uaf_sink_add((*page32).fetch_add(1, Ordering::SeqCst) as u64);
        uaf_fail_dec();
        (*page32).fetch_add(1, Ordering::SeqCst);
        uaf_fail_dec();
        uaf_sink_add((*page32).fetch_sub(1, Ordering::SeqCst) as u64);
        uaf_fail_dec();
        (*page32).fetch_sub(1, Ordering::SeqCst);
        uaf_fail_dec();
        uaf_sink_add((*page32).fetch_and(1, Ordering::SeqCst) as u64);
        uaf_fail_dec();
        (*page32).fetch_and(1, Ordering::SeqCst);
        uaf_fail_dec();
        uaf_sink_add((*page32).fetch_or(1, Ordering::SeqCst) as u64);
        uaf_fail_dec();
        (*page32).fetch_or(1, Ordering::SeqCst);
        uaf_fail_dec();
        uaf_sink_add((*page32).fetch_xor(1, Ordering::SeqCst) as u64);
        uaf_fail_dec();
        (*page32).fetch_xor(1, Ordering::SeqCst);
        uaf_fail_dec();
        uaf_sink_add(
            (*page32)
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .unwrap_or_else(|v| v) as u64,
        );
        uaf_fail_dec();
        uaf_sink_add((*page32).swap(1, Ordering::SeqCst) as u64);
        uaf_fail_dec();

        let page64 = cast_kern(page) as *mut AtomicU64;
        uaf_sink_add((*page64).fetch_add(1, Ordering::SeqCst));
        uaf_fail_dec();
        (*page64).fetch_add(1, Ordering::SeqCst);
        uaf_fail_dec();
        uaf_sink_add((*page64).fetch_sub(1, Ordering::SeqCst));
        uaf_fail_dec();
        (*page64).fetch_sub(1, Ordering::SeqCst);
        uaf_fail_dec();
        uaf_sink_add((*page64).fetch_and(1, Ordering::SeqCst));
        uaf_fail_dec();
        (*page64).fetch_and(1, Ordering::SeqCst);
        uaf_fail_dec();
        uaf_sink_add((*page64).fetch_or(1, Ordering::SeqCst));
        uaf_fail_dec();
        (*page64).fetch_or(1, Ordering::SeqCst);
        uaf_fail_dec();
        uaf_sink_add((*page64).fetch_xor(1, Ordering::SeqCst));
        uaf_fail_dec();
        (*page64).fetch_xor(1, Ordering::SeqCst);
        uaf_fail_dec();
        uaf_sink_add(
            (*page64)
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .unwrap_or_else(|v| v),
        );
        uaf_fail_dec();
        uaf_sink_add((*page64).swap(1, Ordering::SeqCst));
        uaf_fail_dec();

        // The x86 JIT needs RAX for the CMPXCHG loop it lowers a fetching
        // AND/OR/XOR into, and substitutes BPF_REG_AX for r0 when r0 is
        // either operand. Only then does the fault fixup have to name that
        // register, so spell both forms out: the compiler picks its own and
        // never produces them.
        //
        // The freed page is the first of the arena, whose 32-bit address is
        // 0, which would make "the address register was left alone" an empty
        // check. Use the page after it, which is unmapped as well.
        let next = cast_kern((page as *mut u8).add(4096));
        let before = cast_kern(core::ptr::addr_of_mut!(uaf_r0_before_dst_r0));
        let after_r0 = cast_kern(core::ptr::addr_of_mut!(uaf_r0_after_dst_r0));
        let after_r1 = cast_kern(core::ptr::addr_of_mut!(uaf_r1_after_dst_r0));
        core::arch::asm!(
            "r1 = 1",
            "*(u64 *)({before} + 0) = r0",
            fetch_or_dw!(r0, r1),
            "*(u64 *)({after_r0} + 0) = r0",
            "*(u64 *)({after_r1} + 0) = r1",
            in("r0") next,
            out("r1") _,
            before = in(reg) before,
            after_r0 = in(reg) after_r0,
            after_r1 = in(reg) after_r1,
            options(nostack, preserves_flags),
        );
        uaf_fail_dec();

        let after_src = cast_kern(core::ptr::addr_of_mut!(uaf_r0_after_src_r0));
        core::arch::asm!(
            "r0 = 1",
            fetch_or_dw!(r1, r0),
            "*(u64 *)({after_src} + 0) = r0",
            in("r1") next,
            out("r0") _,
            after_src = in(reg) after_src,
            options(nostack, preserves_flags),
        );
        uaf_fail_dec();

        // If a fault were recovered by the arena mapping its zeroed scratch
        // page rather than by the JIT's exception table entry, the access
        // above would have succeeded and written there. The page has to
        // still be unmapped, so that the read faults and gives 0.
        let v = core::ptr::read_volatile(next as *const u64);
        *cast_kern(core::ptr::addr_of_mut!(uaf_reread)) = v;
    }
    0
}

#[link_section = ".addr_space.1"]
#[no_mangle]
static mut load_acquire8_value: u8 = 0x12;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut load_acquire16_value: u16 = 0x1234;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut load_acquire32_value: u32 = 0x12345678;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut load_acquire64_value: u64 = 0x1234567890abcdef;

#[link_section = ".addr_space.1"]
#[no_mangle]
static mut load_acquire8_result: u8 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut load_acquire16_result: u16 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut load_acquire32_result: u32 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut load_acquire64_result: u64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn load_acquire(_ctx: *const c_void) -> i32 {
    unsafe {
        let v8 = (*(cast_kern(core::ptr::addr_of_mut!(load_acquire8_value)) as *mut AtomicU8))
            .load(Ordering::Relaxed);
        (*(cast_kern(core::ptr::addr_of_mut!(load_acquire8_result)) as *mut AtomicU8))
            .store(v8, Ordering::Relaxed);

        let v16 = (*(cast_kern(core::ptr::addr_of_mut!(load_acquire16_value)) as *mut AtomicU16))
            .load(Ordering::Relaxed);
        (*(cast_kern(core::ptr::addr_of_mut!(load_acquire16_result)) as *mut AtomicU16))
            .store(v16, Ordering::Relaxed);

        let v32 = (*(cast_kern(core::ptr::addr_of_mut!(load_acquire32_value)) as *mut AtomicU32))
            .load(Ordering::Relaxed);
        (*(cast_kern(core::ptr::addr_of_mut!(load_acquire32_result)) as *mut AtomicU32))
            .store(v32, Ordering::Relaxed);

        let v64 = (*(cast_kern(core::ptr::addr_of_mut!(load_acquire64_value)) as *mut AtomicU64))
            .load(Ordering::Relaxed);
        (*(cast_kern(core::ptr::addr_of_mut!(load_acquire64_result)) as *mut AtomicU64))
            .store(v64, Ordering::Relaxed);
    }
    0
}

#[link_section = ".addr_space.1"]
#[no_mangle]
static mut store_release8_result: u8 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut store_release16_result: u16 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut store_release32_result: u32 = 0;
#[link_section = ".addr_space.1"]
#[no_mangle]
static mut store_release64_result: u64 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn store_release(_ctx: *const c_void) -> i32 {
    unsafe {
        (*(cast_kern(core::ptr::addr_of_mut!(store_release8_result)) as *mut AtomicU8))
            .store(0x12, Ordering::Relaxed);
        (*(cast_kern(core::ptr::addr_of_mut!(store_release16_result)) as *mut AtomicU16))
            .store(0x1234, Ordering::Relaxed);
        (*(cast_kern(core::ptr::addr_of_mut!(store_release32_result)) as *mut AtomicU32))
            .store(0x12345678, Ordering::Relaxed);
        (*(cast_kern(core::ptr::addr_of_mut!(store_release64_result)) as *mut AtomicU64))
            .store(0x1234567890abcdef, Ordering::Relaxed);
    }
    0
}

bpf_object!("GPL");
