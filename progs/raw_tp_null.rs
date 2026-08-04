#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/raw_tp_null.c,
// bpf-rs-core idiom.
//
// The C source's inline asm ("%[i] += 1; if %[ctx] != 0 goto +1; %[i] += 2;")
// forces a real, unoptimizable branch on the tp_btf raw-tracepoint pointer
// argument (which the verifier marks PTR_MAYBE_NULL for kernel-module
// tracepoints), so the test can observe whether the branch really executes
// at runtime rather than being folded by the compiler. Rust has no
// equivalent volatile-asm-with-named-register-operand construct that
// assembles to plain BPF mnemonics, so the three instructions are
// hand-encoded as raw `struct bpf_insn` bytes via `asm!`, using the same
// operand-register-sniffing trick (`.ifc {x}, rN` / `.byte`) this repo's
// arena_atomics.rs/arena_htab_asm.rs already validated for single
// hand-encoded instructions -- scaled up to three chained instructions
// (ALU32 add-imm, JMP32-style JNE-imm with offset=+1, ALU32 add-imm) so the
// middle branch's relative offset (skip exactly the trailing `i += 2`) is
// baked in at authorship time, matching the C original byte for byte:
// `i` is a plain 32-bit int global loaded into a register before the asm
// (mirroring the "+r" read-modify-write constraint) and stored back after.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_task_btf;
use bpf_rs_core::progs::fentry_arg;
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
}

#[no_mangle]
static mut tid: i32 = 0;
#[no_mangle]
static mut i: i32 = 0;

/// `i += 1; if (ctx != 0) goto +1; i += 2;` as three hand-encoded
/// `struct bpf_insn`s (8 bytes each: opcode, dst_reg|src_reg<<4, offset,
/// imm). Both instructions touching `i` use ALU32 ADD|K (opcode 0x04,
/// src_reg=0 since the source is an immediate, so the reg byte is just the
/// dst register number); the middle instruction is JMP32 JNE|K on `ctx`
/// (opcode 0x55) with offset=1 (skip the next instruction) and imm=0.
#[inline(always)]
unsafe fn null_gated_incr(i_val: i32, ctx_ptr: u64) -> i32 {
    let mut i_reg = i_val;
    core::arch::asm!(
        ".byte 0x04",
        ".ifc {i}, r0", ".byte 0x00", ".endif",
        ".ifc {i}, r1", ".byte 0x01", ".endif",
        ".ifc {i}, r2", ".byte 0x02", ".endif",
        ".ifc {i}, r3", ".byte 0x03", ".endif",
        ".ifc {i}, r4", ".byte 0x04", ".endif",
        ".ifc {i}, r5", ".byte 0x05", ".endif",
        ".ifc {i}, r6", ".byte 0x06", ".endif",
        ".ifc {i}, r7", ".byte 0x07", ".endif",
        ".ifc {i}, r8", ".byte 0x08", ".endif",
        ".ifc {i}, r9", ".byte 0x09", ".endif",
        ".short 0",
        ".long 1",
        ".byte 0x55",
        ".ifc {ctx}, r0", ".byte 0x00", ".endif",
        ".ifc {ctx}, r1", ".byte 0x01", ".endif",
        ".ifc {ctx}, r2", ".byte 0x02", ".endif",
        ".ifc {ctx}, r3", ".byte 0x03", ".endif",
        ".ifc {ctx}, r4", ".byte 0x04", ".endif",
        ".ifc {ctx}, r5", ".byte 0x05", ".endif",
        ".ifc {ctx}, r6", ".byte 0x06", ".endif",
        ".ifc {ctx}, r7", ".byte 0x07", ".endif",
        ".ifc {ctx}, r8", ".byte 0x08", ".endif",
        ".ifc {ctx}, r9", ".byte 0x09", ".endif",
        ".short 1",
        ".long 0",
        ".byte 0x04",
        ".ifc {i}, r0", ".byte 0x00", ".endif",
        ".ifc {i}, r1", ".byte 0x01", ".endif",
        ".ifc {i}, r2", ".byte 0x02", ".endif",
        ".ifc {i}, r3", ".byte 0x03", ".endif",
        ".ifc {i}, r4", ".byte 0x04", ".endif",
        ".ifc {i}, r5", ".byte 0x05", ".endif",
        ".ifc {i}, r6", ".byte 0x06", ".endif",
        ".ifc {i}, r7", ".byte 0x07", ".endif",
        ".ifc {i}, r8", ".byte 0x08", ".endif",
        ".ifc {i}, r9", ".byte 0x09", ".endif",
        ".short 0",
        ".long 2",
        i = inout(reg) i_reg,
        ctx = in(reg) ctx_ptr,
        options(nostack, preserves_flags),
    );
    i_reg
}

#[link_section = "tp_btf/bpf_testmod_test_raw_tp_null_tp"]
#[no_mangle]
extern "C" fn test_raw_tp_null(ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();

    if *unsafe { &*task }.pid().get().unwrap() != unsafe { tid } {
        return 0;
    }

    let skb = fentry_arg(ctx, 0);
    let cur_i = unsafe { i };
    let new_i = unsafe { null_gated_incr(cur_i, skb) };
    unsafe {
        i = new_i;
    }
    0
}

bpf_object!("GPL");
