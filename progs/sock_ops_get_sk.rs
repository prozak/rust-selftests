#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/sock_ops_get_sk.c
// (bpf-rs-core idiom).
//
// The C source is three `__naked` sockops programs whose entire body is
// hand-written BPF asm exercising the SOCK_OPS_GET_SK()/SOCK_OPS_GET_FIELD()
// ctx-rewrite macros in the kernel's sock_ops_convert_ctx_access(): reading
// `ctx->sk` / `ctx->snd_cwnd` with the destination register equal to (or
// different from) the ctx pointer's own register. What matters for the
// verifier's internal codegen path is the *raw instruction encoding*
// (dst_reg == src_reg or not) of that one ctx field-access load, not any
// value semantics of the rest of the program — so only that load needs to
// be hand-written `asm!`; the branch/store logic around it can be plain
// Rust. Reusing a single `inout(reg)` operand for both the load's base and
// destination forces the assembler to pick one physical register for both
// (dst == src, matching the `_same_reg` variants); using a separate `in`
// input register plus `lateout` output registers instead forces the
// opposite (`lateout` is guaranteed by `asm!`'s semantics to not overlap any
// `in` operand's register, matching `_diff_reg`). This sidesteps needing to
// know *which* physical registers LLVM picks (unlike this repo's other
// naked-asm translations, arena_htab_asm.rs/raw_tp_null.rs, which hand-code
// raw instruction bytes via `.ifc {x}, rN` register sniffing because they
// need to fully control encodings that don't correspond to plain Rust
// operations) — the verifier's ctx rewrite only cares about dst_reg==src_reg
// at that one instruction, regardless of which register number it is.
//
// (A first attempt translated each program as a single all-asm `__naked`-
// style block ending in a literal `exit;`, matching the C source
// instruction-for-instruction with `options(noreturn)`. That compiled, but
// rustc/LLVM's lowering for the unreachable code after a `noreturn` asm
// block on this bpf target emits a concrete `w0 = 0; exit;` trap rather
// than eliding it, which the kernel verifier rejects as unreachable dead
// code ("unreachable insn 15"). Keeping only the register-sensitive load in
// asm and returning normally in Rust avoids that trailing dead code.)

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

#[no_mangle]
static mut bug_detected: i32 = 0;
#[no_mangle]
static mut null_seen: i32 = 0;

/// SOCK_OPS_GET_SK: same-register, is_fullsock == 0 path.
#[link_section = "sockops"]
#[no_mangle]
extern "C" fn sock_ops_get_sk_same_reg(ctx: *const c_void) -> i32 {
    let is_fullsock: u32;
    let mut sk: u64 = ctx as u64;
    unsafe {
        core::arch::asm!(
            "{is_fullsock} = *(u32 *)({sk} + 72);",
            "{sk} = *(u64 *)({sk} + 184);",
            is_fullsock = out(reg) is_fullsock,
            sk = inout(reg) sk,
        );
        if is_fullsock == 0 {
            if sk == 0 {
                null_seen = 1;
            } else {
                bug_detected = 1;
            }
        }
    }
    1
}

#[no_mangle]
static mut field_bug_detected: i32 = 0;
#[no_mangle]
static mut field_null_seen: i32 = 0;

/// SOCK_OPS_GET_FIELD: same-register, is_locked_tcp_sock == 0 path.
#[link_section = "sockops"]
#[no_mangle]
extern "C" fn sock_ops_get_field_same_reg(ctx: *const c_void) -> i32 {
    let is_fullsock: u32;
    let mut snd_cwnd: u64 = ctx as u64;
    unsafe {
        core::arch::asm!(
            "{is_fullsock} = *(u32 *)({snd_cwnd} + 72);",
            "{snd_cwnd} = *(u32 *)({snd_cwnd} + 76);",
            is_fullsock = out(reg) is_fullsock,
            snd_cwnd = inout(reg) snd_cwnd,
        );
        if is_fullsock == 0 {
            if snd_cwnd == 0 {
                field_null_seen = 1;
            } else {
                field_bug_detected = 1;
            }
        }
    }
    1
}

#[no_mangle]
static mut diff_reg_bug_detected: i32 = 0;
#[no_mangle]
static mut diff_reg_null_seen: i32 = 0;

/// SOCK_OPS_GET_SK: different-register, is_fullsock == 0 path.
#[link_section = "sockops"]
#[no_mangle]
extern "C" fn sock_ops_get_sk_diff_reg(ctx: *const c_void) -> i32 {
    let ctx_val = ctx as u64;
    let is_fullsock: u32;
    let sk: u64;
    unsafe {
        core::arch::asm!(
            "{is_fullsock} = *(u32 *)({ctx} + 72);",
            "{sk} = *(u64 *)({ctx} + 184);",
            ctx = in(reg) ctx_val,
            is_fullsock = out(reg) is_fullsock,
            sk = out(reg) sk,
        );
        if is_fullsock == 0 {
            if sk == 0 {
                diff_reg_null_seen = 1;
            } else {
                diff_reg_bug_detected = 1;
            }
        }
    }
    1
}

bpf_object!("GPL");
