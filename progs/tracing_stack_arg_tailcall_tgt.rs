// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/tracing_stack_arg_tailcall_tgt.c
// (bpf-rs-core idiom).
//
// The C source takes its __BPF_FEATURE_STACK_ARGUMENT branch under the
// clang 23 oracle (see stack_arg.rs): callee_stack's g and h travel in the
// r11 stack-argument area, and the test attaches fentry/fexit programs to
// that static subprogram by name. `run` is tail_call_reachable through
// subprog_tail while callee_stack is not, which is what the test checks
// the trampoline handles. C's bpf_tail_call_static() pins the index in
// r3 as a constant; the helper thunk with a literal index compiles to the
// same `r3 = 0; call 12`.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::bpf_map;
use bpf_rs_core::helpers::{barrier_var, bpf_tail_call};

bpf_map! {
    jmp_table {
        r#type: *const [i32; 3], // BPF_MAP_TYPE_PROG_ARRAY
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[no_mangle]
static mut base: u64 = 0;
#[no_mangle]
static mut ret_stack: u64 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static has_stack_arg: bool = true;

/* g and h are on the stack, for the x86-64 kernel convention too. */
#[inline(never)]
#[no_mangle]
extern "C" fn callee_stack(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64) -> u64 {
    a.wrapping_add(b.wrapping_mul(2))
        .wrapping_add(c.wrapping_mul(3))
        .wrapping_add(d.wrapping_mul(4))
        .wrapping_add(e.wrapping_mul(5))
        .wrapping_add(f.wrapping_mul(6))
        .wrapping_add(g.wrapping_mul(7))
        .wrapping_add(h.wrapping_mul(8))
}

/* No stack args of its own, so it can share a program with a tail call. */
#[inline(never)]
#[no_mangle]
extern "C" fn call_stack(x: u64) -> u64 {
    callee_stack(
        x.wrapping_add(1),
        x.wrapping_add(2),
        x.wrapping_add(3),
        x.wrapping_add(4),
        x.wrapping_add(5),
        x.wrapping_add(6),
        x.wrapping_add(7),
        x.wrapping_add(8),
    )
}

/* Makes the program tail_call_reachable, though callee_stack() is not. */
#[inline(never)]
#[no_mangle]
extern "C" fn subprog_tail(ctx: *mut c_void) -> i32 {
    let mut ret: usize = 0;

    bpf_tail_call(ctx, &jmp_table, 0);
    barrier_var(&mut ret);
    ret as i32
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn run(ctx: *mut c_void) -> i32 {
    unsafe {
        ret_stack = call_stack(base);
    }
    subprog_tail(ctx)
}

bpf_object!("GPL");
