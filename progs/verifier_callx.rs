// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_callx.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_callx.rs
// (include!d below): global_add3, mul3, sub7, apply_op, callx_c_fn_as_arg, callx_c_select, run_ops, callx_c_ops_on_stack.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_callx` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: add1 add2 apply callx_basic callx_disasm callx_two_callees callx_fn_as_arg get_add1 callx_r0 callx_spill_fill clobber_callee_saved callx_callee_saved_regs callx_scratches_args callx_retval_is_tracked write42 callx_callee_writes_caller_stack callx_scalar callx_uninit_reg callx_fp callx_map_value callx_modified_ptr callx_variable_ptr global_add3 callx_global_func callx_reserved_field_src_reg callx_reserved_field_off callx_reserved_field_imm callx_jmp32 callx_under_lock call_helper callx_helper_under_lock self callx_unbounded_recursion countdown callx_bounded_recursion ping pong callx_mutual_recursion use_stack_304 use_stack_480_0 use_stack_480_1 use_stack_480_2 use_stack_480_3 callx_stack_depth apply_stack_304 callx_stack_depth_nested callx_stack_depth_ok do_tail_call callx_tail_call_in_callee callx_tail_call_in_caller read_idx callx_callee_reads_caller_stack callx_callee_reads_caller_stack_ok callx_callee_reads_caller_stack_nested callx_clobbers_const_regs identity callx_precision callx_addr_of_dead_func callx_addr_of_dead_func_first call_addr_of_dead_func mul3 sub7 apply_op callx_c_fn_as_arg callx_c_select run_ops callx_c_ops_on_stack

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    callx_basic:
        __success,
        __retval("6");
    callx_disasm:
        __success,
        __log_level("2"),
        __msg("(8d) callx r2"),
        __xlated("callx r2");
    callx_two_callees:
        __success,
        __retval("11");
    callx_fn_as_arg:
        __success,
        __retval("45");
    callx_r0:
        __success,
        __retval("2");
    callx_spill_fill:
        __success,
        __retval("9");
    callx_callee_saved_regs:
        __success,
        __retval("11");
    callx_scratches_args:
        __failure,
        __msg("R1 !read_ok");
    callx_retval_is_tracked:
        __success,
        __log_level("2"),
        __msg("to caller at 4:"),
        __msg("R0=6");
    callx_callee_writes_caller_stack:
        __success,
        __retval("42");
    callx_scalar:
        __failure,
        __msg("R1 has type scalar, expected func");
    callx_uninit_reg:
        __failure,
        __msg("R2 !read_ok");
    callx_fp:
        __failure,
        __msg("R10 has type fp, expected func");
    callx_map_value:
        __failure,
        __msg("R1 has type map_value, expected func");
    callx_modified_ptr:
        __failure,
        __msg("dereference of modified func ptr R2 off=8 disallowed");
    callx_variable_ptr:
        __failure,
        __msg("variable func access var_off=");
    callx_global_func:
        __failure,
        __msg("callback function not static");
    callx_reserved_field_src_reg:
        __failure,
        __msg("BPF_CALL|BPF_X uses reserved fields");
    callx_reserved_field_off:
        __failure,
        __msg("BPF_CALL|BPF_X uses reserved fields");
    callx_reserved_field_imm:
        __failure,
        __msg("BPF_CALL|BPF_X uses reserved fields");
    callx_jmp32:
        __failure,
        __msg("unknown opcode 8e");
    callx_under_lock:
        __success,
        __retval("3");
    callx_helper_under_lock:
        __failure,
        __msg("function calls are not allowed while holding a lock");
    callx_unbounded_recursion:
        __failure,
        __msg("frames is too deep");
    callx_bounded_recursion:
        __failure,
        __msg("recursive call from countdown() to countdown()");
    callx_mutual_recursion:
        __failure,
        __msg("recursive call from");
    callx_stack_depth:
        __failure,
        __msg("combined stack size of {{[0-9]+}} calls is");
    callx_stack_depth_nested:
        __failure,
        __msg("combined stack size of {{[0-9]+}} calls is");
    callx_stack_depth_ok:
        __success,
        __retval("0");
    callx_tail_call_in_callee:
        __failure,
        __msg("tail_calls are not allowed in functions called via callx");
    callx_tail_call_in_caller:
        __success,
        __retval("3");
    callx_callee_reads_caller_stack:
        __failure,
        __msg("invalid access to map value, value_size=8 off=1000 size=1"),
        __flag("BPF_F_TEST_STATE_FREQ");
    callx_callee_reads_caller_stack_ok:
        __success,
        __retval("0"),
        __flag("BPF_F_TEST_STATE_FREQ");
    callx_callee_reads_caller_stack_nested:
        __failure,
        __msg("invalid access to map value, value_size=8 off=1000 size=1"),
        __flag("BPF_F_TEST_STATE_FREQ");
    callx_clobbers_const_regs:
        __success,
        __retval("1");
    callx_precision:
        __success,
        __log_level("2"),
        __msg("mark_precise: frame0: regs=r0 stack= before 12: (95) exit"),
        __msg("mark_precise: frame1: regs=r0 stack= before 11: (bf) r0 = r1"),
        __msg("mark_precise: frame1: regs=r1 stack= before 4: (8d) callx r2"),
        __msg("mark_precise: frame0: regs=r1 stack= before 3: (bf) r1 = r6"),
        __msg("mark_precise: frame0: regs=r6 stack= before 2: (b7) r6 = 3"),
        __retval("4");
    callx_addr_of_dead_func:
        __success,
        __retval("6");
    callx_addr_of_dead_func_first:
        __success,
        __retval("7");
    call_addr_of_dead_func:
        __success,
        __retval("6");
    callx_c_fn_as_arg:
        __success,
        __retval("36");
    callx_c_select:
        __success,
        __retval("30");
    callx_c_ops_on_stack:
        __success,
        __retval("100");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct ops {
    first: *mut c_void,
    second: *mut c_void,
    bias: i32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct val_with_lock {
    lock: bpf_spin_lock,
    cnt: i32,
}

bpf_map! {
    map_array {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i64,
    }
}

bpf_map! {
    map_lock {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const val_with_lock,
    }
}

bpf_map! {
    map_prog {
        r#type: *const [i32; 3],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = ".data.vals"]
#[no_mangle]
static mut vals: [i64; 4] = [1, 2, 3, 4];

#[no_mangle]
#[inline(never)]
// BPF_NAKED: add1
extern "C" fn add1() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = r1;",
            "r0 += 1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: add2
extern "C" fn add2() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = r1;",
            "r0 += 2;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: apply
extern "C" fn apply() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r3 = r1;",
            "r1 = r2;",
            "callx r3;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_basic
extern "C" fn callx_basic() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "r2 = {add1} ll;",
            "callx r2;",
            "exit;",
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_disasm
extern "C" fn callx_disasm() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "r2 = {add1} ll;",
            "callx r2;",
            "exit;",
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_two_callees
extern "C" fn callx_two_callees() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r6 = r0;",
            "r6 &= 1;",
            "r2 = {add1} ll;",
            "if r6 == 0 goto +2;",
            "r2 = {add2} ll;",
            "r1 = 10;",
            "callx r2;",
            "r0 -= r6;",
            "exit;",
            add1 = sym add1,
            add2 = sym add2,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_fn_as_arg
extern "C" fn callx_fn_as_arg() {
    unsafe {
        core::arch::asm!(
            "r1 = {add2} ll;",
            "r2 = 40;",
            "call {apply};",
            "r6 = r0;",
            "r1 = {add1} ll;",
            "r2 = 2;",
            "call {apply};",
            "r0 += r6;",
            "exit;",
            add1 = sym add1,
            add2 = sym add2,
            apply = sym apply,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: get_add1
extern "C" fn get_add1() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = {add1} ll;",
            "exit;",
            add1 = sym add1,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_r0
extern "C" fn callx_r0() {
    unsafe {
        core::arch::asm!(
            "call {get_add1};",
            "r1 = 1;",
            "callx r0;",
            "exit;",
            get_add1 = sym get_add1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_spill_fill
extern "C" fn callx_spill_fill() {
    unsafe {
        core::arch::asm!(
            "r2 = {add2} ll;",
            "*(u64 *)(r10 - 8) = r2;",
            "call 7;",
            "r1 = 7;",
            "r9 = *(u64 *)(r10 - 8);",
            "callx r9;",
            "exit;",
            add2 = sym add2,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: clobber_callee_saved
extern "C" fn clobber_callee_saved() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r6 = 100;",
            "r7 = 100;",
            "r8 = 100;",
            "r9 = 100;",
            "r0 = r1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_callee_saved_regs
extern "C" fn callx_callee_saved_regs() {
    unsafe {
        core::arch::asm!(
            "r6 = 1;",
            "r7 = 2;",
            "r8 = 3;",
            "r9 = 4;",
            "r1 = 1;",
            "r2 = {clobber_callee_saved} ll;",
            "callx r2;",
            "r0 += r6;",
            "r0 += r7;",
            "r0 += r8;",
            "r0 += r9;",
            "exit;",
            clobber_callee_saved = sym clobber_callee_saved,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_scratches_args
extern "C" fn callx_scratches_args() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "r2 = {add1} ll;",
            "callx r2;",
            "r0 = r1;",
            "exit;",
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_retval_is_tracked
extern "C" fn callx_retval_is_tracked() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "r2 = {add1} ll;",
            "callx r2;",
            "exit;",
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: write42
extern "C" fn write42() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r2 = 42;",
            "*(u64 *)(r1 + 0) = r2;",
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_callee_writes_caller_stack
extern "C" fn callx_callee_writes_caller_stack() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = {write42} ll;",
            "callx r2;",
            "r0 = *(u64 *)(r10 - 8);",
            "exit;",
            write42 = sym write42,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_scalar
extern "C" fn callx_scalar() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "callx r1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_uninit_reg
extern "C" fn callx_uninit_reg() {
    unsafe {
        core::arch::asm!(
            "callx r2;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_fp
extern "C" fn callx_fp() {
    unsafe {
        core::arch::asm!(
            "callx r10;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_map_value
extern "C" fn callx_map_value() {
    unsafe {
        core::arch::asm!(
            "r1 = {map_array} ll;",
            "r2 = r10;",
            "r2 += -4;",
            "r3 = 0;",
            "*(u32 *)(r2 + 0) = r3;",
            "call 1;",
            "if r0 == 0 goto 1f;",
            "r1 = r0;",
            "callx r1;",
            "1:",
            "r0 = 0;",
            "exit;",
            map_array = sym map_array,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_modified_ptr
extern "C" fn callx_modified_ptr() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "r2 = {add1} ll;",
            "r2 += 8;",
            "callx r2;",
            "exit;",
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_variable_ptr
extern "C" fn callx_variable_ptr() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r0 &= 8;",
            "r2 = {add1} ll;",
            "r2 += r0;",
            "r1 = 5;",
            "callx r2;",
            "exit;",
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_global_func
extern "C" fn callx_global_func() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "r2 = {global_add3} ll;",
            "callx r2;",
            "exit;",
            global_add3 = sym global_add3,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_reserved_field_src_reg
extern "C" fn callx_reserved_field_src_reg() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "r2 = {add1} ll;",
            ".8byte 4749;",
            "exit;",
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_reserved_field_off
extern "C" fn callx_reserved_field_off() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "r2 = {add1} ll;",
            ".8byte 66189;",
            "exit;",
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_reserved_field_imm
extern "C" fn callx_reserved_field_imm() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "r2 = {add1} ll;",
            ".8byte 4294967949;",
            "exit;",
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_jmp32
extern "C" fn callx_jmp32() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "r2 = {add1} ll;",
            ".8byte 654;",
            "exit;",
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_under_lock
extern "C" fn callx_under_lock() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32 *)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_lock} ll;",
            "call 1;",
            "if r0 != 0 goto 1f;",
            "exit;",
            "1:",
            "r6 = r0;",
            "r1 = r6;",
            "call 93;",
            "r1 = 1;",
            "r2 = {add2} ll;",
            "callx r2;",
            "r7 = r0;",
            "r1 = r6;",
            "call 94;",
            "r0 = r7;",
            "exit;",
            map_lock = sym map_lock,
            add2 = sym add2,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: call_helper
extern "C" fn call_helper() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "call 7;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_helper_under_lock
extern "C" fn callx_helper_under_lock() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32 *)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_lock} ll;",
            "call 1;",
            "if r0 != 0 goto 1f;",
            "exit;",
            "1:",
            "r6 = r0;",
            "r1 = r6;",
            "call 93;",
            "r2 = {call_helper} ll;",
            "callx r2;",
            "r1 = r6;",
            "call 94;",
            "r0 = 0;",
            "exit;",
            map_lock = sym map_lock,
            call_helper = sym call_helper,
            options(nostack)
        );
    }
}

#[export_name = "self"]
#[inline(never)]
// BPF_NAKED: self
extern "C" fn self_() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "callx r1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_unbounded_recursion
extern "C" fn callx_unbounded_recursion() {
    unsafe {
        core::arch::asm!(
            "r1 = {self_} ll;",
            "call {self_};",
            "exit;",
            self_ = sym self_,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: countdown
extern "C" fn countdown() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r2 == 0 goto 1f;",
            "r2 += -1;",
            "callx r1;",
            "1:",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_bounded_recursion
extern "C" fn callx_bounded_recursion() {
    unsafe {
        core::arch::asm!(
            "r1 = {countdown} ll;",
            "r2 = 2;",
            "call {countdown};",
            "exit;",
            countdown = sym countdown,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ping
extern "C" fn ping() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r3 == 0 goto 1f;",
            "r3 += -1;",
            "r4 = r1;",
            "r1 = r2;",
            "r2 = r4;",
            "callx r1;",
            "1:",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: pong
extern "C" fn pong() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "if r3 == 0 goto 1f;",
            "r3 += -1;",
            "r4 = r1;",
            "r1 = r2;",
            "r2 = r4;",
            "callx r1;",
            "1:",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_mutual_recursion
extern "C" fn callx_mutual_recursion() {
    unsafe {
        core::arch::asm!(
            "r1 = {ping} ll;",
            "r2 = {pong} ll;",
            "r3 = 3;",
            "call {ping};",
            "exit;",
            ping = sym ping,
            pong = sym pong,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: use_stack_304
extern "C" fn use_stack_304() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 304) = r0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: use_stack_480_0
extern "C" fn use_stack_480_0() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 480) = r0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: use_stack_480_1
extern "C" fn use_stack_480_1() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 480) = r0;",
            "call {use_stack_480_0};",
            "exit;",
            use_stack_480_0 = sym use_stack_480_0,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: use_stack_480_2
extern "C" fn use_stack_480_2() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 480) = r0;",
            "call {use_stack_480_1};",
            "exit;",
            use_stack_480_1 = sym use_stack_480_1,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: use_stack_480_3
extern "C" fn use_stack_480_3() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 480) = r0;",
            "call {use_stack_480_2};",
            "exit;",
            use_stack_480_2 = sym use_stack_480_2,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_stack_depth
extern "C" fn callx_stack_depth() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 480) = r0;",
            "r2 = {use_stack_480_3} ll;",
            "callx r2;",
            "exit;",
            use_stack_480_3 = sym use_stack_480_3,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: apply_stack_304
extern "C" fn apply_stack_304() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 304) = r0;",
            "callx r1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_stack_depth_nested
extern "C" fn callx_stack_depth_nested() {
    unsafe {
        core::arch::asm!(
            "r1 = {use_stack_480_3} ll;",
            "call {apply_stack_304};",
            "exit;",
            use_stack_480_3 = sym use_stack_480_3,
            apply_stack_304 = sym apply_stack_304,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_stack_depth_ok
extern "C" fn callx_stack_depth_ok() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "*(u64 *)(r10 - 200) = r0;",
            "r2 = {use_stack_304} ll;",
            "callx r2;",
            "exit;",
            use_stack_304 = sym use_stack_304,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: do_tail_call
extern "C" fn do_tail_call() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r2 = {map_prog} ll;",
            "r3 = 0;",
            "call 12;",
            "r0 = 0;",
            "exit;",
            map_prog = sym map_prog,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_tail_call_in_callee
extern "C" fn callx_tail_call_in_callee() {
    unsafe {
        core::arch::asm!(
            "r2 = {do_tail_call} ll;",
            "callx r2;",
            "exit;",
            do_tail_call = sym do_tail_call,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_tail_call_in_caller
extern "C" fn callx_tail_call_in_caller() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r1 = 2;",
            "r2 = {add1} ll;",
            "callx r2;",
            "r7 = r0;",
            "r1 = r6;",
            "r2 = {map_prog} ll;",
            "r3 = 0;",
            "call 12;",
            "r0 = r7;",
            "exit;",
            map_prog = sym map_prog,
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: read_idx
extern "C" fn read_idx() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r6 = *(u64 *)(r1 + 0);",
            "r1 = 0;",
            "*(u32 *)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_array} ll;",
            "call 1;",
            "if r0 == 0 goto 1f;",
            "r0 += r6;",
            "r0 = *(u8 *)(r0 + 0);",
            "1:",
            "exit;",
            map_array = sym map_array,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_callee_reads_caller_stack
extern "C" fn callx_callee_reads_caller_stack() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 1000;",
            "*(u64 *)(r10 - 8) = r1;",
            "if r0 == 0 goto 1f;",
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "1:",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = {read_idx} ll;",
            "callx r2;",
            "r0 = 0;",
            "exit;",
            read_idx = sym read_idx,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_callee_reads_caller_stack_ok
extern "C" fn callx_callee_reads_caller_stack_ok() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 7;",
            "*(u64 *)(r10 - 8) = r1;",
            "if r0 == 0 goto 1f;",
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "1:",
            "r1 = r10;",
            "r1 += -8;",
            "r2 = {read_idx} ll;",
            "callx r2;",
            "exit;",
            read_idx = sym read_idx,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_callee_reads_caller_stack_nested
extern "C" fn callx_callee_reads_caller_stack_nested() {
    unsafe {
        core::arch::asm!(
            "call 7;",
            "r1 = 1000;",
            "*(u64 *)(r10 - 8) = r1;",
            "if r0 == 0 goto 1f;",
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            "1:",
            "r1 = {read_idx} ll;",
            "r2 = r10;",
            "r2 += -8;",
            "call {apply};",
            "r0 = 0;",
            "exit;",
            read_idx = sym read_idx,
            apply = sym apply,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_clobbers_const_regs
extern "C" fn callx_clobbers_const_regs() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = 0;",
            "r2 = {add1} ll;",
            "callx r2;",
            "if r0 == 0 goto 1f;",
            "r0 = 1;",
            "exit;",
            "1:",
            "r0 = 2;",
            "exit;",
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: identity
extern "C" fn identity() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = r1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_precision
extern "C" fn callx_precision() {
    unsafe {
        core::arch::asm!(
            "r2 = {identity} ll;",
            "r6 = 3;",
            "r1 = r6;",
            "callx r2;",
            "r0 *= 8;",
            "r1 = {vals} ll;",
            "r1 += r0;",
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            identity = sym identity,
            vals = sym vals,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_addr_of_dead_func
extern "C" fn callx_addr_of_dead_func() {
    unsafe {
        core::arch::asm!(
            "r6 = {add1} ll;",
            "r7 = {add2} ll;",
            "r1 = 5;",
            "callx r6;",
            "if r7 != r6 goto +1;",
            "r0 = 0;",
            "exit;",
            add1 = sym add1,
            add2 = sym add2,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_addr_of_dead_func_first
extern "C" fn callx_addr_of_dead_func_first() {
    unsafe {
        core::arch::asm!(
            "r7 = {add1} ll;",
            "r6 = {add2} ll;",
            "r1 = 5;",
            "callx r6;",
            "if r7 != r6 goto +1;",
            "r0 = 0;",
            "exit;",
            add1 = sym add1,
            add2 = sym add2,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: call_addr_of_dead_func
extern "C" fn call_addr_of_dead_func() {
    unsafe {
        core::arch::asm!(
            "r1 = 5;",
            "call {add1};",
            "r7 = {add2} ll;",
            "exit;",
            add2 = sym add2,
            add1 = sym add1,
            options(nostack)
        );
    }
}

include!("hand/verifier_callx.rs");

bpf_object!("GPL");
