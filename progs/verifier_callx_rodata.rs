// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]
#![allow(function_casts_as_integer)]

// Translation of tools/testing/selftests/bpf/progs/verifier_callx_rodata.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_callx_rodata.rs
// (include!d below): global_add3, pull_data, calls_pull_data, global_calls_pull_data, op0, op1, op2, op3, op4, op5, op6, op7, op8, op9, op10, op11, op12, op13, op14, op15, callx_c_table, callx_c_table_null_check, use_shape, callx_c_ops_mixed_with_data, callx_c_ops_selected, call_by_switch, callx_c_switch_table, callx_c_packed_struct.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_callx_rodata` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: add1 add2 callx_rodata_const_index callx_rodata_needs_perfmon callx_rodata_elem_addr callx_rodata_mixed_with_data callx_data_rel_ro callx_rodata_array_of_structs callx_rodata_array_of_structs_data callx_rodata_array_of_structs_any callx_rodata_two_vtables callx_rodata_var_index callx_rodata_no_symbol nop_add1 callx_rodata_func_starts_with_nop deref_r1 ret0 callx_rodata_all_callees_verified callx_rodata_unused_callee callx_rodata_read_unused_callee callx_rodata_index_beyond_table callx_rodata_partial_read callx_rodata_misaligned_read callx_rodata_no_callx callx_rodata_data_is_const callx_rodata_ptr_is_not_const callx_rodata_modified_ptr global_add3 callx_rodata_global_func selfcall callx_rodata_recursion use_stack_480_0 use_stack_480_1 use_stack_480_2 use_stack_480_3 callx_rodata_stack_depth callx_rodata_callback_stack_depth pull_data calls_pull_data global_calls_pull_data callx_rodata_callee_effects op0 op1 op2 op3 op4 op5 op6 op7 op8 op9 op10 op11 op12 op13 op14 op15 callx_c_table callx_c_table_null_check use_shape callx_c_ops_mixed_with_data callx_c_ops_selected call_by_switch callx_c_switch_table callx_c_packed_struct

// the C's anonymous types, named here; scripts/btf_anon.py clears
// the names in the object's BTF
// BTF_ANON

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    callx_rodata_const_index:
        __success,
        __retval("12");
    callx_rodata_needs_perfmon:
        __success,
        __retval("12"),
        __failure_unpriv,
        __msg_unpriv("unreachable insn"),
        __caps_unpriv("39");
    callx_rodata_elem_addr:
        __success,
        __retval("12");
    callx_rodata_mixed_with_data:
        __success,
        __retval("23"),
        __log_level("2"),
        __msg("r1 = *(u64 *)(r6 +0)          ; R1=7"),
        __msg("r2 = *(u64 *)(r6 +8)          ; R2=func()");
    callx_data_rel_ro:
        __success,
        __retval("23");
    callx_rodata_array_of_structs:
        __success,
        __retval("11");
    callx_rodata_array_of_structs_data:
        __success,
        __retval("16");
    callx_rodata_array_of_structs_any:
        __failure,
        __msg("overlaps with a pointer to a function");
    callx_rodata_two_vtables:
        __success,
        __retval("2");
    callx_rodata_var_index:
        __success,
        __retval("11");
    callx_rodata_no_symbol:
        __success,
        __retval("11");
    callx_rodata_func_starts_with_nop:
        __success,
        __retval("11");
    callx_rodata_all_callees_verified:
        __failure,
        __msg("R1 invalid mem access 'scalar'");
    callx_rodata_unused_callee:
        __success,
        __retval("0");
    callx_rodata_read_unused_callee:
        __success,
        __retval("1");
    callx_rodata_index_beyond_table:
        __failure,
        __msg("overlaps with a pointer to a function");
    callx_rodata_partial_read:
        __failure,
        __msg("read of 4 bytes at offset"),
        __msg("overlaps with a pointer to a function");
    callx_rodata_misaligned_read:
        __failure,
        __msg("read of 8 bytes at offset"),
        __msg("overlaps with a pointer to a function");
    callx_rodata_no_callx:
        __success;
    callx_rodata_data_is_const:
        __success,
        __retval("0x1234"),
        __log_level("2"),
        __msg("R0=4660");
    callx_rodata_ptr_is_not_const:
        __success,
        __retval("11");
    callx_rodata_modified_ptr:
        __failure,
        __msg("dereference of modified func ptr R2 off=8 disallowed");
    callx_rodata_global_func:
        __failure,
        __msg("R2 has type scalar, expected func");
    callx_rodata_recursion:
        __failure,
        __msg("recursive call from selfcall() to selfcall()");
    callx_rodata_stack_depth:
        __failure,
        __msg("combined stack size of {{[0-9]+}} calls is");
    callx_rodata_callback_stack_depth:
        __failure,
        __msg("combined stack size of {{[0-9]+}} calls is");
    callx_rodata_callee_effects:
        __failure,
        __msg("R7 invalid mem access 'scalar'");
    callx_c_table:
        __success,
        __retval("50");
    callx_c_table_null_check:
        __success,
        __retval("50");
    callx_c_ops_mixed_with_data:
        __success,
        __retval("433");
    callx_c_ops_selected:
        __success,
        __retval("367");
    callx_c_switch_table:
        __success,
        __retval("50");
    callx_c_packed_struct:
        __success,
        __retval("7");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union __sk_buff__anon26 {
    flow_keys: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union __sk_buff__anon30 {
    sk: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct __sk_buff {
    len: u32,
    pkt_type: u32,
    mark: u32,
    queue_mapping: u32,
    protocol: u32,
    vlan_present: u32,
    vlan_tci: u32,
    vlan_proto: u32,
    priority: u32,
    ingress_ifindex: u32,
    ifindex: u32,
    tc_index: u32,
    cb: [u32; 5],
    hash: u32,
    tc_classid: u32,
    data: u32,
    data_end: u32,
    napi_id: u32,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [u32; 4],
    local_ip6: [u32; 4],
    remote_port: u32,
    local_port: u32,
    data_meta: u32,
    __anon26: __sk_buff__anon26,
    tstamp: u64,
    wire_len: u32,
    gso_segs: u32,
    __anon30: __sk_buff__anon30,
    gso_size: u32,
    tstamp_type: u8,
    hwtstamp: u64,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct shape_ops {
    id: i32,
    area: extern "C" fn(i32) -> i32,
    scale: i64,
    perimeter: extern "C" fn(i32) -> i32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct __anon_type236 {
    tag: i8,
    op: extern "C" fn(i32) -> i32,
}

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut op_idx: i32 = 11;

#[link_section = ".rodata"]
#[no_mangle]
#[allow(non_upper_case_globals)]
static ops: [extern "C" fn(i32) -> i32; 16] = [op0, op1, op2, op3, op4, op5, op6, op7, op8, op9, op10, op11, op12, op13, op14, op15];

#[link_section = ".rodata"]
#[no_mangle]
#[allow(non_upper_case_globals)]
static packed_ops: [__anon_type236; 2] = [__anon_type236 { tag: 5, op: op0 }, __anon_type236 { tag: 7, op: op1 }];

#[link_section = ".rodata"]
#[no_mangle]
#[allow(non_upper_case_globals)]
static square_ops: shape_ops = shape_ops { id: 1, area: op1, scale: 10, perimeter: op2 };

#[link_section = ".rodata"]
#[no_mangle]
#[allow(non_upper_case_globals)]
static circle_ops: shape_ops = shape_ops { id: 2, area: op3, scale: 20, perimeter: op1 };

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

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_rodata_const_index
extern "C" fn callx_rodata_const_index() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_0:",
            ".quad {add1};",
            ".quad {add2};",
            ".type tbl_0, @object;",
            ".size tbl_0, .-tbl_0;",
            ".popsection;",
            "r2 = tbl_0 ll;",
            "r2 = *(u64 *)(r2 + 8);",
            "r1 = 10;",
            "callx r2;",
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
// BPF_NAKED: callx_rodata_needs_perfmon
extern "C" fn callx_rodata_needs_perfmon() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_1:",
            ".quad {add1};",
            ".quad {add2};",
            ".type tbl_1, @object;",
            ".size tbl_1, .-tbl_1;",
            ".popsection;",
            "r2 = tbl_1 ll;",
            "r2 = *(u64 *)(r2 + 8);",
            "r1 = 10;",
            "callx r2;",
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
// BPF_NAKED: callx_rodata_elem_addr
extern "C" fn callx_rodata_elem_addr() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_2:",
            ".quad {add1};",
            ".quad {add2};",
            ".type tbl_2, @object;",
            ".size tbl_2, .-tbl_2;",
            ".popsection;",
            "r2 = tbl_2 + 8 ll;",
            "r2 = *(u64 *)(r2 + 0);",
            "r1 = 10;",
            "callx r2;",
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
// BPF_NAKED: callx_rodata_mixed_with_data
extern "C" fn callx_rodata_mixed_with_data() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "vt_3:",
            ".quad 7;",
            ".quad {add1};",
            ".quad 13;",
            ".quad {add2};",
            ".type vt_3, @object;",
            ".size vt_3, .-vt_3;",
            ".popsection;",
            "r6 = vt_3 ll;",
            "r1 = *(u64 *)(r6 + 0);",
            "r2 = *(u64 *)(r6 + 8);",
            "callx r2;",
            "r7 = r0;",
            "r1 = *(u64 *)(r6 + 16);",
            "r2 = *(u64 *)(r6 + 24);",
            "callx r2;",
            "r0 += r7;",
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
// BPF_NAKED: callx_data_rel_ro
extern "C" fn callx_data_rel_ro() {
    unsafe {
        core::arch::asm!(
            ".pushsection .data.rel.ro,\"aw\",@progbits;",
            ".balign 8;",
            "vt_4:",
            ".quad 7;",
            ".quad {add1};",
            ".quad 13;",
            ".quad {add2};",
            ".type vt_4, @object;",
            ".size vt_4, .-vt_4;",
            ".popsection;",
            "r6 = vt_4 ll;",
            "r1 = *(u64 *)(r6 + 0);",
            "r2 = *(u64 *)(r6 + 8);",
            "callx r2;",
            "r7 = r0;",
            "r1 = *(u64 *)(r6 + 16);",
            "r2 = *(u64 *)(r6 + 24);",
            "callx r2;",
            "r0 += r7;",
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
// BPF_NAKED: callx_rodata_array_of_structs
extern "C" fn callx_rodata_array_of_structs() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "arr_5:",
            ".quad {add1};",
            ".quad 0x1111;",
            ".quad {add2};",
            ".quad 0x2222;",
            ".type arr_5, @object;",
            ".size arr_5, .-arr_5;",
            ".popsection;",
            "call 7;",
            "r6 = r0;",
            "r6 &= 1;",
            "r3 = r6;",
            "r3 <<= 4;",
            "r2 = arr_5 ll;",
            "r2 += r3;",
            "r2 = *(u64 *)(r2 + 0);",
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
// BPF_NAKED: callx_rodata_array_of_structs_data
extern "C" fn callx_rodata_array_of_structs_data() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "arr_6:",
            ".quad {add1};",
            ".quad 5;",
            ".quad {add2};",
            ".quad 5;",
            ".type arr_6, @object;",
            ".size arr_6, .-arr_6;",
            ".popsection;",
            "call 7;",
            "r6 = r0;",
            "r6 &= 1;",
            "r3 = r6;",
            "r3 <<= 4;",
            "r7 = arr_6 ll;",
            "r7 += r3;",
            "r2 = *(u64 *)(r7 + 0);",
            "r1 = 10;",
            "callx r2;",
            "r0 -= r6;",
            "r1 = *(u64 *)(r7 + 8);",
            "r0 += r1;",
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
// BPF_NAKED: callx_rodata_array_of_structs_any
extern "C" fn callx_rodata_array_of_structs_any() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "arr_7:",
            ".quad {add1};",
            ".quad 5;",
            ".quad {add2};",
            ".quad 5;",
            ".type arr_7, @object;",
            ".size arr_7, .-arr_7;",
            ".popsection;",
            "call 7;",
            "r0 &= 3;",
            "r0 <<= 3;",
            "r2 = arr_7 ll;",
            "r2 += r0;",
            "r2 = *(u64 *)(r2 + 0);",
            "r1 = 10;",
            "callx r2;",
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
// BPF_NAKED: callx_rodata_two_vtables
extern "C" fn callx_rodata_two_vtables() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "vt_a_8:",
            ".quad 1;",
            ".quad {add1};",
            ".type vt_a_8, @object;",
            ".size vt_a_8, .-vt_a_8;",
            ".popsection;",
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "vt_b_8:",
            ".quad 0;",
            ".quad {add2};",
            ".type vt_b_8, @object;",
            ".size vt_b_8, .-vt_b_8;",
            ".popsection;",
            "call 7;",
            "r6 = vt_a_8 ll;",
            "r0 &= 1;",
            "if r0 == 0 goto +2;",
            "r6 = vt_b_8 ll;",
            "r1 = *(u64 *)(r6 + 0);",
            "r2 = *(u64 *)(r6 + 8);",
            "callx r2;",
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
// BPF_NAKED: callx_rodata_var_index
extern "C" fn callx_rodata_var_index() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_9:",
            ".quad {add1};",
            ".quad {add2};",
            ".type tbl_9, @object;",
            ".size tbl_9, .-tbl_9;",
            ".popsection;",
            "call 7;",
            "r6 = r0;",
            "r6 &= 1;",
            "r3 = r6;",
            "r3 <<= 3;",
            "r2 = tbl_9 ll;",
            "r2 += r3;",
            "r2 = *(u64 *)(r2 + 0);",
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
// BPF_NAKED: callx_rodata_no_symbol
extern "C" fn callx_rodata_no_symbol() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            ".Lanon_10:.quad add1;",
            ".quad {add2};",
            ".popsection;",
            "call 7;",
            "r6 = r0;",
            "r6 &= 1;",
            "r3 = r6;",
            "r3 <<= 3;",
            "r2 = .Lanon_10 ll;",
            "r2 += r3;",
            "r2 = *(u64 *)(r2 + 0);",
            "r1 = 10;",
            "callx r2;",
            "r0 -= r6;",
            "exit;",
            add2 = sym add2,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: nop_add1
extern "C" fn nop_add1() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "goto +0;",
            "r0 = r1;",
            "r0 += 1;",
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
// BPF_NAKED: callx_rodata_func_starts_with_nop
extern "C" fn callx_rodata_func_starts_with_nop() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_11:",
            ".quad {nop_add1};",
            ".quad 0;",
            ".type tbl_11, @object;",
            ".size tbl_11, .-tbl_11;",
            ".popsection;",
            "r2 = tbl_11 ll;",
            "r2 = *(u64 *)(r2 + 0);",
            "r1 = 10;",
            "callx r2;",
            "exit;",
            nop_add1 = sym nop_add1,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: deref_r1
extern "C" fn deref_r1() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "r0 = *(u64 *)(r1 + 0);",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: ret0
extern "C" fn ret0() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
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
// BPF_NAKED: callx_rodata_all_callees_verified
extern "C" fn callx_rodata_all_callees_verified() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_12:",
            ".quad {ret0};",
            ".quad {deref_r1};",
            ".type tbl_12, @object;",
            ".size tbl_12, .-tbl_12;",
            ".popsection;",
            "call 7;",
            "r0 &= 1;",
            "r0 <<= 3;",
            "r2 = tbl_12 ll;",
            "r2 += r0;",
            "r2 = *(u64 *)(r2 + 0);",
            "r1 = 0;",
            "callx r2;",
            "exit;",
            ret0 = sym ret0,
            deref_r1 = sym deref_r1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_rodata_unused_callee
extern "C" fn callx_rodata_unused_callee() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_13:",
            ".quad {ret0};",
            ".quad {deref_r1};",
            ".type tbl_13, @object;",
            ".size tbl_13, .-tbl_13;",
            ".popsection;",
            "r2 = tbl_13 ll;",
            "r2 = *(u64 *)(r2 + 0);",
            "r1 = 0;",
            "callx r2;",
            "exit;",
            ret0 = sym ret0,
            deref_r1 = sym deref_r1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_rodata_read_unused_callee
extern "C" fn callx_rodata_read_unused_callee() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_14:",
            ".quad {ret0};",
            ".quad {deref_r1};",
            ".type tbl_14, @object;",
            ".size tbl_14, .-tbl_14;",
            ".popsection;",
            "r6 = tbl_14 ll;",
            "r2 = *(u64 *)(r6 + 0);",
            "r1 = 0;",
            "callx r2;",
            "r2 = *(u64 *)(r6 + 8);",
            "if r2 != 0 goto +1;",
            "r0 = 1;",
            "exit;",
            ret0 = sym ret0,
            deref_r1 = sym deref_r1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_rodata_index_beyond_table
extern "C" fn callx_rodata_index_beyond_table() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_15:",
            ".quad {add1};",
            ".quad {add2};",
            ".quad 0x1234;",
            ".quad 0x5678;",
            ".type tbl_15, @object;",
            ".size tbl_15, .-tbl_15;",
            ".popsection;",
            "call 7;",
            "r0 &= 3;",
            "r0 <<= 3;",
            "r2 = tbl_15 ll;",
            "r2 += r0;",
            "r2 = *(u64 *)(r2 + 0);",
            "r1 = 10;",
            "callx r2;",
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
// BPF_NAKED: callx_rodata_partial_read
extern "C" fn callx_rodata_partial_read() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_16:",
            ".quad {add1};",
            ".quad {add2};",
            ".type tbl_16, @object;",
            ".size tbl_16, .-tbl_16;",
            ".popsection;",
            "r6 = tbl_16 ll;",
            "r2 = *(u64 *)(r6 + 8);",
            "r1 = 10;",
            "callx r2;",
            "r0 = *(u32 *)(r6 + 0);",
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
// BPF_NAKED: callx_rodata_misaligned_read
extern "C" fn callx_rodata_misaligned_read() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_17:",
            ".quad {add1};",
            ".quad {add2};",
            ".quad 0;",
            ".type tbl_17, @object;",
            ".size tbl_17, .-tbl_17;",
            ".popsection;",
            "r6 = tbl_17 ll;",
            "r2 = *(u64 *)(r6 + 0);",
            "r1 = 10;",
            "callx r2;",
            "r0 = *(u64 *)(r6 + 4);",
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
// BPF_NAKED: callx_rodata_no_callx
extern "C" fn callx_rodata_no_callx() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_18:",
            ".quad {add1};",
            ".quad {add2};",
            ".type tbl_18, @object;",
            ".size tbl_18, .-tbl_18;",
            ".popsection;",
            "r2 = tbl_18 ll;",
            "r0 = *(u32 *)(r2 + 0);",
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
// BPF_NAKED: callx_rodata_data_is_const
extern "C" fn callx_rodata_data_is_const() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_19:",
            ".quad {add1};",
            ".quad 0x1234;",
            ".type tbl_19, @object;",
            ".size tbl_19, .-tbl_19;",
            ".popsection;",
            "r6 = tbl_19 ll;",
            "r2 = *(u64 *)(r6 + 0);",
            "r1 = 10;",
            "callx r2;",
            "r0 = *(u64 *)(r6 + 8);",
            "exit;",
            add1 = sym add1,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_rodata_ptr_is_not_const
extern "C" fn callx_rodata_ptr_is_not_const() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_20:",
            ".quad {add1};",
            ".quad {add2};",
            ".type tbl_20, @object;",
            ".size tbl_20, .-tbl_20;",
            ".popsection;",
            "r2 = tbl_20 ll;",
            "r2 = *(u64 *)(r2 + 0);",
            "r0 = 0;",
            "if r2 < 0x100000 goto 1f;",
            "r1 = 10;",
            "callx r2;",
            "1:",
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
// BPF_NAKED: callx_rodata_modified_ptr
extern "C" fn callx_rodata_modified_ptr() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_21:",
            ".quad {add1};",
            ".quad {add2};",
            ".type tbl_21, @object;",
            ".size tbl_21, .-tbl_21;",
            ".popsection;",
            "r2 = tbl_21 ll;",
            "r2 = *(u64 *)(r2 + 0);",
            "r2 += 8;",
            "r1 = 10;",
            "callx r2;",
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
// BPF_NAKED: callx_rodata_global_func
extern "C" fn callx_rodata_global_func() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_22:",
            ".quad {add1};",
            ".quad {global_add3};",
            ".type tbl_22, @object;",
            ".size tbl_22, .-tbl_22;",
            ".popsection;",
            "r1 = 1;",
            "call {global_add3};",
            "r2 = tbl_22 ll;",
            "r2 = *(u64 *)(r2 + 8);",
            "r1 = 10;",
            "callx r2;",
            "exit;",
            add1 = sym add1,
            global_add3 = sym global_add3,
            options(nostack)
        );
    }
}

#[no_mangle]
#[inline(never)]
// BPF_NAKED: selfcall
extern "C" fn selfcall() -> u64 {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_23:",
            ".quad {selfcall};",
            ".quad {ret0};",
            ".type tbl_23, @object;",
            ".size tbl_23, .-tbl_23;",
            ".popsection;",
            "r0 = 0;",
            "if r1 == 0 goto 1f;",
            "r1 += -1;",
            "r2 = tbl_23 ll;",
            "r2 = *(u64 *)(r2 + 0);",
            "callx r2;",
            "1:",
            "exit;",
            selfcall = sym selfcall,
            ret0 = sym ret0,
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_rodata_recursion
extern "C" fn callx_rodata_recursion() {
    unsafe {
        core::arch::asm!(
            "r1 = 2;",
            "call {selfcall};",
            "exit;",
            selfcall = sym selfcall,
            options(nostack)
        );
    }
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
// BPF_NAKED: callx_rodata_stack_depth
extern "C" fn callx_rodata_stack_depth() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_24:",
            ".quad {ret0};",
            ".quad {use_stack_480_3};",
            ".type tbl_24, @object;",
            ".size tbl_24, .-tbl_24;",
            ".popsection;",
            "r0 = 0;",
            "*(u64 *)(r10 - 304) = r0;",
            "call 7;",
            "r0 &= 1;",
            "r0 <<= 3;",
            "r2 = tbl_24 ll;",
            "r2 += r0;",
            "r2 = *(u64 *)(r2 + 0);",
            "callx r2;",
            "exit;",
            ret0 = sym ret0,
            use_stack_480_3 = sym use_stack_480_3,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_rodata_callback_stack_depth
extern "C" fn callx_rodata_callback_stack_depth() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_25:",
            ".quad {use_stack_480_3};",
            ".quad {ret0};",
            ".type tbl_25, @object;",
            ".size tbl_25, .-tbl_25;",
            ".popsection;",
            "r0 = 0;",
            "*(u64 *)(r10 - 304) = r0;",
            "r6 = tbl_25 ll;",
            "r1 = 1;",
            "r2 = *(u64 *)(r6 + 0);",
            "r3 = 0;",
            "r4 = 0;",
            "call 181;",
            "r2 = *(u64 *)(r6 + 8);",
            "r1 = 0;",
            "callx r2;",
            "exit;",
            use_stack_480_3 = sym use_stack_480_3,
            ret0 = sym ret0,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: callx_rodata_callee_effects
extern "C" fn callx_rodata_callee_effects() {
    unsafe {
        core::arch::asm!(
            ".pushsection .rodata,\"a\",@progbits;",
            ".balign 8;",
            "tbl_26:",
            ".quad {pull_data};",
            ".quad {calls_pull_data};",
            ".type tbl_26, @object;",
            ".size tbl_26, .-tbl_26;",
            ".popsection;",
            "r6 = r1;",
            "r7 = *(u32 *)(r6 + 76);",
            "r8 = *(u32 *)(r6 + 80);",
            "r2 = r7;",
            "r2 += 8;",
            "if r2 > r8 goto 1f;",
            "r1 = r6;",
            "call {global_calls_pull_data};",
            "r0 = *(u8 *)(r7 + 0);",
            "1:",
            "r9 = tbl_26 ll;",
            "r2 = *(u64 *)(r9 + 8);",
            "r1 = r6;",
            "callx r2;",
            "r0 = 0;",
            "exit;",
            pull_data = sym pull_data,
            calls_pull_data = sym calls_pull_data,
            global_calls_pull_data = sym global_calls_pull_data,
            options(nostack)
        );
    }
}

include!("hand/verifier_callx_rodata.rs");

bpf_object!("GPL");
