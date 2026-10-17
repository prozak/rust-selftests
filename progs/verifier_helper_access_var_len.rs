// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_helper_access_var_len.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_helper_access_var_len.rs
// (include!d below): writeonly_sized_input, readwrite_sized_input, readonly_sized_output, xdp_writeonly_sized_input, writeonly_header_option, readwrite_header_option, snprintf_writeonly_output, snprintf_readonly_output, sysctl_writeonly_output, sysctl_partial_dynptr, snprintf_partial_output_runtime.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_helper_access_var_len` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: bitwise_and_jmp_correct_bounds stack_bitwise_and_zero_included bitwise_and_jmp_wrong_max memory_stack_jmp_correct_bounds stack_jmp_signed_correct_bounds memory_stack_jmp_bounds_offset memory_stack_jmp_wrong_max stack_jmp_no_max_check stack_jmp_no_min_check jmp_signed_no_min_check memory_map_jmp_correct_bounds memory_map_jmp_wrong_max map_adjusted_jmp_correct_bounds map_adjusted_jmp_wrong_max ptr_to_mem_or_null_1 ptr_to_mem_or_null_2 ptr_to_mem_or_null_3 ptr_to_mem_or_null_4 ptr_to_mem_or_null_5 ptr_to_mem_or_null_6 ptr_to_mem_or_null_7 ptr_to_mem_or_null_8 ptr_to_mem_or_null_9 ptr_to_mem_or_null_10 ptr_to_mem_or_null_11 ptr_to_mem_or_null_12 ptr_to_mem_or_null_13 variable_memory_8_bytes_leak bytes_no_leak_init_memory writeonly_sized_input readwrite_sized_input readonly_sized_output xdp_writeonly_sized_input writeonly_header_option readwrite_header_option snprintf_writeonly_output snprintf_readonly_output sysctl_writeonly_output sysctl_initialized_stack sysctl_uninitialized_stack sysctl_partial_initialized_bytes sysctl_partial_invalid_bytes sysctl_partial_variable_size sysctl_partial_variable_invalid sysctl_partial_spilled_pointer sysctl_partial_dynptr sysctl_partial_variable_offset snprintf_partial_output_runtime

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    bitwise_and_jmp_correct_bounds:
        __description("helper access to variable memory: stack, bitwise AND + JMP, correct bounds"),
        __success;
    stack_bitwise_and_zero_included:
        __description("helper access to variable memory: stack, bitwise AND, zero included"),
        __success,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack R2 off -64+0 size 64"),
        __retval("0");
    bitwise_and_jmp_wrong_max:
        __description("helper access to variable memory: stack, bitwise AND + JMP, wrong max"),
        __failure,
        __msg("invalid write to stack R1 off=-64 size=65");
    memory_stack_jmp_correct_bounds:
        __description("helper access to variable memory: stack, JMP, correct bounds"),
        __success;
    stack_jmp_signed_correct_bounds:
        __description("helper access to variable memory: stack, JMP (signed), correct bounds"),
        __success;
    memory_stack_jmp_bounds_offset:
        __description("helper access to variable memory: stack, JMP, bounds + offset"),
        __failure,
        __msg("invalid write to stack R1 off=-64 size=65");
    memory_stack_jmp_wrong_max:
        __description("helper access to variable memory: stack, JMP, wrong max"),
        __failure,
        __msg("invalid write to stack R1 off=-64 size=65");
    stack_jmp_no_max_check:
        __description("helper access to variable memory: stack, JMP, no max check"),
        __failure,
        __msg("R2 min value is negative, either use unsigned or 'var &= const'");
    stack_jmp_no_min_check:
        __description("helper access to variable memory: stack, JMP, no min check"),
        __success,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack R2 off -64+0 size 64"),
        __retval("0");
    jmp_signed_no_min_check:
        __description("helper access to variable memory: stack, JMP (signed), no min check"),
        __failure,
        __msg("R2 min value is negative");
    memory_map_jmp_correct_bounds:
        __description("helper access to variable memory: map, JMP, correct bounds"),
        __success;
    memory_map_jmp_wrong_max:
        __description("helper access to variable memory: map, JMP, wrong max"),
        __failure,
        __msg("invalid access to map value, value_size=48 off=0 size=49");
    map_adjusted_jmp_correct_bounds:
        __description("helper access to variable memory: map adjusted, JMP, correct bounds"),
        __success;
    map_adjusted_jmp_wrong_max:
        __description("helper access to variable memory: map adjusted, JMP, wrong max"),
        __failure,
        __msg("R1 min value is outside of the allowed memory range");
    ptr_to_mem_or_null_1:
        __description("helper access to variable memory: size = 0 allowed on NULL (ARG_PTR_TO_MEM_OR_NULL)"),
        __success,
        __retval("0");
    ptr_to_mem_or_null_2:
        __description("helper access to variable memory: size > 0 not allowed on NULL (ARG_PTR_TO_MEM_OR_NULL)"),
        __failure,
        __msg("R1 type=scalar expected=fp");
    ptr_to_mem_or_null_3:
        __description("helper access to variable memory: size = 0 allowed on != NULL stack pointer (ARG_PTR_TO_MEM_OR_NULL)"),
        __success,
        __retval("0");
    ptr_to_mem_or_null_4:
        __description("helper access to variable memory: size = 0 allowed on != NULL map pointer (ARG_PTR_TO_MEM_OR_NULL)"),
        __success,
        __retval("0");
    ptr_to_mem_or_null_5:
        __description("helper access to variable memory: size possible = 0 allowed on != NULL stack pointer (ARG_PTR_TO_MEM_OR_NULL)"),
        __success,
        __retval("0");
    ptr_to_mem_or_null_6:
        __description("helper access to variable memory: size possible = 0 allowed on != NULL map pointer (ARG_PTR_TO_MEM_OR_NULL)"),
        __success,
        __retval("0");
    ptr_to_mem_or_null_7:
        __description("helper access to variable memory: size possible = 0 allowed on != NULL packet pointer (ARG_PTR_TO_MEM_OR_NULL)"),
        __success,
        __retval("0"),
        __flag("BPF_F_ANY_ALIGNMENT");
    ptr_to_mem_or_null_8:
        __description("helper access to variable memory: size = 0 not allowed on NULL (!ARG_PTR_TO_MEM_OR_NULL)"),
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1");
    ptr_to_mem_or_null_9:
        __description("helper access to variable memory: size > 0 not allowed on NULL (!ARG_PTR_TO_MEM_OR_NULL)"),
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1");
    ptr_to_mem_or_null_10:
        __description("helper access to variable memory: size = 0 allowed on != NULL stack pointer (!ARG_PTR_TO_MEM_OR_NULL)"),
        __success;
    ptr_to_mem_or_null_11:
        __description("helper access to variable memory: size = 0 allowed on != NULL map pointer (!ARG_PTR_TO_MEM_OR_NULL)"),
        __success;
    ptr_to_mem_or_null_12:
        __description("helper access to variable memory: size possible = 0 allowed on != NULL stack pointer (!ARG_PTR_TO_MEM_OR_NULL)"),
        __success;
    ptr_to_mem_or_null_13:
        __description("helper access to variable memory: size possible = 0 allowed on != NULL map pointer (!ARG_PTR_TO_MEM_OR_NULL)"),
        __success;
    variable_memory_8_bytes_leak:
        __description("helper access to variable memory: 8 bytes leak"),
        __success,
        __failure_unpriv,
        __msg_unpriv("invalid read from stack R2 off -64+32 size 64"),
        __retval("0");
    bytes_no_leak_init_memory:
        __description("helper access to variable memory: 8 bytes no leak (init memory)"),
        __success;
    writeonly_sized_input:
        __failure,
        __msg("read from map forbidden");
    readwrite_sized_input:
        __success;
    readonly_sized_output:
        __failure,
        __msg("write into map forbidden");
    xdp_writeonly_sized_input:
        __failure,
        __msg("read from map forbidden");
    writeonly_header_option:
        __failure,
        __msg("read from map forbidden");
    readwrite_header_option:
        __success;
    snprintf_writeonly_output:
        __success;
    snprintf_readonly_output:
        __failure,
        __msg("write into map forbidden");
    sysctl_writeonly_output:
        __success,
        __caps_unpriv("39 | 12"),
        __success_unpriv;
    sysctl_initialized_stack:
        __success,
        __caps_unpriv("39 | 12"),
        __success_unpriv;
    sysctl_uninitialized_stack:
        __success,
        __caps_unpriv("39 | 12"),
        __success_unpriv;
    sysctl_partial_initialized_bytes:
        __success,
        __flag("BPF_F_TEST_STATE_FREQ"),
        __caps_unpriv("39 | 12"),
        __success_unpriv;
    sysctl_partial_invalid_bytes:
        __success,
        __caps_unpriv("39 | 12"),
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -1+0 size 1");
    sysctl_partial_variable_size:
        __success,
        __flag("BPF_F_TEST_STATE_FREQ"),
        __caps_unpriv("39 | 12"),
        __success_unpriv;
    sysctl_partial_variable_invalid:
        __success,
        __caps_unpriv("39 | 12"),
        __failure_unpriv,
        __msg_unpriv("invalid read from stack off -1+0 size 1");
    sysctl_partial_spilled_pointer:
        __success,
        __flag("BPF_F_TEST_STATE_FREQ"),
        __caps_unpriv("39 | 12"),
        __failure_unpriv,
        __msg_unpriv("invalid read from stack R2");
    sysctl_partial_dynptr:
        __success,
        __caps_unpriv("39 | 12"),
        __failure_unpriv,
        __msg_unpriv("invalid read from stack R2");
    sysctl_partial_variable_offset:
        __success;
    snprintf_partial_output_runtime:
        __success,
        __retval("42");
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
struct xdp_md {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_sock_ops__anon1 {
    args: [u32; 4],
    reply: u32,
    replylong: [u32; 4],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_sock_ops__anon35 {
    sk: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_sock_ops__anon36 {
    skb_data: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_sock_ops__anon37 {
    skb_data_end: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_sock_ops {
    op: u32,
    __anon1: bpf_sock_ops__anon1,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [u32; 4],
    local_ip6: [u32; 4],
    remote_port: u32,
    local_port: u32,
    is_fullsock: u32,
    snd_cwnd: u32,
    srtt_us: u32,
    bpf_sock_ops_cb_flags: u32,
    state: u32,
    rtt_min: u32,
    snd_ssthresh: u32,
    rcv_nxt: u32,
    snd_nxt: u32,
    snd_una: u32,
    mss_cache: u32,
    ecn_flags: u32,
    rate_delivered: u32,
    rate_interval_us: u32,
    packets_out: u32,
    retrans_out: u32,
    total_retrans: u32,
    segs_in: u32,
    data_segs_in: u32,
    segs_out: u32,
    data_segs_out: u32,
    lost_out: u32,
    sacked_out: u32,
    sk_txhash: u32,
    bytes_received: u64,
    bytes_acked: u64,
    __anon35: bpf_sock_ops__anon35,
    __anon36: bpf_sock_ops__anon36,
    __anon37: bpf_sock_ops__anon37,
    skb_len: u32,
    skb_tcp_flags: u32,
    skb_hwtstamp: u64,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_sysctl {
    write: u32,
    file_pos: u32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct test_val {
    index: u32,
    foo: [i32; 11],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_fib_lookup__anon4 {
    tot_len: u16,
    mtu_result: u16,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_fib_lookup__anon6 {
    tos: u8,
    flowinfo: u32,
    rt_metric: u32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_fib_lookup__anon7 {
    ipv4_src: u32,
    ipv6_src: [u32; 4],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_fib_lookup__anon8 {
    ipv4_dst: u32,
    ipv6_dst: [u32; 4],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_fib_lookup__anon9__anon0 {
    h_vlan_proto: u16,
    h_vlan_TCI: u16,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_fib_lookup__anon9 {
    __anon0: bpf_fib_lookup__anon9__anon0,
    tbid: u32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_fib_lookup__anon10__anon0 {
    mark: u32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_fib_lookup__anon10__anon1 {
    smac: [u8; 6],
    dmac: [u8; 6],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_fib_lookup__anon10 {
    __anon0: bpf_fib_lookup__anon10__anon0,
    __anon1: bpf_fib_lookup__anon10__anon1,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_fib_lookup {
    family: u8,
    l4_protocol: u8,
    sport: u16,
    dport: u16,
    __anon4: bpf_fib_lookup__anon4,
    ifindex: u32,
    __anon6: bpf_fib_lookup__anon6,
    __anon7: bpf_fib_lookup__anon7,
    __anon8: bpf_fib_lookup__anon8,
    __anon9: bpf_fib_lookup__anon9,
    __anon10: bpf_fib_lookup__anon10,
}

bpf_map! {
    map_ringbuf {
        r#type: *const [i32; 27],
        max_entries: *const [i32; 4096],
    }
}

bpf_map! {
    map_hash_48b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const test_val,
    }
}

bpf_map! {
    map_hash_8b {
        r#type: *const [i32; 1],
        max_entries: *const [i32; 1],
        key: *const i64,
        value: *const i64,
    }
}

bpf_map! {
    map_fib_wo {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        map_flags: *const [i32; 256],
        key: *const u32,
        value: *const bpf_fib_lookup,
    }
}

bpf_map! {
    map_fib_rw {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const bpf_fib_lookup,
    }
}

bpf_map! {
    map_fib_ro {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        map_flags: *const [i32; 128],
        key: *const u32,
        value: *const bpf_fib_lookup,
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bitwise_and_jmp_correct_bounds
extern "C" fn bitwise_and_jmp_correct_bounds() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -64;",
            "r0 = 0;",
            "*(u64*)(r10 - 64) = r0;",
            "*(u64*)(r10 - 56) = r0;",
            "*(u64*)(r10 - 48) = r0;",
            "*(u64*)(r10 - 40) = r0;",
            "*(u64*)(r10 - 32) = r0;",
            "*(u64*)(r10 - 24) = r0;",
            "*(u64*)(r10 - 16) = r0;",
            "*(u64*)(r10 - 8) = r0;",
            "r2 = 16;",
            "*(u64*)(r1 - 128) = r2;",
            "r2 = *(u64*)(r1 - 128);",
            "r2 &= 64;",
            "r4 = 0;",
            "if r4 >= r2 goto l0_0;",
            "r3 = 0;",
            "call 113;",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_bitwise_and_zero_included
extern "C" fn stack_bitwise_and_zero_included() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "*(u64*)(r10 - 128) = r6;",
            "call 7;",
            "r3 = r0;",
            "r3 &= 64;",
            "r1 = {map_ringbuf} ll;",
            "r2 = r10;",
            "r2 += -64;",
            "r4 = 0;",
            "call 130;",
            "exit;",
            map_ringbuf = sym map_ringbuf,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bitwise_and_jmp_wrong_max
extern "C" fn bitwise_and_jmp_wrong_max() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64*)(r1 + 8);",
            "r1 = r10;",
            "r1 += -64;",
            "*(u64*)(r1 - 128) = r2;",
            "r2 = *(u64*)(r1 - 128);",
            "r2 &= 65;",
            "r4 = 0;",
            "if r4 >= r2 goto l0_1;",
            "r3 = 0;",
            "call 113;",
            "l0_1:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: memory_stack_jmp_correct_bounds
extern "C" fn memory_stack_jmp_correct_bounds() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -64;",
            "r0 = 0;",
            "*(u64*)(r10 - 64) = r0;",
            "*(u64*)(r10 - 56) = r0;",
            "*(u64*)(r10 - 48) = r0;",
            "*(u64*)(r10 - 40) = r0;",
            "*(u64*)(r10 - 32) = r0;",
            "*(u64*)(r10 - 24) = r0;",
            "*(u64*)(r10 - 16) = r0;",
            "*(u64*)(r10 - 8) = r0;",
            "r2 = 16;",
            "*(u64*)(r1 - 128) = r2;",
            "r2 = *(u64*)(r1 - 128);",
            "if r2 > 64 goto l0_2;",
            "r4 = 0;",
            "if r4 >= r2 goto l0_2;",
            "r3 = 0;",
            "call 113;",
            "l0_2:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_jmp_signed_correct_bounds
extern "C" fn stack_jmp_signed_correct_bounds() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -64;",
            "r0 = 0;",
            "*(u64*)(r10 - 64) = r0;",
            "*(u64*)(r10 - 56) = r0;",
            "*(u64*)(r10 - 48) = r0;",
            "*(u64*)(r10 - 40) = r0;",
            "*(u64*)(r10 - 32) = r0;",
            "*(u64*)(r10 - 24) = r0;",
            "*(u64*)(r10 - 16) = r0;",
            "*(u64*)(r10 - 8) = r0;",
            "r2 = 16;",
            "*(u64*)(r1 - 128) = r2;",
            "r2 = *(u64*)(r1 - 128);",
            "if r2 s> 64 goto l0_3;",
            "r4 = 0;",
            "if r4 s>= r2 goto l0_3;",
            "r3 = 0;",
            "call 113;",
            "l0_3:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: memory_stack_jmp_bounds_offset
extern "C" fn memory_stack_jmp_bounds_offset() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64*)(r1 + 8);",
            "r1 = r10;",
            "r1 += -64;",
            "*(u64*)(r1 - 128) = r2;",
            "r2 = *(u64*)(r1 - 128);",
            "if r2 > 64 goto l0_4;",
            "r4 = 0;",
            "if r4 >= r2 goto l0_4;",
            "r2 += 1;",
            "r3 = 0;",
            "call 113;",
            "l0_4:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: memory_stack_jmp_wrong_max
extern "C" fn memory_stack_jmp_wrong_max() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64*)(r1 + 8);",
            "r1 = r10;",
            "r1 += -64;",
            "*(u64*)(r1 - 128) = r2;",
            "r2 = *(u64*)(r1 - 128);",
            "if r2 > 65 goto l0_5;",
            "r4 = 0;",
            "if r4 >= r2 goto l0_5;",
            "r3 = 0;",
            "call 113;",
            "l0_5:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_jmp_no_max_check
extern "C" fn stack_jmp_no_max_check() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64*)(r1 + 8);",
            "r1 = r10;",
            "r1 += -64;",
            "*(u64*)(r1 - 128) = r2;",
            "r2 = *(u64*)(r1 - 128);",
            "r4 = 0;",
            "if r4 >= r2 goto l0_6;",
            "r3 = 0;",
            "call 113;",
            "l0_6:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_jmp_no_min_check
extern "C" fn stack_jmp_no_min_check() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "*(u64*)(r10 - 128) = r6;",
            "call 7;",
            "r3 = r0;",
            "if r3 > 64 goto l0_7;",
            "r1 = {map_ringbuf} ll;",
            "r2 = r10;",
            "r2 += -64;",
            "r4 = 0;",
            "call 130;",
            "l0_7:",
            "r0 = 0;",
            "exit;",
            map_ringbuf = sym map_ringbuf,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: jmp_signed_no_min_check
extern "C" fn jmp_signed_no_min_check() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64*)(r1 + 8);",
            "r1 = r10;",
            "r1 += -64;",
            "*(u64*)(r1 - 128) = r2;",
            "r2 = *(u64*)(r1 - 128);",
            "if r2 s> 64 goto l0_8;",
            "r3 = 0;",
            "call 113;",
            "r0 = 0;",
            "l0_8:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: memory_map_jmp_correct_bounds
extern "C" fn memory_map_jmp_correct_bounds() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_9;",
            "r1 = r0;",
            "r2 = 48;",
            "*(u64*)(r10 - 128) = r2;",
            "r2 = *(u64*)(r10 - 128);",
            "if r2 s> 48 goto l1_9;",
            "r4 = 0;",
            "if r4 s>= r2 goto l1_9;",
            "r3 = 0;",
            "call 113;",
            "l1_9:",
            "r0 = 0;",
            "l0_9:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: memory_map_jmp_wrong_max
extern "C" fn memory_map_jmp_wrong_max() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64*)(r1 + 8);",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_10;",
            "r1 = r0;",
            "r2 = r6;",
            "*(u64*)(r10 - 128) = r2;",
            "r2 = *(u64*)(r10 - 128);",
            "if r2 s> 49 goto l1_10;",
            "r4 = 0;",
            "if r4 s>= r2 goto l1_10;",
            "r3 = 0;",
            "call 113;",
            "l1_10:",
            "r0 = 0;",
            "l0_10:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_adjusted_jmp_correct_bounds
extern "C" fn map_adjusted_jmp_correct_bounds() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_11;",
            "r1 = r0;",
            "r1 += 20;",
            "r2 = 48;",
            "*(u64*)(r10 - 128) = r2;",
            "r2 = *(u64*)(r10 - 128);",
            "if r2 s> 28 goto l1_11;",
            "r4 = 0;",
            "if r4 s>= r2 goto l1_11;",
            "r3 = 0;",
            "call 113;",
            "l1_11:",
            "r0 = 0;",
            "l0_11:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_adjusted_jmp_wrong_max
extern "C" fn map_adjusted_jmp_wrong_max() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u64*)(r1 + 8);",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = 0;",
            "*(u64*)(r2 + 0) = r1;",
            "r1 = {map_hash_48b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_12;",
            "r1 = r0;",
            "r1 += 20;",
            "r2 = r6;",
            "*(u64*)(r10 - 128) = r2;",
            "r2 = *(u64*)(r10 - 128);",
            "if r2 s> 29 goto l1_12;",
            "r4 = 0;",
            "if r4 s>= r2 goto l1_12;",
            "r3 = 0;",
            "call 113;",
            "l1_12:",
            "r0 = 0;",
            "l0_12:",
            "exit;",
            map_hash_48b = sym map_hash_48b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_1
extern "C" fn ptr_to_mem_or_null_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "r2 = 0;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_2
extern "C" fn ptr_to_mem_or_null_2() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32*)(r1 + 0);",
            "r1 = 0;",
            "*(u64*)(r10 - 128) = r2;",
            "r2 = *(u64*)(r10 - 128);",
            "r2 &= 64;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_3
extern "C" fn ptr_to_mem_or_null_3() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "*(u64*)(r1 + 0) = r2;",
            "r2 &= 8;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_4
extern "C" fn ptr_to_mem_or_null_4() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_13;",
            "r1 = r0;",
            "r2 = 0;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_13:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_5
extern "C" fn ptr_to_mem_or_null_5() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_14;",
            "r2 = *(u64*)(r0 + 0);",
            "if r2 > 8 goto l0_14;",
            "r1 = r10;",
            "r1 += -8;",
            "*(u64*)(r1 + 0) = r2;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_14:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_6
extern "C" fn ptr_to_mem_or_null_6() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_15;",
            "r1 = r0;",
            "r2 = *(u64*)(r0 + 0);",
            "if r2 > 8 goto l0_15;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_15:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_7
extern "C" fn ptr_to_mem_or_null_7() {
    unsafe {
        core::arch::asm!(
            "r6 = *(u32*)(r1 + 76);",
            "r3 = *(u32*)(r1 + 80);",
            "r0 = r6;",
            "r0 += 8;",
            "if r0 > r3 goto l0_16;",
            "r1 = r6;",
            "r2 = *(u64*)(r6 + 0);",
            "if r2 > 8 goto l0_16;",
            "r3 = 0;",
            "r4 = 0;",
            "r5 = 0;",
            "call 28;",
            "l0_16:",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_8
extern "C" fn ptr_to_mem_or_null_8() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "r2 = 0;",
            "r3 = 0;",
            "call 113;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_9
extern "C" fn ptr_to_mem_or_null_9() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "r2 = 1;",
            "r3 = 0;",
            "call 113;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_10
extern "C" fn ptr_to_mem_or_null_10() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r1 += -8;",
            "r2 = 0;",
            "r3 = 0;",
            "call 113;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_11
extern "C" fn ptr_to_mem_or_null_11() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_17;",
            "r1 = r0;",
            "r2 = 0;",
            "r3 = 0;",
            "call 113;",
            "l0_17:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_12
extern "C" fn ptr_to_mem_or_null_12() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_18;",
            "r2 = *(u64*)(r0 + 0);",
            "if r2 > 8 goto l0_18;",
            "r1 = r10;",
            "r1 += -8;",
            "r3 = 0;",
            "call 113;",
            "l0_18:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ptr_to_mem_or_null_13
extern "C" fn ptr_to_mem_or_null_13() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_hash_8b} ll;",
            "call 1;",
            "if r0 == 0 goto l0_19;",
            "r1 = r0;",
            "r2 = *(u64*)(r0 + 0);",
            "if r2 > 8 goto l0_19;",
            "r3 = 0;",
            "call 113;",
            "l0_19:",
            "exit;",
            map_hash_8b = sym map_hash_8b,
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: variable_memory_8_bytes_leak
extern "C" fn variable_memory_8_bytes_leak() {
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "*(u64*)(r10 - 128) = r6;",
            "call 7;",
            "r3 = r0;",
            "r1 = {map_ringbuf} ll;",
            "r2 = r10;",
            "r2 += -64;",
            "r0 = 0;",
            "*(u64*)(r10 - 64) = r0;",
            "*(u64*)(r10 - 56) = r0;",
            "*(u64*)(r10 - 48) = r0;",
            "*(u64*)(r10 - 40) = r0;",
            "*(u64*)(r10 - 24) = r0;",
            "*(u64*)(r10 - 16) = r0;",
            "*(u64*)(r10 - 8) = r0;",
            "r3 &= 63;",
            "r3 += 1;",
            "r4 = 0;",
            "call 130;",
            "r0 = 0;",
            "exit;",
            map_ringbuf = sym map_ringbuf,
            options(nostack)
        );
    }
}

#[link_section = "tracepoint"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bytes_no_leak_init_memory
extern "C" fn bytes_no_leak_init_memory() {
    unsafe {
        core::arch::asm!(
            "r1 = r10;",
            "r0 = 0;",
            "r0 = 0;",
            "*(u64*)(r10 - 64) = r0;",
            "*(u64*)(r10 - 56) = r0;",
            "*(u64*)(r10 - 48) = r0;",
            "*(u64*)(r10 - 40) = r0;",
            "*(u64*)(r10 - 32) = r0;",
            "*(u64*)(r10 - 24) = r0;",
            "*(u64*)(r10 - 16) = r0;",
            "*(u64*)(r10 - 8) = r0;",
            "r1 += -64;",
            "r2 = 0;",
            "r2 &= 32;",
            "r2 += 32;",
            "r3 = 0;",
            "call 113;",
            "r1 = *(u64*)(r10 - 16);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sysctl"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sysctl_initialized_stack
extern "C" fn sysctl_initialized_stack() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 16) = 0;",
            "*(u64 *)(r10 - 8) = 0;",
            "r2 = r10;",
            "r2 += -16;",
            "r3 = 16;",
            "r4 = 0;",
            "call 101;",
            "r0 = *(u8 *)(r10 - 1);",
            "r0 &= 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sysctl"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sysctl_uninitialized_stack
extern "C" fn sysctl_uninitialized_stack() {
    unsafe {
        core::arch::asm!(
            "r2 = r10;",
            "r2 += -16;",
            "r3 = 16;",
            "r4 = 0;",
            "call 101;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sysctl"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sysctl_partial_initialized_bytes
extern "C" fn sysctl_partial_initialized_bytes() {
    unsafe {
        core::arch::asm!(
            "*(u32 *)(r10 - 16) = 0;",
            "*(u8 *)(r10 - 1) = 1;",
            "goto +0;",
            "r2 = r10;",
            "r2 += -16;",
            "r3 = 16;",
            "r4 = 0;",
            "call 101;",
            "r0 = *(u32 *)(r10 - 16);",
            "r1 = *(u8 *)(r10 - 1);",
            "r0 += r1;",
            "r0 &= 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sysctl"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sysctl_partial_invalid_bytes
extern "C" fn sysctl_partial_invalid_bytes() {
    unsafe {
        core::arch::asm!(
            "*(u32 *)(r10 - 16) = 0;",
            "r2 = r10;",
            "r2 += -16;",
            "r3 = 16;",
            "r4 = 0;",
            "call 101;",
            "r0 = *(u8 *)(r10 - 1);",
            "r0 &= 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sysctl"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sysctl_partial_variable_size
extern "C" fn sysctl_partial_variable_size() {
    unsafe {
        core::arch::asm!(
            "r3 = *(u32 *)(r1 + 0);",
            "r3 &= 15;",
            "r3 += 1;",
            "*(u8 *)(r10 - 1) = 1;",
            "goto +0;",
            "r2 = r10;",
            "r2 += -16;",
            "r4 = 0;",
            "call 101;",
            "r0 = *(u8 *)(r10 - 1);",
            "r0 &= 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sysctl"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sysctl_partial_variable_invalid
extern "C" fn sysctl_partial_variable_invalid() {
    unsafe {
        core::arch::asm!(
            "r3 = *(u32 *)(r1 + 0);",
            "r3 &= 15;",
            "r3 += 1;",
            "r2 = r10;",
            "r2 += -16;",
            "r4 = 0;",
            "call 101;",
            "r0 = *(u8 *)(r10 - 1);",
            "r0 &= 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sysctl"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sysctl_partial_spilled_pointer
extern "C" fn sysctl_partial_spilled_pointer() {
    unsafe {
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = r1;",
            "goto +0;",
            "r2 = r10;",
            "r2 += -8;",
            "r3 = 8;",
            "r4 = 0;",
            "call 101;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sysctl"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sysctl_partial_variable_offset
extern "C" fn sysctl_partial_variable_offset() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32 *)(r1 + 0);",
            "r2 &= 8;",
            "r2 += r10;",
            "r2 += -24;",
            "r3 = 16;",
            "r4 = 0;",
            "call 101;",
            "r0 = *(u8 *)(r10 - 16);",
            "r0 &= 1;",
            "exit;",
            options(nostack)
        );
    }
}

include!("hand/verifier_helper_access_var_len.rs");

bpf_object!("GPL");
