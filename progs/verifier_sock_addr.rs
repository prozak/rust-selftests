// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/verifier_sock_addr.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_sock_addr.rs
// (include!d below): get_set_sk_priority, recvmsg4_good_return_code, recvmsg4_bad_return_code, recvmsg6_good_return_code, recvmsg6_bad_return_code, recvmsg_unix_good_return_code, recvmsg_unix_bad_return_code, sendmsg4_good_return_code_0, sendmsg4_good_return_code_1, sendmsg4_bad_return_code, sendmsg6_good_return_code_0, sendmsg6_good_return_code_1, sendmsg6_bad_return_code, sendmsg_unix_good_return_code_0, sendmsg_unix_good_return_code_1, sendmsg_unix_bad_return_code, getpeername4_good_return_code, getpeername4_bad_return_code, getpeername6_good_return_code, getpeername6_bad_return_code, getpeername_unix_good_return_code, getpeername_unix_bad_return_code, getsockname4_good_return_code, getsockname4_bad_return_code, getsockname6_good_return_code, getsockname6_bad_return_code, getsockname_unix_good_return_code, getsockname_unix_unix_bad_return_code, bind4_good_return_code_0, bind4_good_return_code_1, bind4_good_return_code_2, bind4_good_return_code_3, bind4_bad_return_code, bind6_good_return_code_0, bind6_good_return_code_1, bind6_good_return_code_2, bind6_good_return_code_3, bind6_bad_return_code, connect4_good_return_code_0, connect4_good_return_code_1, connect4_bad_return_code, connect6_good_return_code_0, connect6_good_return_code_1, connect6_bad_return_code, connect_unix_good_return_code_0, connect_unix_good_return_code_1, connect_unix_bad_return_code.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_sock_addr` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: get_set_sk_priority recvmsg4_good_return_code recvmsg4_bad_return_code recvmsg6_good_return_code recvmsg6_bad_return_code recvmsg_unix_good_return_code recvmsg_unix_bad_return_code sendmsg4_good_return_code_0 sendmsg4_good_return_code_1 sendmsg4_bad_return_code sendmsg6_good_return_code_0 sendmsg6_good_return_code_1 sendmsg6_bad_return_code sendmsg_unix_good_return_code_0 sendmsg_unix_good_return_code_1 sendmsg_unix_bad_return_code getpeername4_good_return_code getpeername4_bad_return_code getpeername6_good_return_code getpeername6_bad_return_code getpeername_unix_good_return_code getpeername_unix_bad_return_code getsockname4_good_return_code getsockname4_bad_return_code getsockname6_good_return_code getsockname6_bad_return_code getsockname_unix_good_return_code getsockname_unix_unix_bad_return_code bind4_good_return_code_0 bind4_good_return_code_1 bind4_good_return_code_2 bind4_good_return_code_3 bind4_bad_return_code bind6_good_return_code_0 bind6_good_return_code_1 bind6_good_return_code_2 bind6_good_return_code_3 bind6_bad_return_code connect4_good_return_code_0 connect4_good_return_code_1 connect4_bad_return_code connect6_good_return_code_0 connect6_good_return_code_1 connect6_bad_return_code connect_unix_good_return_code_0 connect_unix_good_return_code_1 connect_unix_bad_return_code

// the C's anonymous types, named here; scripts/btf_anon.py clears
// the names in the object's BTF
// BTF_ANON

// a `*mut c_void` is the C's `void *` in BTF (scripts/btf_rename.py)
// BTF_C_VOID: c_void

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    recvmsg4_good_return_code:
        __success;
    recvmsg4_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]");
    recvmsg6_good_return_code:
        __success;
    recvmsg6_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]");
    recvmsg_unix_good_return_code:
        __success;
    recvmsg_unix_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]");
    sendmsg4_good_return_code_0:
        __success;
    sendmsg4_good_return_code_1:
        __success;
    sendmsg4_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]");
    sendmsg6_good_return_code_0:
        __success;
    sendmsg6_good_return_code_1:
        __success;
    sendmsg6_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]");
    sendmsg_unix_good_return_code_0:
        __success;
    sendmsg_unix_good_return_code_1:
        __success;
    sendmsg_unix_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]");
    getpeername4_good_return_code:
        __success;
    getpeername4_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]");
    getpeername6_good_return_code:
        __success;
    getpeername6_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]");
    getpeername_unix_good_return_code:
        __success;
    getpeername_unix_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]");
    getsockname4_good_return_code:
        __success;
    getsockname4_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]");
    getsockname6_good_return_code:
        __success;
    getsockname6_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]");
    getsockname_unix_good_return_code:
        __success;
    getsockname_unix_unix_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]");
    bind4_good_return_code_0:
        __success;
    bind4_good_return_code_1:
        __success;
    bind4_good_return_code_2:
        __success;
    bind4_good_return_code_3:
        __success;
    bind4_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=4 smax=4 should have been in [0, 3]");
    bind6_good_return_code_0:
        __success;
    bind6_good_return_code_1:
        __success;
    bind6_good_return_code_2:
        __success;
    bind6_good_return_code_3:
        __success;
    bind6_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=4 smax=4 should have been in [0, 3]");
    connect4_good_return_code_0:
        __success;
    connect4_good_return_code_1:
        __success;
    connect4_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]");
    connect6_good_return_code_0:
        __success;
    connect6_good_return_code_1:
        __success;
    connect6_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]");
    connect_unix_good_return_code_0:
        __success;
    connect_unix_good_return_code_1:
        __success;
    connect_unix_bad_return_code:
        __failure,
        __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_sock_addr__anon9 {
    sk: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_sock_addr {
    user_family: u32,
    user_ip4: u32,
    user_ip6: [u32; 4],
    user_port: u32,
    family: u32,
    r#type: u32,
    protocol: u32,
    msg_src_ip4: u32,
    msg_src_ip6: [u32; 4],
    __anon9: bpf_sock_addr__anon9,
}

include!("hand/verifier_sock_addr.rs");

bpf_object!("GPL");
