// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_load_acquire.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_load_acquire.rs
// (include!d below): load_acquire_from_rdonly_untrusted_mem.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_load_acquire` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: load_acquire_8 load_acquire_16 load_acquire_32 load_acquire_64 load_acquire_with_uninitialized_src_reg load_acquire_with_non_pointer_src_reg load_acquire_misaligned load_acquire_from_ctx_pointer load_acquire_ctx_same_dst_src load_acquire_from_pkt_pointer load_acquire_from_flow_keys_pointer load_acquire_from_sock_pointer load_acquire_from_rdonly_untrusted_mem load_acquire_with_invalid_reg

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    load_acquire_8:
        __description("load-acquire, 8-bit"),
        __success,
        __success_unpriv,
        __retval("0");
    load_acquire_16:
        __description("load-acquire, 16-bit"),
        __success,
        __success_unpriv,
        __retval("0");
    load_acquire_32:
        __description("load-acquire, 32-bit"),
        __success,
        __success_unpriv,
        __retval("0");
    load_acquire_64:
        __description("load-acquire, 64-bit"),
        __success,
        __success_unpriv,
        __retval("0");
    load_acquire_with_uninitialized_src_reg:
        __description("load-acquire with uninitialized src_reg"),
        __failure,
        __failure_unpriv,
        __msg("R2 !read_ok");
    load_acquire_with_non_pointer_src_reg:
        __description("load-acquire with non-pointer src_reg"),
        __failure,
        __failure_unpriv,
        __msg("R1 invalid mem access 'scalar'");
    load_acquire_misaligned:
        __description("misaligned load-acquire"),
        __failure,
        __failure_unpriv,
        __msg("misaligned stack access off"),
        __flag("BPF_F_ANY_ALIGNMENT");
    load_acquire_from_ctx_pointer:
        __description("load-acquire from ctx pointer"),
        __failure,
        __failure_unpriv,
        __msg("BPF_ATOMIC loads from R1 ctx is not allowed");
    load_acquire_ctx_same_dst_src:
        __description("load-acquire from ctx pointer, same dst and src register"),
        __failure,
        __failure_unpriv,
        __msg("BPF_ATOMIC loads from R6 ctx is not allowed");
    load_acquire_from_pkt_pointer:
        __description("load-acquire from pkt pointer"),
        __failure,
        __msg("BPF_ATOMIC loads from R2 pkt is not allowed");
    load_acquire_from_flow_keys_pointer:
        __description("load-acquire from flow_keys pointer"),
        __failure,
        __msg("BPF_ATOMIC loads from R2 flow_keys is not allowed");
    load_acquire_from_sock_pointer:
        __description("load-acquire from sock pointer"),
        __failure,
        __msg("BPF_ATOMIC loads from R2 sock is not allowed");
    load_acquire_from_rdonly_untrusted_mem:
        __description("load-acquire from rdonly_untrusted_mem pointer"),
        __failure,
        __msg("BPF_ATOMIC loads from R{{[0-9]+}} rdonly_untrusted_mem is not allowed");
    load_acquire_with_invalid_reg:
        __description("load-acquire with invalid register R15"),
        __failure,
        __failure_unpriv,
        __msg("R15 is invalid");
}

extern "C" {
    fn bpf_rdonly_cast(a0: *mut c_void, a1: u32) -> *mut c_void;
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_8
extern "C" fn load_acquire_8() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "w1 = 0xfe;",
            "*(u8 *)(r10 - 1) = w1;",
            ".8byte 1103806571219;",
            "if r2 == r1 goto 1f;",
            "r0 = 1;",
            "1:exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_16
extern "C" fn load_acquire_16() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "w1 = 0xfedc;",
            "*(u16 *)(r10 - 2) = w1;",
            ".8byte 1103806505675;",
            "if r2 == r1 goto 1f;",
            "r0 = 1;",
            "1:exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_32
extern "C" fn load_acquire_32() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "w1 = 0xfedcba09;",
            "*(u32 *)(r10 - 4) = w1;",
            ".8byte 1103806374595;",
            "if r2 == r1 goto 1f;",
            "r0 = 1;",
            "1:exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_64
extern "C" fn load_acquire_64() {
    unsafe {
        core::arch::asm!(
            "r0 = 0;",
            "r1 = 0xfedcba0987654321 ll;",
            "*(u64 *)(r10 - 8) = r1;",
            ".8byte 1103806112475;",
            "if r2 == r1 goto 1f;",
            "r0 = 1;",
            "1:exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_with_uninitialized_src_reg
extern "C" fn load_acquire_with_uninitialized_src_reg() {
    unsafe {
        core::arch::asm!(
            ".8byte 1099511636187;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_with_non_pointer_src_reg
extern "C" fn load_acquire_with_non_pointer_src_reg() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            ".8byte 1099511632091;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_misaligned
extern "C" fn load_acquire_misaligned() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u64 *)(r10 - 8) = r1;",
            ".8byte 1103806308547;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_from_ctx_pointer
extern "C" fn load_acquire_from_ctx_pointer() {
    unsafe {
        core::arch::asm!(
            ".8byte 1099511632083;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_ctx_same_dst_src
extern "C" fn load_acquire_ctx_same_dst_src() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            ".8byte 1099511654083;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_from_pkt_pointer
extern "C" fn load_acquire_from_pkt_pointer() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u32 *)(r1 + 0);",
            "r3 = *(u32 *)(r1 + 4);",
            "r1 = r2;",
            "r1 += 8;",
            "if r1 >= r3 goto l0_0;",
            ".8byte 1099511636179;",
            "l0_0:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "flow_dissector"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_from_flow_keys_pointer
extern "C" fn load_acquire_from_flow_keys_pointer() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64 *)(r1 + 144);",
            ".8byte 1099511636179;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "sk_reuseport"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_from_sock_pointer
extern "C" fn load_acquire_from_sock_pointer() {
    unsafe {
        core::arch::asm!(
            "r2 = *(u64 *)(r1 + 40);",
            ".8byte 1099511898323;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: load_acquire_with_invalid_reg
extern "C" fn load_acquire_with_invalid_reg() {
    unsafe {
        core::arch::asm!(
            ".8byte 1099511689435;",
            "exit;",
            options(nostack)
        );
    }
}

include!("hand/verifier_load_acquire.rs");

bpf_object!("GPL");
