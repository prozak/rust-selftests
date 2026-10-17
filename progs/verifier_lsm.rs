// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_lsm.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_lsm.rs
// (include!d below): no_null_check, null_check, sleepable_lsm_cgroup.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_lsm` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: errno_zero_retval_test1 errno_zero_retval_test2 errno_zero_retval_test4 errno_zero_retval_test5 errno_zero_retval_test6 bool_retval_test1 bool_retval_test2 bool_retval_test3 bool_retval_test4 void_retval_test1 void_retval_test2 disabled_hook_test1 disabled_hook_test2 disabled_hook_test3 no_null_check null_check sleepable_lsm_cgroup retval_load_resets_bounds reject_ctx_write

use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    errno_zero_retval_test1:
        __description("lsm bpf prog with -4095~0 retval. test 1"),
        __success;
    errno_zero_retval_test2:
        __description("lsm bpf prog with -4095~0 retval. test 2"),
        __success;
    errno_zero_retval_test4:
        __description("lsm bpf prog with -4095~0 retval. test 4"),
        __failure,
        __msg("R0 has smin=-4096 smax=-4096 should have been in [-4095, 0]");
    errno_zero_retval_test5:
        __description("lsm bpf prog with -4095~0 retval. test 5"),
        __failure,
        __msg("R0 has smin=4096 smax=4096 should have been in [-4095, 0]");
    errno_zero_retval_test6:
        __description("lsm bpf prog with -4095~0 retval. test 6"),
        __failure,
        __msg("R0 has smin=1 smax=1 should have been in [-4095, 0]");
    bool_retval_test1:
        __description("lsm bpf prog with bool retval. test 1"),
        __success;
    bool_retval_test2:
        __description("lsm bpf prog with bool retval. test 2"),
        __success,
        __success;
    bool_retval_test3:
        __description("lsm bpf prog with bool retval. test 3"),
        __failure,
        __msg("R0 has smin=-1 smax=-1 should have been in [0, 1]");
    bool_retval_test4:
        __description("lsm bpf prog with bool retval. test 4"),
        __failure,
        __msg("R0 has smin=2 smax=2 should have been in [0, 1]");
    void_retval_test1:
        __success,
        __description("lsm bpf prog with void retval. test 1");
    void_retval_test2:
        __success,
        __description("lsm bpf prog with void retval. test 2");
    disabled_hook_test1:
        __description("lsm disabled hook: getprocattr"),
        __failure,
        __msg("points to disabled hook");
    disabled_hook_test2:
        __description("lsm disabled hook: setprocattr"),
        __failure,
        __msg("points to disabled hook");
    disabled_hook_test3:
        __description("lsm disabled hook: ismaclabel"),
        __failure,
        __msg("points to disabled hook");
    no_null_check:
        __description("not null checking nullable pointer in bpf_lsm_mmap_file"),
        __failure,
        __msg("R1 invalid mem access 'trusted_ptr_or_null_'");
    null_check:
        __description("null checking nullable pointer in bpf_lsm_mmap_file"),
        __success;
    sleepable_lsm_cgroup:
        __description("sleepable lsm_cgroup program is rejected"),
        __failure,
        __msg("Program of this type cannot be sleepable"),
        __flag("BPF_F_SLEEPABLE");
    retval_load_resets_bounds:
        __description("lsm retval load must reset stale register bounds"),
        __failure,
        __msg("div by zero");
    reject_ctx_write:
        __description("lsm ctx is read-only"),
        __failure,
        __msg("invalid bpf_context access");
}

#[link_section = "lsm/file_permission"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: errno_zero_retval_test1
extern "C" fn errno_zero_retval_test1(_ctx: *mut c_void) -> i32 {
    let ret: i32;
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

#[link_section = "lsm/file_permission"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: errno_zero_retval_test2
extern "C" fn errno_zero_retval_test2(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = -4095;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm/file_mprotect"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: errno_zero_retval_test4
extern "C" fn errno_zero_retval_test4(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = -4096;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm/file_mprotect"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: errno_zero_retval_test5
extern "C" fn errno_zero_retval_test5(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 4096;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm/file_mprotect"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: errno_zero_retval_test6
extern "C" fn errno_zero_retval_test6(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm/audit_rule_known"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bool_retval_test1
extern "C" fn bool_retval_test1(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm/audit_rule_known"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bool_retval_test2
extern "C" fn bool_retval_test2(_ctx: *mut c_void) -> i32 {
    let ret: i32;
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

#[link_section = "lsm/audit_rule_known"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bool_retval_test3
extern "C" fn bool_retval_test3(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = -1;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm/audit_rule_known"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bool_retval_test4
extern "C" fn bool_retval_test4(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 2;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm/file_free_security"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: void_retval_test1
extern "C" fn void_retval_test1(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = -4096;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm/file_free_security"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: void_retval_test2
extern "C" fn void_retval_test2(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r0 = 4096;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm/getprocattr"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: disabled_hook_test1
extern "C" fn disabled_hook_test1(_ctx: *mut c_void) -> i32 {
    let ret: i32;
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

#[link_section = "lsm/setprocattr"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: disabled_hook_test2
extern "C" fn disabled_hook_test2(_ctx: *mut c_void) -> i32 {
    let ret: i32;
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

#[link_section = "lsm/ismaclabel"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: disabled_hook_test3
extern "C" fn disabled_hook_test3(_ctx: *mut c_void) -> i32 {
    let ret: i32;
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

#[link_section = "lsm/file_mprotect"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: retval_load_resets_bounds
extern "C" fn retval_load_resets_bounds(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "r6 = *(u64 *)(r1 + 24);",
            "if r6 == 0 goto +1;",
            "r6 /= 0;",
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

#[link_section = "lsm/file_mprotect"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reject_ctx_write
extern "C" fn reject_ctx_write(_ctx: *mut c_void) -> i32 {
    let ret: i32;
    unsafe {
        core::arch::asm!(
            "r6 = 0;",
            "*(u64 *)(r1 + 0) = r6;",
            "r0 = 0;",
            "exit;",
            out("r0") ret,
            options(nostack)
        );
    }
    ret
}

include!("hand/verifier_lsm.rs");

bpf_object!("GPL");
