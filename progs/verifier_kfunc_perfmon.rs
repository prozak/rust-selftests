// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(linkage)]

// Translation of tools/testing/selftests/bpf/progs/verifier_kfunc_perfmon.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_kfunc_perfmon.rs
// (include!d below): rdonly_cast_noperfmon, probe_read_kernel_dynptr_noperfmon, stream_vprintk_noperfmon, get_kmem_cache_noperfmon, subprog_untrusted_read, arg_untrusted_read_noperfmon.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_kfunc_perfmon` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: rdonly_cast_noperfmon probe_read_kernel_dynptr_noperfmon stream_vprintk_noperfmon get_kmem_cache_noperfmon subprog_untrusted_read arg_untrusted_read_noperfmon

use bpf_rs_core::{arg_tags, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    rdonly_cast_noperfmon:
        __success,
        __caps_unpriv("39"),
        __failure_unpriv,
        __msg_unpriv("bpf_rdonly_cast is allowed only to CAP_PERFMON and CAP_SYS_ADMIN");
    probe_read_kernel_dynptr_noperfmon:
        __success,
        __caps_unpriv("39"),
        __failure_unpriv,
        __msg_unpriv("bpf_probe_read_kernel_dynptr is allowed only to CAP_PERFMON and CAP_SYS_ADMIN");
    stream_vprintk_noperfmon:
        __success,
        __caps_unpriv("39"),
        __failure_unpriv,
        __msg_unpriv("bpf_stream_vprintk is allowed only to CAP_PERFMON and CAP_SYS_ADMIN");
    get_kmem_cache_noperfmon:
        __success,
        __caps_unpriv("39"),
        __failure_unpriv,
        __msg_unpriv("bpf_get_kmem_cache is allowed only to CAP_PERFMON and CAP_SYS_ADMIN");
    arg_untrusted_read_noperfmon:
        __success,
        __caps_unpriv("39"),
        __failure_unpriv,
        __msg_unpriv("rdonly_untrusted_mem access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN");
}

arg_tags! {
    subprog_untrusted_read: 0: "arg:untrusted";
}

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut dynptr_buf: [i8; 8] = [0; 8];

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut user_ptr: *mut c_void = core::ptr::null_mut();

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut kaddr: u64 = 0;

#[link_section = ".rodata.str"]
#[allow(non_upper_case_globals)]
#[export_name = "stream_vprintk_noperfmon.___fmt"]
static stream_vprintk_noperfmon____fmt: [i8; 4] = [37, 112, 66, 0];

extern "C" {
    fn bpf_rdonly_cast(a0: *mut c_void, a1: u32) -> *mut c_void;
    fn bpf_probe_read_kernel_dynptr(a0: *mut c_void, a1: u64, a2: u64, a3: *mut c_void) -> i32;
    fn bpf_stream_vprintk(a0: i32, a1: *mut c_void, a2: *mut c_void, a3: u32) -> i32;
    fn bpf_get_kmem_cache(a0: u64) -> *mut c_void;
}

include!("hand/verifier_kfunc_perfmon.rs");

bpf_object!("GPL");
