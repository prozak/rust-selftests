// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_kfunc_dynptr_param.c,
// bpf-rs-core idiom.
//
// Two NEGATIVE verifier tests on bpf_verify_pkcs7_signature's dynptr
// arguments (prog_tests/kfunc_dynptr_param.c RUN_TESTS this object; the
// `?` sections stay unloaded otherwise): a dynptr pointer at a stack offset
// that cannot hold a 16-byte dynptr (`&val` of an 8-byte local), and a
// dynptr in a function-local static (a map value, not the stack). The
// third program loads and is run by the consumer: it passes invalid flags
// to bpf_dynptr_from_mem and the resulting uninitialized dynptr on. The
// C_LAYOUT marker orders .bss as the C object does (err, pid, then the
// function-local static dynptr at offset 8): the prover's trace observable
// carries the kfunc's .bss pointer argument.

// C_LAYOUT: .bss

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_dynptr_from_mem, bpf_get_current_pid_tgid, bpf_map_lookup_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_map, test_tags};
use core::ffi::c_void;
use core::ptr::addr_of_mut;

const EINVAL: i32 = 22;

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_key {
    _unused: [u8; 0],
}

bpf_map! {
    ringbuf {
        r#type: *const [i32; maps::RINGBUF],
        max_entries: *const [i32; 4096],
    }
}

#[link_section = ".maps"]
#[no_mangle]
static array_map: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut err: i32 = 0;
#[no_mangle]
static mut pid: i32 = 0;

extern "C" {
    fn bpf_verify_pkcs7_signature(data_ptr: *const bpf_dynptr, sig_ptr: *const bpf_dynptr, trusted_keyring: *mut bpf_key) -> i32;
    fn bpf_lookup_system_key(id: u64) -> *mut bpf_key;
    fn bpf_key_put(key: *mut bpf_key);
}

test_tags! {
    not_valid_dynptr: __failure, __msg("cannot pass in dynptr at an offset=-8");
    not_ptr_to_stack: __failure, __msg("R1 type=map_value expected=fp, dynptr_ptr");
}

#[link_section = "?lsm.s/bpf"]
#[no_mangle]
extern "C" fn not_valid_dynptr(_ctx: *const u64) -> i32 {
    let mut val: u64 = 0;
    let p = &mut val as *mut u64 as *const bpf_dynptr;

    unsafe { bpf_verify_pkcs7_signature(p, p, core::ptr::null_mut()) }
}

// C: static struct bpf_dynptr val; (a function-local static in .bss, which
// clang names `____not_ptr_to_stack.val`; the Rust static carries that
// symbol name since translint's layout check and the prover's trace key on
// it, and is called static_val in the source because Rust lets no local
// shadow a static)
#[allow(non_upper_case_globals)]
#[export_name = "____not_ptr_to_stack.val"]
static mut static_val: bpf_dynptr = bpf_dynptr { __opaque: [0; 2] };

#[link_section = "?lsm.s/bpf"]
#[no_mangle]
extern "C" fn not_ptr_to_stack(_ctx: *const u64) -> i32 {
    let p = unsafe { addr_of_mut!(static_val) } as *const bpf_dynptr;

    unsafe { bpf_verify_pkcs7_signature(p, p, core::ptr::null_mut()) }
}

#[link_section = "lsm.s/bpf"]
#[no_mangle]
extern "C" fn dynptr_data_null(_ctx: *const u64) -> i32 {
    let mut ptr = bpf_dynptr { __opaque: [0; 2] };
    let zero: i32 = 0;

    if (bpf_get_current_pid_tgid() >> 32) as i32 != unsafe { pid } {
        return 0;
    }

    let value = bpf_map_lookup_elem(&array_map, &zero) as *mut u32;
    if value.is_null() {
        return 0;
    }

    /* Pass invalid flags. */
    let ret = bpf_dynptr_from_mem(value as *mut c_void, 4, !0u64, &mut ptr as *mut bpf_dynptr as *mut c_void) as i32;
    if ret != -EINVAL {
        return 0;
    }

    let trusted_keyring = unsafe { bpf_lookup_system_key(0) };
    if trusted_keyring.is_null() {
        return 0;
    }

    unsafe { err = bpf_verify_pkcs7_signature(&ptr, &ptr, trusted_keyring) };

    unsafe { bpf_key_put(trusted_keyring) };

    0
}

bpf_object!("GPL");
