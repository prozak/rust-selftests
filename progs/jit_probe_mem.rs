// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/jit_probe_mem.c
// bpf-rs-core idiom.

use core::ptr::addr_of_mut;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_kptr_xchg;
use bpf_rs_core::{bpf_object, btf_type_tags};

#[repr(C)]
struct prog_test_ref_kfunc {
    _opaque: [u8; 0],
}

extern "C" {
    fn bpf_kfunc_call_test_acquire(scalar_ptr: *mut u64) -> *mut prog_test_ref_kfunc;
    fn bpf_kfunc_call_test_release(p: *mut prog_test_ref_kfunc);
}

#[no_mangle]
static mut total_sum: i64 = -1;

// C: static struct prog_test_ref_kfunc __kptr *v;
static mut v: *mut prog_test_ref_kfunc = core::ptr::null_mut();

#[link_section = "tc"]
#[no_mangle]
extern "C" fn test_jit_probe_mem(_ctx: *const __sk_buff) -> i32 {
    let mut zero: u64 = 0;
    let mut p = unsafe { bpf_kfunc_call_test_acquire(&mut zero) };
    if p.is_null() {
        return 1;
    }

    p = bpf_kptr_xchg(unsafe { addr_of_mut!(v) }.cast(), p.cast()).cast();
    if !p.is_null() {
        unsafe {
            bpf_kfunc_call_test_release(p);
        }
        return 1;
    }

    // Direct map value access of kptr, should be PTR_UNTRUSTED
    p = unsafe { v };
    if p.is_null() {
        return 1;
    }

    let sum: u64;
    unsafe {
        core::arch::asm!(
            "r9 = {p};",
            "{sum} = 0;",
            // r8 = p->a
            "r8 = *(u32 *)(r9 + 0);",
            "{sum} += r8;",
            // r8 = p->b
            "r8 = *(u32 *)(r9 + 4);",
            "{sum} += r8;",
            "r9 += 8;",
            // r9 = p->a
            "r9 = *(u32 *)(r9 - 8);",
            "{sum} += r9;",
            p = in(reg) p,
            sum = out(reg) sum,
            out("r8") _,
            out("r9") _,
        );
    }

    unsafe {
        total_sum = sum as i64;
    }
    0
}

btf_type_tags! {
    v: kptr;
}

bpf_object!("GPL");
