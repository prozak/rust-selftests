#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_ksyms.c
// (bpf-rs-core idiom).
//
// Reads the ADDRESSES of four kernel ksyms and publishes them. libbpf
// resolves each `extern ... __ksym` to its kallsyms address at load time;
// bpf_link_fops1 is deliberately non-existent and `__weak`, so it resolves
// to 0 and the test asserts exactly that.
//
// `&__stop_BTF - &__start_BTF` is C pointer arithmetic on `const void *`,
// which gcc/clang treat as byte arithmetic (the GNU void-pointer
// extension), so it is a plain byte difference rather than a scaled one.

#![allow(non_upper_case_globals)]

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

#[no_mangle]
static mut out__bpf_link_fops: u64 = u64::MAX;
#[no_mangle]
static mut out__bpf_link_fops1: u64 = u64::MAX;
#[no_mangle]
static mut out__btf_size: u64 = u64::MAX;
#[no_mangle]
static mut out__per_cpu_start: u64 = u64::MAX;

unsafe extern "C" {
    static bpf_link_fops: c_void;
    static __start_BTF: c_void;
    static __stop_BTF: c_void;
    static __per_cpu_start: c_void;
    // non-existing symbol, weak, defaults to zero
    static bpf_link_fops1: c_void;
}

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler(_ctx: *const c_void) -> i32 {
    unsafe {
        out__bpf_link_fops = core::ptr::addr_of!(bpf_link_fops) as u64;
        out__btf_size = (core::ptr::addr_of!(__stop_BTF) as u64)
            .wrapping_sub(core::ptr::addr_of!(__start_BTF) as u64);
        out__per_cpu_start = core::ptr::addr_of!(__per_cpu_start) as u64;
        out__bpf_link_fops1 = core::ptr::addr_of!(bpf_link_fops1) as u64;
    }
    0
}

bpf_object!("GPL");
