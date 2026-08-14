#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/ksym_race.c
// (bpf-rs-core idiom). The program is expected to FAIL to load once the
// testmod is unloaded — prog_tests/ksyms_module.c races the two — so what
// matters is that it references the module's percpu ksym at all.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_this_cpu_ptr;
use core::ffi::c_void;

unsafe extern "C" {
    static bpf_testmod_ksym_percpu: i32;
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ksym_fail(_ctx: *const __sk_buff) -> i32 {
    let p = bpf_this_cpu_ptr(
        core::ptr::addr_of!(bpf_testmod_ksym_percpu) as *const c_void,
    ) as *const i32;
    unsafe { *p }
}

bpf_object!("GPL");
