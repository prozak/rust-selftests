// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// BTF_KSYM: bpf_testmod_ksym_percpu
// BTF_WEAK_KFUNC: bpf_testmod_invalid_mod_kfunc

// Direct translation of tools/testing/selftests/bpf/progs/test_ksyms_module.c
// (bpf-rs-core idiom): bpf_testmod's per-cpu variable `bpf_testmod_ksym_percpu`
// through BTF_KSYM and bpf_this_cpu_ptr, and its test kfuncs.

use core::ffi::c_void;
use core::ptr::read_volatile;

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_this_cpu_ptr;

extern "C" {
    static bpf_testmod_ksym_percpu: i32;
    fn bpf_testmod_test_mod_kfunc(i: i32);
    fn bpf_testmod_invalid_mod_kfunc();
}

#[no_mangle]
static mut out_bpf_testmod_ksym: i32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static x: i32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn load(_skb: *const __sk_buff) -> i32 {
    if unsafe { read_volatile(&x) } != 0 {
        unsafe { bpf_testmod_invalid_mod_kfunc() };
    }
    unsafe { bpf_testmod_test_mod_kfunc(42) };
    let p = bpf_this_cpu_ptr(core::ptr::addr_of!(bpf_testmod_ksym_percpu) as *const c_void) as *const i32;
    unsafe { out_bpf_testmod_ksym = *p };
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn load_256(_skb: *const __sk_buff) -> i32 {
    let mut i = 0;
    while i < 256 {
        unsafe { bpf_testmod_test_mod_kfunc(42) };
        i += 1;
    }
    unsafe { bpf_testmod_test_mod_kfunc(42) };
    0
}

// char LICENSE[] SEC("license") = "GPL": the C names the license variable
// LICENSE, which the keep list derived from the C object requires
// (bpf_object!'s `_license` would be internalized and dropped).
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
