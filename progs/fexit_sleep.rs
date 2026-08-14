#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/fexit_sleep.c
// (bpf-rs-core idiom). The test blocks in nanosleep with the fexit program
// attached and then detaches, so both programs only need to count.

#![allow(non_upper_case_globals)]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use core::ffi::c_void;

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut fentry_cnt: i32 = 0;
#[no_mangle]
static mut fexit_cnt: i32 = 0;

#[link_section = "fentry/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn nanosleep_fentry(_ctx: *const c_void) -> i32 {
    // C: `bpf_get_current_pid_tgid() >> 32 != pid` — an int compared
    // against a u64, so the int promotes and the compare is 64-bit
    if (bpf_get_current_pid_tgid() >> 32) as i64 != unsafe { pid } as i64 {
        return 0;
    }
    unsafe { fentry_cnt += 1 };
    0
}

#[link_section = "fexit/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn nanosleep_fexit(_ctx: *const c_void) -> i32 {
    if (bpf_get_current_pid_tgid() >> 32) as i64 != unsafe { pid } as i64 {
        return 0;
    }
    unsafe { fexit_cnt += 1 };
    0
}

bpf_object!("GPL");
