#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/livepatch_trampoline.c

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;

#[no_mangle]
static mut fentry_hit: i32 = 0;
#[no_mangle]
static mut fexit_hit: i32 = 0;
#[no_mangle]
static mut my_pid: i32 = 0;

#[link_section = "fentry/cmdline_proc_show"]
#[no_mangle]
extern "C" fn fentry_cmdline(_ctx: *const u64) -> i32 {
    unsafe {
        if my_pid != (bpf_get_current_pid_tgid() >> 32) as i32 {
            return 0;
        }
        fentry_hit = 1;
    }
    0
}

#[link_section = "fexit/cmdline_proc_show"]
#[no_mangle]
extern "C" fn fexit_cmdline(_ctx: *const u64) -> i32 {
    unsafe {
        if my_pid != (bpf_get_current_pid_tgid() >> 32) as i32 {
            return 0;
        }
        fexit_hit = 1;
    }
    0
}

bpf_object!("GPL");
