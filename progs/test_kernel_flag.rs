#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_kernel_flag.c
// (bpf-rs-core idiom).
//
// BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size,
// bool kernel) — only `kernel`, the fourth argument, is read.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use bpf_rs_core::progs::fentry_arg;

const EINVAL: i32 = 22;

#[no_mangle]
static mut monitored_tid: u32 = 0;

#[link_section = "lsm.s/bpf"]
#[no_mangle]
extern "C" fn bpf(ctx: *const u64) -> i32 {
    let tid = (bpf_get_current_pid_tgid() & 0xFFFF_FFFF) as u32;
    // C's `kernel` is a `bool` parameter, and converting an integer to bool
    // tests the WHOLE value, so `!kernel` is a compare against the full
    // 64-bit argument slot rather than its low byte.
    let kernel = fentry_arg(ctx, 3);
    if kernel == 0 || tid != unsafe { monitored_tid } {
        0
    } else {
        -EINVAL
    }
}

bpf_object!("GPL");
