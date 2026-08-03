#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/token_lsm.c

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use bpf_rs_core::progs::fentry_arg as arg;

#[no_mangle]
static mut my_pid: i32 = 0;
#[no_mangle]
static mut reject_capable: i32 = 0;
#[no_mangle]
static mut reject_cmd: i32 = 0;

#[link_section = "lsm/bpf_token_capable"]
#[no_mangle]
extern "C" fn token_capable(ctx: *const u64) -> i32 {
    let _token = arg(ctx, 0);
    let _cap = arg(ctx, 1) as i32;

    let pid = unsafe { my_pid };
    if pid == 0 || pid != (bpf_get_current_pid_tgid() >> 32) as i32 {
        return 0;
    }
    if unsafe { reject_capable } != 0 {
        return -1;
    }
    0
}

#[link_section = "lsm/bpf_token_cmd"]
#[no_mangle]
extern "C" fn token_cmd(ctx: *const u64) -> i32 {
    let _token = arg(ctx, 0);
    let _cmd = arg(ctx, 1) as i32;

    let pid = unsafe { my_pid };
    if pid == 0 || pid != (bpf_get_current_pid_tgid() >> 32) as i32 {
        return 0;
    }
    if unsafe { reject_cmd } != 0 {
        return -1;
    }
    0
}

bpf_object!("GPL");
