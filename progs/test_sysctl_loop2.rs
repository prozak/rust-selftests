#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_sysctl_loop2.c, bpf-rs-core idiom.
//
// The only consumer is bpf_verif_scale.c's test_verif_scale_sysctl_loop2(),
// which calls scale_test() -> check_load(): a raw bpf_object__open_file +
// bpf_object__load, no skeleton involved. The contract is just "the object
// loads under BPF_PROG_TYPE_CGROUP_SYSCTL" — no runtime behavior asserted.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_strtoul, bpf_sysctl_get_current_value, bpf_sysctl_get_name};

const TCP_MEM_LOOPS: usize = 20;
const MAX_ULONG_STR_LEN: usize = 7;
const MAX_VALUE_STR_LEN: usize = TCP_MEM_LOOPS * MAX_ULONG_STR_LEN;

// "net/ipv4/tcp_mem/very_very_very_very_long_pointless_string_to_stress_byte_loop" + NUL.
const TCP_MEM_NAME_LEN: usize = 79;

#[repr(C)]
struct bpf_sysctl {
    write: u32,
    file_pos: u32,
}

#[no_mangle]
static tcp_mem_name: [u8; TCP_MEM_NAME_LEN] =
    *b"net/ipv4/tcp_mem/very_very_very_very_long_pointless_string_to_stress_byte_loop\0";

#[inline(never)]
fn is_tcp_mem(ctx: *mut bpf_sysctl) -> i32 {
    let mut name = [0u8; TCP_MEM_NAME_LEN];

    let ret = bpf_sysctl_get_name(
        ctx,
        name.as_mut_ptr() as *mut c_void,
        TCP_MEM_NAME_LEN as u64,
        0,
    );
    if ret < 0 || ret as usize != TCP_MEM_NAME_LEN - 1 {
        return 0;
    }

    let mut i = 0usize;
    while i < TCP_MEM_NAME_LEN {
        if name[i] != tcp_mem_name[i] {
            return 0;
        }
        i += 1;
    }

    1
}

#[link_section = "cgroup/sysctl"]
#[no_mangle]
extern "C" fn sysctl_tcp_mem(ctx: *mut bpf_sysctl) -> i32 {
    let mut tcp_mem = [0u64; TCP_MEM_LOOPS];
    let mut value = [0u8; MAX_VALUE_STR_LEN];

    if unsafe { (*ctx).write } != 0 {
        return 0;
    }

    if is_tcp_mem(ctx) == 0 {
        return 0;
    }

    let ret = bpf_sysctl_get_current_value(
        ctx,
        value.as_mut_ptr() as *mut c_void,
        MAX_VALUE_STR_LEN as u64,
    );
    if ret < 0 || ret as usize >= MAX_VALUE_STR_LEN {
        return 0;
    }

    let mut off: u8 = 0;
    let mut i = 0usize;
    while i < TCP_MEM_LOOPS {
        let ret = bpf_strtoul(
            unsafe { value.as_ptr().add(off as usize) as *const c_void },
            MAX_ULONG_STR_LEN as u64,
            0,
            unsafe { tcp_mem.as_mut_ptr().add(i) as *mut c_void },
        );
        if ret <= 0 || ret > MAX_ULONG_STR_LEN as i64 {
            return 0;
        }
        off = off.wrapping_add((ret as u8) & (MAX_ULONG_STR_LEN as u8));
        i += 1;
    }

    (tcp_mem[0] < tcp_mem[1] && tcp_mem[1] < tcp_mem[2]) as i32
}

bpf_object!("GPL");
