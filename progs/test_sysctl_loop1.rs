#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_sysctl_loop1.c.
//
// Consumed only by prog_tests/bpf_verif_scale.c's test_verif_scale_sysctl_loop1
// -> scale_test("test_sysctl_loop1.bpf.o", BPF_PROG_TYPE_CGROUP_SYSCTL, false),
// which just bpf_object__load()s the program and asserts success -- it never
// attaches or runs it. So correctness here is "the verifier accepts this
// not-unrolled loop", not any particular return value.

use core::ffi::c_void;

use bpf_rs_core::helpers::{bpf_strtoul, bpf_sysctl_get_current_value, bpf_sysctl_get_name};
use bpf_rs_core::{bpf_object, vload, vstore};

// tcp_mem sysctl has only 3 ints, but this test is doing TCP_MEM_LOOPS.
const TCP_MEM_LOOPS: usize = 28; // 30 doesn't fit into 512 bytes of stack
const MAX_ULONG_STR_LEN: usize = 7;
const MAX_VALUE_STR_LEN: usize = TCP_MEM_LOOPS * MAX_ULONG_STR_LEN;

// Kernel matches ctx structs by BTF name for BPF_PROG_TYPE_CGROUP_SYSCTL.
#[repr(C)]
struct bpf_sysctl {
    write: u32,
    file_pos: u32,
}

#[no_mangle]
static tcp_mem_name: [u8; 59] =
    *b"net/ipv4/tcp_mem/very_very_very_very_long_pointless_string\0";

fn is_tcp_mem(ctx: *mut bpf_sysctl) -> i32 {
    let mut name = [0u8; 59]; // sizeof(tcp_mem_name)

    let ret = bpf_sysctl_get_name(ctx, name.as_mut_ptr() as *mut c_void, name.len() as u64, 0);
    if ret < 0 || ret != (name.len() as i64 - 1) {
        return 0;
    }

    let mut i: usize = 0;
    while i < name.len() {
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
    let mut off: usize = 0;
    // A workaround to prevent the compiler from generating code the
    // verifier cannot handle yet (mirrors the C original's `volatile int
    // ret`).
    let mut ret: i64 = 0;

    if unsafe { (*ctx).write } != 0 {
        return 0;
    }

    if is_tcp_mem(ctx) == 0 {
        return 0;
    }

    vstore!(
        ret,
        bpf_sysctl_get_current_value(
            ctx,
            value.as_mut_ptr() as *mut c_void,
            MAX_VALUE_STR_LEN as u64,
        )
    );
    if vload!(ret) < 0 || vload!(ret) >= MAX_VALUE_STR_LEN as i64 {
        return 0;
    }

    let mut i: usize = 0;
    while i < TCP_MEM_LOOPS {
        let mut res: u64 = 0;
        vstore!(
            ret,
            bpf_strtoul(
                unsafe { value.as_ptr().add(off) } as *const c_void,
                MAX_ULONG_STR_LEN as u64,
                0,
                &mut res as *mut u64 as *mut c_void,
            )
        );
        tcp_mem[i] = res;
        if vload!(ret) <= 0 || vload!(ret) > MAX_ULONG_STR_LEN as i64 {
            return 0;
        }
        off = off.wrapping_add((vload!(ret) as usize) & MAX_ULONG_STR_LEN);
        i += 1;
    }

    i32::from(tcp_mem[0] < tcp_mem[1] && tcp_mem[1] < tcp_mem[2])
}

bpf_object!("GPL");
