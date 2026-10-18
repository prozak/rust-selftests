// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/sk_bypass_prot_mem.c
// (bpf-rs-core idiom). When the test arms tcp_activated/udp_activated, the
// next tcp_init_sock/udp_init_sock sums the protocol's memory_allocated
// counter with the per-CPU forward-alloc counters (the __ksym per-CPU
// variables, walked with bpf_loop over nr_cpus) into
// tcp_memory_allocated/udp_memory_allocated; sock_create sets and reads
// back SK_BPF_BYPASS_PROT_MEM on every new socket of the cgroup.
// bpf_core_cast(sk, struct sock) is bpf_rdonly_cast with the kernel type
// id; the sk->__sk_common.skc_prot->memory_allocated chain is CO-RE through
// #[btf] views. memory_allocated is an atomic_long_t pointer whose only
// member, counter, is at offset 0; the kernel declares the type through an
// anonymous struct typedef, which no #[btf] root can name, so the counter
// is read at the pointer itself. The test takes `bool *` and `long *` to
// the activated flags and the sums, so those keep the C types (isize is
// BTF `long`); the C names its license global LICENSE.
// BTF_TYPE_ID: tid_sock struct sock
// BTF_KSYM: tcp_memory_per_cpu_fw_alloc
// BTF_KSYM: udp_memory_per_cpu_fw_alloc

use core::ffi::c_void;
use core::ptr::{addr_of, addr_of_mut};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_getsockopt, bpf_loop, bpf_per_cpu_ptr, bpf_set_retval, bpf_setsockopt};
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

const SOL_SOCKET: i32 = 1;
const SK_BPF_BYPASS_PROT_MEM: i32 = 1010;
const EINVAL: i32 = 22;

extern "C" {
    static tcp_memory_per_cpu_fw_alloc: i32;
    static udp_memory_per_cpu_fw_alloc: i32;
    fn tid_sock() -> u64;
    fn bpf_rdonly_cast(obj: *const c_void, btf_id: u32) -> *mut c_void;
}

#[no_mangle]
static mut nr_cpus: i32 = 0;
#[no_mangle]
static mut tcp_activated: bool = false;
#[no_mangle]
static mut udp_activated: bool = false;
#[no_mangle]
static mut tcp_memory_allocated: isize = 0;
#[no_mangle]
static mut udp_memory_allocated: isize = 0;

#[allow(non_camel_case_types)]
#[repr(C)]
struct sk_prot {
    memory_allocated: *mut i64,
    memory_per_cpu_fw_alloc: *const i32,
}

#[btf]
struct sock {
    __sk_common: sock_common,
}

#[btf]
struct sock_common {
    skc_prot: *mut proto,
}

#[btf]
struct proto {
    memory_allocated: *mut i64,
}

extern "C" fn drain_memory_per_cpu_fw_alloc(i: u64, sk_prot_ctx: *mut sk_prot) -> i64 {
    unsafe {
        let memory_per_cpu_fw_alloc =
            bpf_per_cpu_ptr((*sk_prot_ctx).memory_per_cpu_fw_alloc as *const c_void, i as u32) as *mut i32;
        if !memory_per_cpu_fw_alloc.is_null() {
            *(*sk_prot_ctx).memory_allocated += *memory_per_cpu_fw_alloc as i64;
        }
    }

    0
}

#[inline(always)]
fn get_memory_allocated(_sk: *const c_void, memory_per_cpu_fw_alloc: *const i32) -> isize {
    unsafe {
        let sk = bpf_rdonly_cast(_sk, tid_sock() as u32) as *const sock;

        /* net_aligned_data.{tcp,udp}_memory_allocated was not available. */
        let skc_prot = *(&*sk).__sk_common().skc_prot().as_ptr();
        let counter = *(&*skc_prot).memory_allocated().as_ptr();
        let mut memory_allocated: i64 = *counter;

        let mut sk_prot_ctx = sk_prot {
            memory_allocated: &mut memory_allocated,
            memory_per_cpu_fw_alloc,
        };

        bpf_loop(nr_cpus as u32, drain_memory_per_cpu_fw_alloc, &mut sk_prot_ctx, 0);

        memory_allocated as isize
    }
}

#[inline(always)]
fn fentry_init_sock(
    sk: *const c_void,
    activated: *mut bool,
    memory_allocated: *mut isize,
    memory_per_cpu_fw_alloc: *const i32,
) {
    unsafe {
        if !*activated {
            return;
        }

        *memory_allocated = get_memory_allocated(sk, memory_per_cpu_fw_alloc);
        *activated = false;
    }
}

// BPF_PROG(fentry_tcp_init_sock, struct sock *sk)
#[link_section = "fentry/tcp_init_sock"]
#[no_mangle]
extern "C" fn fentry_tcp_init_sock(ctx: *const u64) -> i32 {
    fentry_init_sock(
        arg(ctx, 0) as *const c_void,
        addr_of_mut!(tcp_activated),
        addr_of_mut!(tcp_memory_allocated),
        unsafe { addr_of!(tcp_memory_per_cpu_fw_alloc) },
    );
    0
}

// BPF_PROG(fentry_udp_init_sock, struct sock *sk)
#[link_section = "fentry/udp_init_sock"]
#[no_mangle]
extern "C" fn fentry_udp_init_sock(ctx: *const u64) -> i32 {
    fentry_init_sock(
        arg(ctx, 0) as *const c_void,
        addr_of_mut!(udp_activated),
        addr_of_mut!(udp_memory_allocated),
        unsafe { addr_of!(udp_memory_per_cpu_fw_alloc) },
    );
    0
}

#[link_section = "cgroup/sock_create"]
#[no_mangle]
extern "C" fn sock_create(ctx: *mut c_void) -> i32 {
    let mut val: i32 = 1;

    let mut err: i32 = 'err: {
        let err = bpf_setsockopt(ctx, SOL_SOCKET, SK_BPF_BYPASS_PROT_MEM, &val as *const i32 as *const c_void, 4) as i32;
        if err != 0 {
            break 'err err;
        }

        val = 0;

        let err = bpf_getsockopt(ctx, SOL_SOCKET, SK_BPF_BYPASS_PROT_MEM, &mut val as *mut i32 as *mut c_void, 4) as i32;
        if err != 0 {
            break 'err err;
        }

        if val != 1 {
            break 'err -EINVAL;
        }

        return 1;
    };

    // set_if_not_errno_or_zero(err, -EFAULT): err.h's inline assembly, two
    // signed compares the verifier tracks (a C/Rust range test folds into one
    // unsigned compare it cannot, and bpf_set_retval's argument must be
    // provably in [-4095, 0]). The C object moves the int into the 64-bit
    // register the asm compares with `w1 = w0`, which zero-extends: every
    // error becomes -EFAULT there, so the same here (the prover's finding).
    let mut err: i64 = err as u32 as i64;
    unsafe {
        core::arch::asm!(
            "if {0} s< -4095 goto +1",
            "if {0} s<= 0 goto +1",
            "{0} = -14",
            inout(reg) err,
            options(nostack, preserves_flags),
        );
    }
    bpf_set_retval(err as i32);
    0
}

// char LICENSE[] SEC("license") = "GPL";
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
