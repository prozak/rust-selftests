// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tcp_ca_untrusted_btf_write.c
// bpf-rs-core idiom.
//
// Negative test: prog_tests/bpf_tcp_ca.c's test_untrusted_btf_write() asserts
// tcp_ca_untrusted_btf_write__open_and_load() FAILS — this program must not
// load. In the C original, bpf_rdonly_cast(p, bpf_core_type_id_kernel(struct
// tcp_sock)) yields a PTR_TO_BTF_ID|PTR_UNTRUSTED reg, and the verifier
// rejects any direct write through it (verifier.c check_ptr_to_btf_access:
// "atype != BPF_READ && (type_flag(reg->type) & PTR_UNTRUSTED)" -> "only
// read is supported" — fires before the specific struct/field/offset is even
// resolved, so which struct type is named doesn't matter to the outcome).
//
// bpf_core_type_id_kernel(struct tcp_sock) is the BTF_TYPE_ID declaration
// below (scripts/type_id.py).

// BTF_TYPE_ID: tid_tcp_sock struct tcp_sock

use bpf_rs_core::bpf_object;
use btf_macros::btf;
use core::ffi::c_void;

extern "C" {
    fn bpf_rdonly_cast(obj: *const c_void, btf_id: u32) -> *mut c_void;
    fn tid_tcp_sock() -> u64;
}

#[btf]
struct tcp_sock {
    snd_cwnd: u32,
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn untrusted_btf_write_init(_ctx: *const u64) {
    let v: i32 = 1;
    let p = unsafe { bpf_rdonly_cast(&v as *const i32 as *const c_void, 0) };
    let tp = unsafe { bpf_rdonly_cast(p, tid_tcp_sock() as u32) } as *mut tcp_sock;
    unsafe { *((*tp).snd_cwnd().as_ptr() as *mut u32) = 1 };
}

// struct tcp_congestion_ops (net/tcp.h): only the members this program
// initializes are declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_congestion_ops {
    init: extern "C" fn(*const u64),
    name: [u8; 16],
}

unsafe impl Sync for tcp_congestion_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static untrusted_btf_write: tcp_congestion_ops = tcp_congestion_ops {
    init: untrusted_btf_write_init,
    name: *b"bpf_ro_btf\0\0\0\0\0\0",
};

bpf_object!("GPL");
