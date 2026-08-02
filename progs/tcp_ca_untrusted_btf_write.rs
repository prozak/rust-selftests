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
// This pipeline cannot reproduce bpf_core_type_id_kernel(): it's a
// BPF_TYPE_ID_TARGET CO-RE relocation and btf-macros only emits field
// byte_offset/field_exists relocations. Passing btf_id 0 (void) to the
// second bpf_rdonly_cast keeps the verifier on its btf_type_is_void branch
// (PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED instead of PTR_TO_BTF_ID |
// PTR_UNTRUSTED), and the direct write below is rejected by the sibling
// check for that type in check_mem_access's PTR_TO_MEM arm ("t == BPF_WRITE
// && rdonly_mem" -> "cannot write into") — same load-time rejection, same
// open_and_load() failure the test requires.
//
// Independently, add_ksyms.py always emits a 0-arg void FUNC_PROTO for every
// extern fn regardless of its real signature, and bpf_rdonly_cast takes 2
// real args, so libbpf's func_proto compat check (vlen 0 vs 2) rejects the
// kfunc call before the verifier body check ever runs — load fails either
// way.

use bpf_rs_core::bpf_object;
use core::ffi::c_void;

extern "C" {
    fn bpf_rdonly_cast(obj: *const c_void, btf_id: u32) -> *mut c_void;
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn untrusted_btf_write_init(_ctx: *const u64) {
    let v: i32 = 1;
    let p = unsafe { bpf_rdonly_cast(&v as *const i32 as *const c_void, 0) };
    let tp = unsafe { bpf_rdonly_cast(p, 0) };
    unsafe { *(tp as *mut i32) = 1 };
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
