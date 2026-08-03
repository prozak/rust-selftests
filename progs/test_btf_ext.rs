#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_btf_ext.c,
// bpf-rs-core idiom. Trivial XDP program with one noinline static helper;
// prog_tests/test_btf_ext.c only checks that the kernel's reported
// line_info/func_info for the loaded program match what libbpf parses out
// of the object's own .BTF.ext, so the exact program body is irrelevant as
// long as the compiled object carries valid line/func BTF.ext records.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::sink;

/// UAPI struct xdp_md (linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

const XDP_DROP: u64 = 1;

// C: static void f0(void) { __u64 a = 1; __sink(a); }
// __sink is `asm volatile("" : "+g"(a))`, a compiler barrier that keeps `a`
// live; replicate with sink() on the address so the write/read cannot be
// optimized away.
#[no_mangle]
#[inline(never)]
extern "C" fn f0() {
    let mut a: u64 = 1;
    let mut p = &mut a as *mut u64;
    sink(&mut p);
    unsafe {
        core::ptr::read_volatile(p);
    }
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn global_func(_xdp: *const xdp_md) -> u64 {
    f0();
    XDP_DROP
}

bpf_object!("GPL");
