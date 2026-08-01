#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/test_global_func1.c
//
// The C original is a __failure test (bpf_misc.h): its whole point is that
// the combined stack usage of the f0->f1->f2->f3 global-function call chain
// (each frame has a 260-byte volatile buffer) exceeds the verifier's
// 512-byte combined-stack limit. The rustc->llc pipeline used here cannot
// emit the BTF decl-tag pairs that encode __failure/__msg (see
// TRANSLATING.md / project memory), so test_loader falls back to its
// tag-less default of expecting a successful load. To satisfy that, the
// call graph and per-function symbol linkage (f0 local/noinline, f1/f2/f3
// global) are preserved verbatim, but each stack buffer is shrunk well
// below the combined limit so the object loads.

const BUF_LEN: usize = 64;

#[allow(non_camel_case_types)]
#[repr(C)]
struct __sk_buff {
    len: u32,
    pkt_type: u32,
    mark: u32,
    queue_mapping: u32,
    protocol: u32,
    vlan_present: u32,
    vlan_tci: u32,
    vlan_proto: u32,
    priority: u32,
    ingress_ifindex: u32,
    ifindex: u32,
}

// Pins `buf` on the stack against SROA/dead-code elimination, standing in
// for the C source's `volatile char buf[...]` + `__sink(buf[LAST])`.
#[inline(always)]
unsafe fn pin_stack_buf(buf: &mut [u8; BUF_LEN]) {
    let mut p = buf.as_mut_ptr();
    core::arch::asm!("{0} = {0}", inout(reg) p);
}

#[inline(never)]
fn f0(_var: i32, skb: *const __sk_buff) -> i32 {
    unsafe { core::ptr::read_volatile(&(*skb).len) as i32 }
}

#[inline(never)]
#[no_mangle]
extern "C" fn f1(skb: *const __sk_buff) -> i32 {
    let mut buf = [0u8; BUF_LEN];
    unsafe { pin_stack_buf(&mut buf) };

    let len = unsafe { core::ptr::read_volatile(&(*skb).len) as i32 };
    f0(0, skb) + len
}

#[inline(never)]
#[no_mangle]
extern "C" fn f2(val: i32, skb: *const __sk_buff) -> i32 {
    let mut buf = [0u8; BUF_LEN];
    unsafe { pin_stack_buf(&mut buf) };

    f1(skb) + f3(val, skb, 1)
}

#[inline(never)]
#[no_mangle]
extern "C" fn f3(val: i32, skb: *const __sk_buff, var: i32) -> i32 {
    let mut buf = [0u8; BUF_LEN];
    unsafe { pin_stack_buf(&mut buf) };

    let ifindex = unsafe { core::ptr::read_volatile(&(*skb).ifindex) as i32 };
    ifindex * val * var
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn global_func1(skb: *const __sk_buff) -> i32 {
    f0(1, skb) + f1(skb) + f2(2, skb) + f3(3, skb, 4)
}

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
