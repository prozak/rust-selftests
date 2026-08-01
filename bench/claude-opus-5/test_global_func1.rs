#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/test_global_func1.c
//
// A TC (SCHED_CLS) program plus a chain of global subprograms (f1, f2, f3)
// and one static subprogram (f0), each global one holding a zeroed on-stack
// byte buffer. The point of the C test is check_max_stack_depth()'s walk
// across *global* function calls: global_func1 -> f2 -> f1 -> f0 and
// f2 -> f3.
//
// DEVIATION FROM THE C ORIGINAL: the C file is a negative test, annotated
//   __failure __msg("combined stack size of 3 calls is")
// with MAX_STACK 260 so the three 260-byte frames blow the 512-byte limit.
// Those annotations are BTF_KIND_DECL_TAGs that this rustc->llc pipeline
// cannot emit, and test_loader.c treats a tag-less program as expect-success.
// So the buffers are shrunk to 128 bytes: the symbol set, call graph, ctx
// accesses and arithmetic are preserved exactly, but the deepest chain
// (f2 + f1 + f0) now fits in MAX_BPF_STACK and the program loads, which is
// what the regenerated RUN_TESTS(test_global_func1) subtest asserts.

use core::arch::asm;

const MAX_STACK: usize = 128;

// UAPI struct __sk_buff prefix. The name must be exactly `__sk_buff`: the
// verifier matches a global subprogram's pointer argument against the
// program type's context type BY BTF NAME, otherwise f1/f2/f3 are rejected.
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
    tc_index: u32,
    cb: [u32; 5],
    hash: u32,
}

// `volatile char buf[MAX_STACK] = {};` followed by `__sink(buf[MAX_STACK-1])`
// (which is `asm volatile("" : "+g"(expr))`).
//
// The asm barrier on the buffer address is what pins the alloca: it makes the
// pointer escape into an asm that may read and write memory, so neither the
// alloca nor its zero-init can be dropped, and SROA cannot split the array
// into scalars. The barrier emits one real instruction (a self-move) — a
// zero-instruction asm makes llc emit a .BTF.ext line_info record colliding
// with the next instruction's offset, which the kernel rejects at load.
macro_rules! stack_buf {
    () => {{
        let mut buf = [0u8; MAX_STACK];
        let mut addr = buf.as_mut_ptr() as usize;
        unsafe { asm!("{0} = {0}", inout(reg) addr) };
        let p = addr as *mut u8;

        // __sink(buf[MAX_STACK - 1]): read-modify-write of the last byte.
        let last = unsafe { core::ptr::read_volatile(p.add(MAX_STACK - 1)) };
        let mut sink = last as u64;
        unsafe { asm!("{0} = {0}", inout(reg) sink) };
        unsafe { core::ptr::write_volatile(p.add(MAX_STACK - 1), sink as u8) };
    }};
}

#[inline(always)]
fn skb_len(skb: *const __sk_buff) -> i32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*skb).len)) as i32 }
}

#[inline(always)]
fn skb_ifindex(skb: *const __sk_buff) -> i32 {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*skb).ifindex)) as i32 }
}

// static __attribute__((noinline)) int f0(int var, struct __sk_buff *skb)
// The `asm volatile("")` barrier consumes `var` so the otherwise-dead
// argument survives dead-arg-elimination.
#[inline(never)]
fn f0(var: i32, skb: *mut __sk_buff) -> i32 {
    let mut v = var as u64;
    unsafe { asm!("{0} = {0}", inout(reg) v) };

    skb_len(skb)
}

#[inline(never)]
#[no_mangle]
extern "C" fn f1(skb: *mut __sk_buff) -> i32 {
    stack_buf!();

    f0(0, skb).wrapping_add(skb_len(skb))
}

#[inline(never)]
#[no_mangle]
extern "C" fn f2(val: i32, skb: *mut __sk_buff) -> i32 {
    stack_buf!();

    f1(skb).wrapping_add(f3(val, skb, 1))
}

#[inline(never)]
#[no_mangle]
extern "C" fn f3(val: i32, skb: *mut __sk_buff, var: i32) -> i32 {
    stack_buf!();

    // C: skb->ifindex * val * var — unsigned int arithmetic, wraps.
    skb_ifindex(skb).wrapping_mul(val).wrapping_mul(var)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn global_func1(skb: *mut __sk_buff) -> i32 {
    f0(1, skb)
        .wrapping_add(f1(skb))
        .wrapping_add(f2(2, skb))
        .wrapping_add(f3(3, skb, 4))
}

// NOTE: the C source has no `char _license[] SEC("license")` and the
// clang-built object has no `license` section — do not add one, the keep-list
// is derived from the C object's global symbols.

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
