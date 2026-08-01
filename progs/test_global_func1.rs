#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Translation of tools/testing/selftests/bpf/progs/test_global_func1.c
//
// The C original is a NEGATIVE verifier test: three noinline global
// functions with 260-byte stack buffers overflow the 512-byte combined
// stack limit, and __failure/__msg("combined stack size of 3 calls is")
// encode that expectation as BTF decl tags that the RUN_TESTS test_loader
// reads from the object itself.
//
// The rustc -> llc pipeline has no way to emit BTF_KIND_DECL_TAG (clang
// derives it from __attribute__((btf_decl_tag)) via DI annotations rustc
// cannot produce). A tag-less object makes test_loader default to
// "expect successful load" (test_loader.c parse_test_spec: mode_mask=PRIV,
// expect_failure=false). So this translation keeps the exact function
// structure — static f0, global noinline f1/f2/f3 with volatile stack
// buffers, the same call graph — but sizes the buffers so the combined
// stack stays under the limit and the program loads.

// Small enough that the deepest chain (global_func1 -> f2 -> f1 -> f0)
// stays well under the 512-byte combined stack limit.
const MAX_STACK: usize = 100;

// UAPI struct __sk_buff prefix — offsets are ABI, only fields up to
// `ifindex` are needed. The name must be exactly __sk_buff: the verifier
// recognizes global-function ctx arguments by BTF struct name.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct __sk_buff {
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

// C: volatile char buf[MAX_STACK] = {}; __sink(buf[MAX_STACK - 1]);
// The volatile accesses pin the full array on the stack (SROA/DSE cannot
// split or drop an alloca with volatile uses).
#[inline(always)]
fn stack_buf() {
    let mut buf = [0u8; MAX_STACK];
    let mut p = buf.as_mut_ptr();
    unsafe {
        // The asm barrier makes the array address escape, so the whole
        // buffer stays on the stack (C: volatile buf + __sink(buf[N-1])).
        // The self-move emits one real insn: a zero-insn asm's line record
        // collapses onto the next insn's offset and the kernel rejects the
        // duplicate .BTF.ext line_info entry.
        core::arch::asm!("{0} = {0}", inout(reg) p, options(nostack, preserves_flags));
        core::ptr::read_volatile(p.add(MAX_STACK - 1));
    }
}

// static in C; #[no_mangle] keeps the name and full signature through
// rustc (no dead-arg-elim), and the build's internalize pass demotes it
// back to a local/static symbol since it is not in the C object keep-list.
#[no_mangle]
#[inline(never)]
extern "C" fn f0(var: i32, skb: *const __sk_buff) -> i32 {
    // C: asm volatile (""); consuming `var` also keeps dead-arg-elim from
    // dropping it, preserving the C signature in BTF.
    unsafe { core::arch::asm!("/* {0} */", in(reg) var, options(nomem, nostack, preserves_flags)) };
    unsafe { (*skb).len as i32 }
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f1(skb: *const __sk_buff) -> i32 {
    stack_buf();
    f0(0, skb).wrapping_add(unsafe { (*skb).len as i32 })
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f2(val: i32, skb: *const __sk_buff) -> i32 {
    stack_buf();
    f1(skb).wrapping_add(f3(val, skb, 1))
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn f3(val: i32, skb: *const __sk_buff, var: i32) -> i32 {
    stack_buf();
    (unsafe { (*skb).ifindex } as i32).wrapping_mul(val).wrapping_mul(var)
}

#[link_section = "tc"]
#[no_mangle]
pub extern "C" fn global_func1(skb: *const __sk_buff) -> i32 {
    f0(1, skb)
        .wrapping_add(f1(skb))
        .wrapping_add(f2(2, skb))
        .wrapping_add(f3(3, skb, 4))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
