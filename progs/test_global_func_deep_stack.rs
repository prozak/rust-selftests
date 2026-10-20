// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/test_global_func_deep_stack.c
// (bpf-rs-core idiom). The C builds a 38-deep chain of noinline global
// functions f0..f37 with preprocessor macros; macro_rules! does the same
// here. f0..f32 keep one volatile 8-byte local (a 16-byte frame after the
// verifier's rounding), f33..f37 add a 480-byte volatile buffer. The
// test_loader decl tags are declared with test_tags! and appended to the
// object's BTF by scripts/btf_test_tags.py; the two __failure messages
// count the frames, so the chain depth is exactly the C's.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::sink;
use bpf_rs_core::test_tags;
use core::mem::MaybeUninit;
use core::ptr::{read_volatile, write_volatile};

// C: int f0(unsigned long a) { volatile long b = a + 16; if (a == 0) return 0; return b; }
#[no_mangle]
#[inline(never)]
pub extern "C" fn f0(a: u64) -> i32 {
    let mut b = MaybeUninit::<i64>::uninit();
    unsafe { write_volatile(b.as_mut_ptr(), (a as i64).wrapping_add(16)) };
    if a == 0 {
        return 0;
    }
    unsafe { read_volatile(b.as_ptr()) as i32 }
}

// C: FN(n, prev): int fn(unsigned long a) { volatile long b = fprev(a - 1);
//    if (!b) return 0; return b + 1; }
macro_rules! chain_fn {
    ($name:ident, $prev:ident) => {
        #[no_mangle]
        #[inline(never)]
        pub extern "C" fn $name(a: u64) -> i32 {
            let mut b = MaybeUninit::<i64>::uninit();
            unsafe { write_volatile(b.as_mut_ptr(), $prev(a.wrapping_sub(1)) as i64) };
            if unsafe { read_volatile(b.as_ptr()) } == 0 {
                return 0;
            }
            unsafe { read_volatile(b.as_ptr()).wrapping_add(1) as i32 }
        }
    };
}

// C: FNB(n, prev): same, with `volatile char buf[480] = {};` and
//    `return b + buf[479] + 1;` -- a 480-byte frame to exceed the 2 KiB
//    budget of large stacks. The buffer is kept on the stack the way
//    test_global_func1.rs keeps its MAX_STACK_LARGE buffer: its address
//    escapes through sink(), so the alloca cannot be split or dropped.
macro_rules! chain_fn_big {
    ($name:ident, $prev:ident) => {
        #[no_mangle]
        #[inline(never)]
        pub extern "C" fn $name(a: u64) -> i32 {
            let mut buf = [0u8; 480];
            let mut p = buf.as_mut_ptr();
            sink(&mut p);
            let mut b = MaybeUninit::<i64>::uninit();
            unsafe { write_volatile(b.as_mut_ptr(), $prev(a.wrapping_sub(1)) as i64) };
            if unsafe { read_volatile(b.as_ptr()) } == 0 {
                return 0;
            }
            unsafe {
                read_volatile(b.as_ptr())
                    .wrapping_add(read_volatile(p.add(479)) as i64)
                    .wrapping_add(1) as i32
            }
        }
    };
}

/* Call chain 33 levels deep. */
chain_fn!(f1, f0);
chain_fn!(f2, f1);
chain_fn!(f3, f2);
chain_fn!(f4, f3);
chain_fn!(f5, f4);
chain_fn!(f6, f5);
chain_fn!(f7, f6);
chain_fn!(f8, f7);
chain_fn!(f9, f8);
chain_fn!(f10, f9);
chain_fn!(f11, f10);
chain_fn!(f12, f11);
chain_fn!(f13, f12);
chain_fn!(f14, f13);
chain_fn!(f15, f14);
chain_fn!(f16, f15);
chain_fn!(f17, f16);
chain_fn!(f18, f17);
chain_fn!(f19, f18);
chain_fn!(f20, f19);
chain_fn!(f21, f20);
chain_fn!(f22, f21);
chain_fn!(f23, f22);
chain_fn!(f24, f23);
chain_fn!(f25, f24);
chain_fn!(f26, f25);
chain_fn!(f27, f26);
chain_fn!(f28, f27);
chain_fn!(f29, f28);
chain_fn!(f30, f29);
chain_fn!(f31, f30);
chain_fn!(f32, f31);

/* Same, with a 480-byte frame, to exceed the 2 KiB budget of large stacks. */
chain_fn_big!(f33, f32);
chain_fn_big!(f34, f33);
chain_fn_big!(f35, f34);
chain_fn_big!(f36, f35);
chain_fn_big!(f37, f36);

test_tags! {
    global_func_deep_stack_success: __success;
    global_func_deep_stack_fail: __load_if_no_large_stack, __failure, __msg("combined stack size of 34 calls");
    global_func_deep_stack_fail_large: __failure, __msg("combined stack size of {{[0-9]+}} calls");
}

/* Ensure that even 32 levels deep, the function verifies. */
#[link_section = "syscall"]
#[no_mangle]
pub extern "C" fn global_func_deep_stack_success(_skb: *const __sk_buff) -> i32 {
    f31(55)
}

/*
 * Check we actually honor stack limits (33 * 16 = 528 > 512 = MAX_STACK_DEPTH).
 * The stack depth is 16 because the verifier calls round_up_stack_depth() on
 * the size.
 */
#[link_section = "syscall"]
#[no_mangle]
pub extern "C" fn global_func_deep_stack_fail(_skb: *const __sk_buff) -> i32 {
    f32(123)
}

/*
 * Five 480-byte frames on top of the chain: 5 * 480 + 33 * 16 = 2928 bytes,
 * more than the 2 KiB budget of JITs with large stacks, and more than 512
 * bytes after the second frame everywhere else.
 */
#[link_section = "syscall"]
#[no_mangle]
pub extern "C" fn global_func_deep_stack_fail_large(_skb: *const __sk_buff) -> i32 {
    f37(123)
}

bpf_object!("GPL");
