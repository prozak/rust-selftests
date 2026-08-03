#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_verif_scale2.c (bpf-rs-core idiom).
//
// A verifier-scale stress test: `balancer_ingress` (SEC("tc")) is a single
// straight-line function that calls the always-inline `jhash` (from the
// sibling test_jhash.h) 90 times in a row (C's `C30;C30;C30` macro
// expansion), each call bounds-checking a moving `data + i` packet pointer
// against `data_end` before hashing 14 bytes and writing the result to
// ctx->tc_index. The point of the test is purely program *size* after
// inlining (~90 duplicated hash bodies) — prog_tests/bpf_verif_scale.c just
// loads the object as BPF_PROG_TYPE_SCHED_CLS and asserts it verifies.
//
// jhash/rol32/jhash_mix/jhash_final are private `#[inline(always)]` helpers
// (matching C's `ATTR __always_inline`) so they collapse into
// balancer_ingress like the C object does, keeping the same single exported
// FUNC symbol. The 90 call sites are emitted via a small macro_rules! step
// (mirrors C's `#define C`/`C30`), not a loop, since the C source is a flat
// unrolled sequence, not a real loop over `i`.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::{vload, vstore};

const JHASH_INITVAL: u32 = 0xdeadbeef;

#[inline(always)]
fn rol32(word: u32, shift: u32) -> u32 {
    (word << shift) | (word >> (shift.wrapping_neg() & 31))
}

#[inline(always)]
fn jhash_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c);
    *a ^= rol32(*c, 4);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= rol32(*a, 6);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= rol32(*b, 8);
    *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c);
    *a ^= rol32(*c, 16);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= rol32(*a, 19);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= rol32(*b, 4);
    *b = b.wrapping_add(*a);
}

#[inline(always)]
fn jhash_final(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = c.wrapping_sub(rol32(*b, 14));
    *a ^= *c;
    *a = a.wrapping_sub(rol32(*c, 11));
    *b ^= *a;
    *b = b.wrapping_sub(rol32(*a, 25));
    *c ^= *b;
    *c = c.wrapping_sub(rol32(*b, 16));
    *a ^= *c;
    *a = a.wrapping_sub(rol32(*c, 4));
    *b ^= *a;
    *b = b.wrapping_sub(rol32(*a, 14));
    *c ^= *b;
    *c = c.wrapping_sub(rol32(*b, 24));
}

// Mirrors test_jhash.h's `jhash()`: while(length > 12) mixes 12-byte
// chunks, then a Duff's-device switch folds the remaining 0..=12 bytes.
// The switch's fallthrough ("case N:" runs N's action plus every lower
// case's action) is equivalent to a sequence of `if length >= N` guards.
#[inline(always)]
unsafe fn jhash(key: *const u8, length: u32, initval: u32) -> u32 {
    let mut a = JHASH_INITVAL.wrapping_add(length).wrapping_add(initval);
    let mut b = a;
    let mut c = a;
    let mut k = key;
    let mut len = length;

    while len > 12 {
        a = a.wrapping_add(core::ptr::read_unaligned(k as *const u32));
        b = b.wrapping_add(core::ptr::read_unaligned(k.add(4) as *const u32));
        c = c.wrapping_add(core::ptr::read_unaligned(k.add(8) as *const u32));
        jhash_mix(&mut a, &mut b, &mut c);
        len -= 12;
        k = k.add(12);
    }

    if len >= 12 {
        c = c.wrapping_add((*k.add(11) as u32) << 24);
    }
    if len >= 11 {
        c = c.wrapping_add((*k.add(10) as u32) << 16);
    }
    if len >= 10 {
        c = c.wrapping_add((*k.add(9) as u32) << 8);
    }
    if len >= 9 {
        c = c.wrapping_add(*k.add(8) as u32);
    }
    if len >= 8 {
        b = b.wrapping_add((*k.add(7) as u32) << 24);
    }
    if len >= 7 {
        b = b.wrapping_add((*k.add(6) as u32) << 16);
    }
    if len >= 6 {
        b = b.wrapping_add((*k.add(5) as u32) << 8);
    }
    if len >= 5 {
        b = b.wrapping_add(*k.add(4) as u32);
    }
    if len >= 4 {
        a = a.wrapping_add((*k.add(3) as u32) << 24);
    }
    if len >= 3 {
        a = a.wrapping_add((*k.add(2) as u32) << 16);
    }
    if len >= 2 {
        a = a.wrapping_add((*k.add(1) as u32) << 8);
    }
    if len >= 1 {
        a = a.wrapping_add(*k as u32);
        c ^= a;
        jhash_final(&mut a, &mut b, &mut c);
    }

    c
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn balancer_ingress(ctx: *mut __sk_buff) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize;
    let data = vload!((*ctx).data) as usize;
    let mut i: i32 = 0;
    let nh_off: i32 = 14;

    // Mirrors C's `#define C`: a single do{}while(0) whose `break` just
    // skips this call's body (there is no enclosing loop in the C source,
    // C30/C is expanded 90 times as flat straight-line code).
    macro_rules! c_step {
        () => {{
            let ptr = data + (i as usize);
            if ptr + (nh_off as usize) <= data_end {
                let cb0 = vload!((*ctx).cb[0]);
                let val = cb0.wrapping_add(i as u32);
                i += 1;
                let h = unsafe { jhash(ptr as *const u8, nh_off as u32, val) };
                vstore!((*ctx).tc_index, h);
            }
        }};
    }

    macro_rules! c30 {
        () => {
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
            c_step!();
        };
    }

    c30!();
    c30!();
    c30!();

    0
}

bpf_object!("GPL");
