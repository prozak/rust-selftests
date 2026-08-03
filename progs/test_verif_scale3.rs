#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_verif_scale3.c
// (bpf-rs-core idiom). test_jhash.h's jhash() is inlined here (ATTR noinline
// preserved as #[inline(never)] — the whole point of this test is verifier
// scale: 90 unrolled call sites into one shared noinline hash routine, not
// 90 copies of jhash's own body).

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::{bpf_object, vload, vstore};

const JHASH_INITVAL: u32 = 0xdeadbeef;

#[inline(always)]
fn jhash_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c);
    *a ^= c.rotate_left(4);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= a.rotate_left(6);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= b.rotate_left(8);
    *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c);
    *a ^= c.rotate_left(16);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= a.rotate_left(19);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= b.rotate_left(4);
    *b = b.wrapping_add(*a);
}

#[inline(always)]
fn jhash_final(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = c.wrapping_sub(b.rotate_left(14));
    *a ^= *c;
    *a = a.wrapping_sub(c.rotate_left(11));
    *b ^= *a;
    *b = b.wrapping_sub(a.rotate_left(25));
    *c ^= *b;
    *c = c.wrapping_sub(b.rotate_left(16));
    *a ^= *c;
    *a = a.wrapping_sub(c.rotate_left(4));
    *b ^= *a;
    *b = b.wrapping_sub(a.rotate_left(14));
    *c ^= *b;
    *c = c.wrapping_sub(b.rotate_left(24));
}

#[inline(never)]
fn jhash(key: *const u8, length: u32, initval: u32) -> u32 {
    let mut a = JHASH_INITVAL.wrapping_add(length).wrapping_add(initval);
    let mut b = a;
    let mut c = a;

    let mut k = key;
    let mut len = length;

    while len > 12 {
        unsafe {
            a = a.wrapping_add(core::ptr::read_volatile(k as *const u32));
            b = b.wrapping_add(core::ptr::read_volatile(k.add(4) as *const u32));
            c = c.wrapping_add(core::ptr::read_volatile(k.add(8) as *const u32));
        }
        jhash_mix(&mut a, &mut b, &mut c);
        len -= 12;
        k = unsafe { k.add(12) };
    }

    // C's switch(length) with fallthrough from `case length:` down through
    // `case 1:` (case 0 is a no-op); len is bounded to 0..=12 here.
    unsafe {
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
    }

    c
}

// One `C` macro instantiation from the C source: computes ptr = data + i,
// bails (like the do-while(0)'s `break`) if [ptr, ptr+nh_off) isn't fully
// in bounds, otherwise hashes it and advances i. #[inline(always)] gives
// each of the 90 call sites below its own physical copy, matching the C
// preprocessor's manual unroll (C30;C30;C30).
#[inline(always)]
fn step(ctx: *mut __sk_buff, data: usize, data_end: usize, i: &mut u32) {
    const NH_OFF: usize = 32;

    let ptr = data + (*i as usize);
    if ptr + NH_OFF > data_end {
        return;
    }

    let cb0 = vload!((*ctx).cb[0]);
    let idx = *i;
    *i += 1;

    let h = jhash(ptr as *const u8, NH_OFF as u32, cb0.wrapping_add(idx));
    vstore!((*ctx).tc_index, h);
}

macro_rules! c30 {
    ($ctx:expr, $data:expr, $data_end:expr, $i:expr) => {
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
        step($ctx, $data, $data_end, $i);
    };
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn balancer_ingress(ctx: *mut __sk_buff) -> i32 {
    let data_end = vload!((*ctx).data_end) as usize;
    let data = vload!((*ctx).data) as usize;
    let mut i: u32 = 0;

    // C30;C30;C30; /* 90 calls */
    c30!(ctx, data, data_end, &mut i);
    c30!(ctx, data, data_end, &mut i);
    c30!(ctx, data, data_end, &mut i);

    0
}

bpf_object!("GPL");
