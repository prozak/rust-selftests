// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/async_stack_depth.c
// (bpf-rs-core idiom).
//
// Combined-stack-depth rejections for async (timer) callbacks
// (prog_tests/async_stack_depth.c: RUN_TESTS(async_stack_depth)). The C's
// `volatile char buf[N] = {}` locals are 8-byte-aligned frames zeroed with
// write_volatile 8-byte stores (clang expands the initializer into the
// same stores; a plain zeroed array is shrunk to the one byte read) and
// read with read_volatile, so each frame keeps its N bytes; the
// __noinline static chain is #[inline(never)] without #[no_mangle]. The
// __load_if_[no_]large_stack tags pick the 512- or 2 KiB-budget variant
// per JIT.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_timer_set_callback};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_object, test_tags};
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{addr_of_mut, null_mut, read_volatile, write_volatile};

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct hmap_elem {
    timer: bpf_timer,
}

// volatile char buf[N] = {}
#[repr(C, align(8))]
struct Frame<const N: usize>([i8; N]);

#[inline(always)]
unsafe fn zeroed_frame<const N: usize>(buf: &mut MaybeUninit<Frame<N>>) -> *mut i8 {
    let p = buf.as_mut_ptr() as *mut i8;
    let mut off = 0;
    while off + 8 <= N {
        write_volatile(p.add(off) as *mut u64, 0);
        off += 8;
    }
    while off + 4 <= N {
        write_volatile(p.add(off) as *mut u32, 0);
        off += 4;
    }
    while off < N {
        write_volatile(p.add(off), 0);
        off += 1;
    }
    p
}

#[link_section = ".maps"]
#[no_mangle]
static hmap: BpfMap<i32, hmap_elem, { maps::HASH }, 64> = BpfMap::new();

#[inline(never)]
extern "C" fn timer_cb(_map: *mut c_void, _key: *mut i32, _timer: *mut bpf_timer) -> i64 {
    // volatile char buf[256] = {};
    let mut buf = MaybeUninit::<Frame<256>>::uninit();
    let p = unsafe { zeroed_frame(&mut buf) };
    unsafe { read_volatile(p.add(69)) as i64 }
}

#[inline(never)]
extern "C" fn bad_timer_cb(_map: *mut c_void, _key: *mut i32, _timer: *mut bpf_timer) -> i64 {
    // volatile char buf[300] = {};
    let mut buf = MaybeUninit::<Frame<300>>::uninit();
    let p = unsafe { zeroed_frame(&mut buf) };
    unsafe {
        read_volatile(p.add(255)) as i64
            + timer_cb(null_mut(), null_mut(), null_mut())
    }
}

// The same shapes scaled to the 2 KiB budget of JITs with large stacks. The
// compiler caps a single function at 512 bytes, so the depth comes from a
// chain of 480-byte frames.
#[inline(never)]
extern "C" fn timer_cb_large_0(_map: *mut c_void, _key: *mut i32, _timer: *mut bpf_timer) -> i64 {
    // volatile char buf[480] = {};
    let mut buf = MaybeUninit::<Frame<480>>::uninit();
    let p = unsafe { zeroed_frame(&mut buf) };
    unsafe { read_volatile(p.add(69)) as i64 }
}

#[inline(never)]
extern "C" fn timer_cb_large_1(map: *mut c_void, key: *mut i32, timer: *mut bpf_timer) -> i64 {
    let mut buf = MaybeUninit::<Frame<480>>::uninit();
    let p = unsafe { zeroed_frame(&mut buf) };
    unsafe {
        read_volatile(p.add(69)) as i64
            + timer_cb_large_0(map, key, timer)
    }
}

#[inline(never)]
extern "C" fn timer_cb_large_2(map: *mut c_void, key: *mut i32, timer: *mut bpf_timer) -> i64 {
    let mut buf = MaybeUninit::<Frame<480>>::uninit();
    let p = unsafe { zeroed_frame(&mut buf) };
    unsafe {
        read_volatile(p.add(69)) as i64
            + timer_cb_large_1(map, key, timer)
    }
}

#[inline(never)]
extern "C" fn timer_cb_large_3(map: *mut c_void, key: *mut i32, timer: *mut bpf_timer) -> i64 {
    let mut buf = MaybeUninit::<Frame<480>>::uninit();
    let p = unsafe { zeroed_frame(&mut buf) };
    unsafe {
        read_volatile(p.add(69)) as i64
            + timer_cb_large_2(map, key, timer)
    }
}

// 5 * 480 = 2400 bytes on its own
#[inline(never)]
extern "C" fn bad_timer_cb_large(map: *mut c_void, key: *mut i32, timer: *mut bpf_timer) -> i64 {
    let mut buf = MaybeUninit::<Frame<480>>::uninit();
    let p = unsafe { zeroed_frame(&mut buf) };
    unsafe {
        read_volatile(p.add(255)) as i64
            + timer_cb_large_3(map, key, timer)
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn pseudo_call_check(_ctx: *mut __sk_buff) -> i32 {
    // volatile char buf[256] = {};
    let mut buf = MaybeUninit::<Frame<256>>::uninit();
    let p = unsafe { zeroed_frame(&mut buf) };
    let zero: i32 = 0;

    let elem = bpf_map_lookup_elem(&hmap, &zero) as *mut hmap_elem;
    if elem.is_null() {
        return 0;
    }

    unsafe {
        timer_cb(null_mut(), null_mut(), null_mut());
        (bpf_timer_set_callback(addr_of_mut!((*elem).timer), timer_cb)
            + read_volatile(p) as i64) as i32
    }
}

// main plus the four frames under timer_cb_large_3: 2400 bytes
#[link_section = "tc"]
#[no_mangle]
extern "C" fn pseudo_call_check_large(_ctx: *mut __sk_buff) -> i32 {
    let mut buf = MaybeUninit::<Frame<480>>::uninit();
    let p = unsafe { zeroed_frame(&mut buf) };
    let zero: i32 = 0;

    let elem = bpf_map_lookup_elem(&hmap, &zero) as *mut hmap_elem;
    if elem.is_null() {
        return 0;
    }

    unsafe {
        timer_cb_large_3(null_mut(), null_mut(), null_mut());
        (bpf_timer_set_callback(addr_of_mut!((*elem).timer), timer_cb_large_3)
            + read_volatile(p) as i64) as i32
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn async_call_root_check(_ctx: *mut __sk_buff) -> i32 {
    let mut buf = MaybeUninit::<Frame<256>>::uninit();
    let p = unsafe { zeroed_frame(&mut buf) };
    let zero: i32 = 0;

    let elem = bpf_map_lookup_elem(&hmap, &zero) as *mut hmap_elem;
    if elem.is_null() {
        return 0;
    }

    unsafe {
        (bpf_timer_set_callback(addr_of_mut!((*elem).timer), bad_timer_cb)
            + read_volatile(p) as i64) as i32
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn async_call_root_check_large(_ctx: *mut __sk_buff) -> i32 {
    let mut buf = MaybeUninit::<Frame<480>>::uninit();
    let p = unsafe { zeroed_frame(&mut buf) };
    let zero: i32 = 0;

    let elem = bpf_map_lookup_elem(&hmap, &zero) as *mut hmap_elem;
    if elem.is_null() {
        return 0;
    }

    unsafe {
        (bpf_timer_set_callback(addr_of_mut!((*elem).timer), bad_timer_cb_large)
            + read_volatile(p) as i64) as i32
    }
}

test_tags! {
    pseudo_call_check: __load_if_no_large_stack, __failure, __msg("combined stack size of 2 calls is");
    pseudo_call_check_large: __load_if_large_stack, __failure, __msg("combined stack size of 5 calls is");
    async_call_root_check: __load_if_no_large_stack, __failure, __msg("combined stack size of 2 calls is");
    async_call_root_check_large: __load_if_large_stack, __failure, __msg("combined stack size of 5 calls is");
}

bpf_object!("GPL");
