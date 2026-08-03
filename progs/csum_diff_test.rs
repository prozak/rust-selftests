#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/csum_diff_test.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_csum_diff;
use core::ffi::c_void;

const BUFF_SZ: usize = 512;

#[no_mangle]
static mut to_buff: [u8; BUFF_SZ] = [0; BUFF_SZ];

#[link_section = ".rodata"]
#[no_mangle]
static to_buff_len: u32 = 0;

#[no_mangle]
static mut from_buff: [u8; BUFF_SZ] = [0; BUFF_SZ];

#[link_section = ".rodata"]
#[no_mangle]
static from_buff_len: u32 = 0;

#[no_mangle]
static mut seed: u16 = 0;

#[no_mangle]
static mut result: i16 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn compute_checksum(_ctx: *const c_void) -> i32 {
    let to_len = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(to_buff_len)) };
    let from_len = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(from_buff_len)) };
    let to_len_half = to_len / 2;
    let from_len_half = from_len / 2;
    let seed_val = unsafe { seed };

    let from_ptr = unsafe { core::ptr::addr_of!(from_buff) as *const u8 };
    let to_ptr = unsafe { core::ptr::addr_of!(to_buff) as *const u8 };

    // Calculate checksum in one go
    let result2 = bpf_csum_diff(
        from_ptr as *const c_void,
        from_len,
        to_ptr as *const c_void,
        to_len,
        seed_val as u32,
    ) as i16;

    // Calculate checksum by concatenating bpf_csum_diff()
    let mut res = bpf_csum_diff(
        from_ptr as *const c_void,
        from_len - from_len_half,
        to_ptr as *const c_void,
        to_len - to_len_half,
        seed_val as u32,
    ) as i16;

    res = bpf_csum_diff(
        unsafe { from_ptr.add((from_len - from_len_half) as usize) } as *const c_void,
        from_len_half,
        unsafe { to_ptr.add((to_len - to_len_half) as usize) } as *const c_void,
        to_len_half,
        res as i32 as u32,
    ) as i16;

    res = if res == result2 { res } else { 0 };

    unsafe {
        result = res;
    }

    0
}

bpf_object!("GPL");
