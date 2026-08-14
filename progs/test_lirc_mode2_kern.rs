#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_lirc_mode2_kern.c (bpf-rs-core
// idiom). An IR decoder: the ctx is a pointer to one lirc mode2 sample.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_rc_keydown, bpf_rc_pointer_rel};
use core::ffi::c_void;

// uapi/linux/lirc.h
const LIRC_VALUE_MASK: u32 = 0x00FF_FFFF;
const LIRC_MODE2_MASK: u32 = 0xFF00_0000;
const LIRC_MODE2_PULSE: u32 = 0x0100_0000;

#[link_section = "lirc_mode2"]
#[no_mangle]
extern "C" fn bpf_decoder(sample: *mut u32) -> i32 {
    let v = unsafe { core::ptr::read_volatile(sample) };
    if v & LIRC_MODE2_MASK == LIRC_MODE2_PULSE {
        let duration = v & LIRC_VALUE_MASK;
        if duration & 0x1000 != 0 {
            bpf_rc_keydown(
                sample as *const c_void,
                0x40,
                (duration & 0xffff) as u64,
                0,
            );
        }
        if duration & 0x2000 != 0 {
            bpf_rc_pointer_rel(
                sample as *const c_void,
                ((duration >> 8) & 0xff) as i32,
                (duration & 0xff) as i32,
            );
        }
    }
    0
}

bpf_object!("GPL");
