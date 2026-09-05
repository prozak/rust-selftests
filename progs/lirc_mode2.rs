#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/lirc_mode2.c (bpf-rs-core
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
        // Flag bits picked deliberately low: rc-loopback simulates a
        // receiver overflow for any pulse over MS_TO_US(50) (see
        // loop_tx_ir() in rc-loopback.c), which would silently swallow
        // the sample before it ever reaches this decoder.
        if duration & 0x8000 != 0 {
            bpf_rc_keydown(
                sample as *const c_void,
                0x40,
                (duration & 0x3fff) as u64,
                0,
            );
        }
        if duration & 0x4000 != 0 {
            bpf_rc_pointer_rel(
                sample as *const c_void,
                ((duration >> 7) & 0x7f) as i32,
                (duration & 0x7f) as i32,
            );
        }
    }
    0
}

bpf_object!("GPL");
