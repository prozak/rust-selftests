#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_stack_var_off.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use core::ffi::c_void;

#[no_mangle]
static mut probe_res: i32 = 0;

#[no_mangle]
static mut input: [u8; 4] = [0; 4];

#[no_mangle]
static mut test_pid: i32 = 0;

#[link_section = "tracepoint/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn probe(_ctx: *const c_void) -> i32 {
    // This BPF program performs variable-offset reads and writes on a
    // stack-allocated buffer.
    if (bpf_get_current_pid_tgid() >> 32) as u32 != unsafe { test_pid } as u32 {
        return 0;
    }

    let mut stack_buf: [u8; 16] = [0; 16];
    let buf_ptr = stack_buf.as_mut_ptr();
    let input_ptr = core::ptr::addr_of!(input) as *const u8;

    // Copy the input to the stack.
    unsafe {
        for i in 0..4isize {
            core::ptr::write_volatile(buf_ptr.offset(i), core::ptr::read_volatile(input_ptr.offset(i)));
        }
    }

    // The first byte in the buffer indicates the length.
    let len = (unsafe { core::ptr::read_volatile(buf_ptr) } as u64) & 0xf;
    let last = len.wrapping_sub(1) & 0xf;

    // Append something to the buffer. The offset where we write is not
    // statically known; this is a variable-offset stack write.
    unsafe {
        core::ptr::write_volatile(buf_ptr.offset(len as isize), 42);
    }

    // Index into the buffer at an unknown offset. This is a
    // variable-offset stack read.
    //
    // Note that if it wasn't for the preceding variable-offset write, this
    // read would be rejected because the stack slot cannot be verified as
    // being initialized. With the preceding variable-offset write, the
    // stack slot still cannot be verified, but the write inhibits the
    // respective check on the reasoning that, if there was a
    // variable-offset to a higher-or-equal spot, we're probably reading
    // what we just wrote.
    unsafe {
        probe_res = core::ptr::read_volatile(buf_ptr.offset(last as isize)) as i32;
    }

    0
}

bpf_object!("GPL");
