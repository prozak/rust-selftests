#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str};
use core::ffi::c_void;

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut ret: isize = 0;
// `void *user_ptr = 0;` in C. Rust has no genuine void type; `*mut char`
// (rustc's `char` DWARF-encodes as DW_ATE_UTF, which LLVM's BPF BTF-debug
// pass drops entirely) BTFs as `PTR type_id=0`, the real encoding for
// `void *`, matching the C object byte-for-byte. See test_attach_probe.rs.
#[no_mangle]
static mut user_ptr: *mut char = core::ptr::null_mut();
#[no_mangle]
static mut buf: [u8; 256] = [0; 256];

#[link_section = "tracepoint/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn on_write(_ctx: *const c_void) -> i32 {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    if unsafe { pid } != cur_pid {
        return 0;
    }

    let dst = core::ptr::addr_of_mut!(buf) as *mut c_void;
    let src = unsafe { user_ptr } as *const c_void;
    let r = bpf_probe_read_user_str(dst, 256, src);
    unsafe {
        ret = r as isize;
    }

    0
}

bpf_object!("GPL");
