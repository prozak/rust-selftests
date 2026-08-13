#![no_std]
#![no_main]

use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel_str};

use core::ffi::c_void;

const MAX_LEN: usize = 256;

#[no_mangle]
static mut buf_in1: [u8; MAX_LEN] = [0; MAX_LEN];
#[no_mangle]
static mut buf_in2: [u8; MAX_LEN] = [0; MAX_LEN];

#[no_mangle]
static mut test_pid: i32 = 0;
#[no_mangle]
// C's `bool` truthiness test does not compile to one fixed encoding:
// clang emits `jne 0` at some sites and `jne 1` or `(x & 1) != 0` at
// others, even within one file. Store u8 and mirror the compare the C
// object actually made (see TRANSLATING.md, bool-global).
static mut capture: u8 = 0;

/* .bss */
#[no_mangle]
static mut payload1_len1: u64 = 0;
#[no_mangle]
static mut payload1_len2: u64 = 0;
#[no_mangle]
static mut total1: u64 = 0;
#[no_mangle]
static mut payload1: [u8; MAX_LEN + MAX_LEN] = [0; MAX_LEN + MAX_LEN];
#[no_mangle]
static mut ret_bad_read: u64 = 0;

/* .data */
#[no_mangle]
static mut payload2_len1: i32 = -1;
#[no_mangle]
static mut payload2_len2: i32 = -1;
#[no_mangle]
static mut total2: i32 = -1;
#[no_mangle]
static mut payload2: [u8; MAX_LEN + MAX_LEN] = {
    let mut a = [0u8; MAX_LEN + MAX_LEN];
    a[0] = 1;
    a
};

#[no_mangle]
static mut payload3_len1: i32 = -1;
#[no_mangle]
static mut payload3_len2: i32 = -1;
#[no_mangle]
static mut total3: i32 = -1;
#[no_mangle]
static mut payload3: [u8; MAX_LEN + MAX_LEN] = {
    let mut a = [0u8; MAX_LEN + MAX_LEN];
    a[0] = 1;
    a
};

#[no_mangle]
static mut payload4_len1: i32 = -1;
#[no_mangle]
static mut payload4_len2: i32 = -1;
#[no_mangle]
static mut total4: i32 = -1;
#[no_mangle]
static mut payload4: [u8; MAX_LEN + MAX_LEN] = {
    let mut a = [0u8; MAX_LEN + MAX_LEN];
    a[0] = 1;
    a
};

#[no_mangle]
static mut payload_bad: [u8; 5] = [0x42, 0x42, 0x42, 0x42, 0x42];

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler64_unsigned(_regs: *const c_void) -> i32 {
    unsafe {
        let pid = (bpf_get_current_pid_tgid() >> 32) as i32;

        if test_pid != pid || capture & 1 == 0 {
            return 0;
        }

        let base = core::ptr::addr_of_mut!(payload1) as *mut u8;
        let mut payload = base;

        let len = bpf_probe_read_kernel_str(
            payload as *mut c_void,
            MAX_LEN as u32,
            core::ptr::addr_of!(buf_in1) as *const c_void,
        );
        if len >= 0 {
            payload = payload.add(len as usize);
            payload1_len1 = len as u64;
        }

        let len = bpf_probe_read_kernel_str(
            payload as *mut c_void,
            MAX_LEN as u32,
            core::ptr::addr_of!(buf_in2) as *const c_void,
        );
        if len >= 0 {
            payload = payload.add(len as usize);
            payload1_len2 = len as u64;
        }

        total1 = (payload as usize - base as usize) as u64;

        ret_bad_read = bpf_probe_read_kernel_str(
            (core::ptr::addr_of_mut!(payload_bad) as *mut u8).add(2) as *mut c_void,
            1,
            -1i64 as *const c_void,
        ) as u64;
    }
    0
}

#[link_section = "raw_tp/sys_exit"]
#[no_mangle]
extern "C" fn handler64_signed(_regs: *const c_void) -> i32 {
    unsafe {
        let pid = (bpf_get_current_pid_tgid() >> 32) as i32;

        if test_pid != pid || capture & 1 == 0 {
            return 0;
        }

        let base = core::ptr::addr_of_mut!(payload3) as *mut u8;
        let mut payload = base;

        let len = bpf_probe_read_kernel_str(
            payload as *mut c_void,
            MAX_LEN as u32,
            core::ptr::addr_of!(buf_in1) as *const c_void,
        );
        if len >= 0 {
            payload = payload.add(len as usize);
            payload3_len1 = len as i32;
        }

        let len = bpf_probe_read_kernel_str(
            payload as *mut c_void,
            MAX_LEN as u32,
            core::ptr::addr_of!(buf_in2) as *const c_void,
        );
        if len >= 0 {
            payload = payload.add(len as usize);
            payload3_len2 = len as i32;
        }

        total3 = (payload as usize - base as usize) as i32;
    }
    0
}

#[link_section = "tp/raw_syscalls/sys_enter"]
#[no_mangle]
extern "C" fn handler32_unsigned(_regs: *const c_void) -> i32 {
    unsafe {
        let pid = (bpf_get_current_pid_tgid() >> 32) as i32;

        if test_pid != pid || capture & 1 == 0 {
            return 0;
        }

        let base = core::ptr::addr_of_mut!(payload2) as *mut u8;
        let mut payload = base;

        let len = bpf_probe_read_kernel_str(
            payload as *mut c_void,
            MAX_LEN as u32,
            core::ptr::addr_of!(buf_in1) as *const c_void,
        ) as u32;
        if len <= MAX_LEN as u32 {
            payload = payload.add(len as usize);
            payload2_len1 = len as i32;
        }

        let len = bpf_probe_read_kernel_str(
            payload as *mut c_void,
            MAX_LEN as u32,
            core::ptr::addr_of!(buf_in2) as *const c_void,
        ) as u32;
        if len <= MAX_LEN as u32 {
            payload = payload.add(len as usize);
            payload2_len2 = len as i32;
        }

        total2 = (payload as usize - base as usize) as i32;
    }
    0
}

#[link_section = "tp/raw_syscalls/sys_exit"]
#[no_mangle]
extern "C" fn handler32_signed(_regs: *const c_void) -> i32 {
    unsafe {
        let pid = (bpf_get_current_pid_tgid() >> 32) as i32;

        if test_pid != pid || capture & 1 == 0 {
            return 0;
        }

        let base = core::ptr::addr_of_mut!(payload4) as *mut u8;
        let mut payload = base;

        let len = bpf_probe_read_kernel_str(
            payload as *mut c_void,
            MAX_LEN as u32,
            core::ptr::addr_of!(buf_in1) as *const c_void,
        );
        if len >= 0 {
            payload = payload.add(len as usize);
            payload4_len1 = len as i32;
        }

        let len = bpf_probe_read_kernel_str(
            payload as *mut c_void,
            MAX_LEN as u32,
            core::ptr::addr_of!(buf_in2) as *const c_void,
        );
        if len >= 0 {
            payload = payload.add(len as usize);
            payload4_len2 = len as i32;
        }

        total4 = (payload as usize - base as usize) as i32;
    }
    0
}

#[link_section = "tp/syscalls/sys_exit_getpid"]
#[no_mangle]
extern "C" fn handler_exit(_regs: *const c_void) -> i32 {
    use bpf_rs_core::helpers::bpf_probe_read_kernel;

    let mut bla: i64 = 0;
    let ret = bpf_probe_read_kernel(&mut bla, core::mem::size_of::<i64>() as u32, core::ptr::null());
    if ret != 0 {
        1
    } else {
        0
    }
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
