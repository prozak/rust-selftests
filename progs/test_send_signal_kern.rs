#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_send_signal_kern.c,
// bpf-rs-core idiom.

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_send_signal, bpf_send_signal_thread,
};

const PIDTYPE_PID: i32 = 0;
const PIDTYPE_TGID: i32 = 1;

#[repr(C)]
struct task_struct {
    _opaque: [u8; 0],
}

extern "C" {
    fn bpf_task_from_pid(pid: i32) -> *mut task_struct;
    fn bpf_task_release(p: *mut task_struct);
    fn bpf_send_signal_task(task: *mut task_struct, sig: i32, r#type: i32, value: u64) -> i32;
}

#[no_mangle]
static mut sig: u32 = 0;
#[no_mangle]
static mut pid: u32 = 0;
#[no_mangle]
static mut status: u32 = 0;
#[no_mangle]
static mut signal_thread: u32 = 0;
#[no_mangle]
static mut target_pid: u32 = 0;

#[inline(always)]
fn bpf_send_signal_test() -> i32 {
    let cur_status = unsafe { status };
    let cur_pid = unsafe { pid };
    let cur_target_pid = unsafe { target_pid };
    let cur_sig = unsafe { sig };
    let cur_signal_thread = unsafe { signal_thread };

    let mut target_task: *mut task_struct = core::ptr::null_mut();

    if cur_status != 0 || cur_pid == 0 {
        return 0;
    }

    if (bpf_get_current_pid_tgid() >> 32) as u32 == cur_pid {
        let mut value: u64 = 0;

        if cur_target_pid != 0 {
            target_task = unsafe { bpf_task_from_pid(cur_target_pid as i32) };
            if target_task.is_null() {
                return 0;
            }
            value = 8;
        }

        let ret: i64 = if cur_signal_thread != 0 {
            if cur_target_pid != 0 {
                (unsafe { bpf_send_signal_task(target_task, cur_sig as i32, PIDTYPE_PID, value) })
                    as i64
            } else {
                bpf_send_signal_thread(cur_sig)
            }
        } else if cur_target_pid != 0 {
            (unsafe { bpf_send_signal_task(target_task, cur_sig as i32, PIDTYPE_TGID, value) })
                as i64
        } else {
            bpf_send_signal(cur_sig)
        };

        if ret == 0 {
            unsafe { status = 1 };
        }
    }

    if !target_task.is_null() {
        unsafe { bpf_task_release(target_task) };
    }

    0
}

#[link_section = "tracepoint/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn send_signal_tp(_ctx: *const core::ffi::c_void) -> i32 {
    bpf_send_signal_test()
}

#[link_section = "tracepoint/sched/sched_switch"]
#[no_mangle]
extern "C" fn send_signal_tp_sched(_ctx: *const core::ffi::c_void) -> i32 {
    bpf_send_signal_test()
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn send_signal_perf(_ctx: *const core::ffi::c_void) -> i32 {
    bpf_send_signal_test()
}

// The C source names the license global `__license` (not the usual
// `LICENSE`); bpf_rs_core::bpf_object! always emits `_license`, which
// mismatches this prog's internalize keep-list and gets DCE'd on a fresh
// .corig, so hand-write the matching symbol instead (see
// bpf_object-macro-license-symbol-mismatch memory).
#[link_section = "license"]
#[no_mangle]
static __license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
