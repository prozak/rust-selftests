#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/atomics.c
// (bpf-rs-core idiom).
//
// This target's reference object is built with -DENABLE_ATOMICS_TESTS (same
// environment as arena_atomics.rs, see [[arena-programs-blocked-by-addrspace-and-kfunc-proto]]
// history), so skip_tests is false and every atomic op below is live, not
// the C source's `#else bool skip_tests = true;` fallback.
//
// All ops go through core::sync::atomic::Atomic* on a pointer obtained via
// core::ptr::addr_of_mut! and cast to the matching atomic type — the same
// idiom arena_atomics.rs uses for its (arena-backed) globals, minus the
// address-space cast those need and these plain .data/.bss globals don't.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, AtomicU64, Ordering};

#[link_section = ".data"]
#[no_mangle]
static mut skip_tests: bool = false;

#[no_mangle]
static mut pid: u32 = 0;

#[no_mangle]
static mut add64_value: u64 = 1;
#[no_mangle]
static mut add64_result: u64 = 0;
#[no_mangle]
static mut add32_value: u32 = 1;
#[no_mangle]
static mut add32_result: u32 = 0;
#[no_mangle]
static mut add_stack_value_copy: u64 = 0;
#[no_mangle]
static mut add_stack_result: u64 = 0;
#[no_mangle]
static mut add_noreturn_value: u64 = 1;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn add(_ctx: *const c_void) -> i32 {
    unsafe {
        if pid as u64 != (bpf_get_current_pid_tgid() >> 32) {
            return 0;
        }

        let mut add_stack_value: u64 = 1;

        let r = (*(core::ptr::addr_of_mut!(add64_value) as *mut AtomicU64))
            .fetch_add(2, Ordering::SeqCst);
        add64_result = r;

        let r = (*(core::ptr::addr_of_mut!(add32_value) as *mut AtomicU32))
            .fetch_add(2, Ordering::SeqCst);
        add32_result = r;

        let r = (*(core::ptr::addr_of_mut!(add_stack_value) as *mut AtomicU64))
            .fetch_add(2, Ordering::SeqCst);
        add_stack_result = r;
        add_stack_value_copy = add_stack_value;

        (*(core::ptr::addr_of_mut!(add_noreturn_value) as *mut AtomicU64))
            .fetch_add(2, Ordering::SeqCst);
    }
    0
}

#[no_mangle]
static mut sub64_value: i64 = 1;
#[no_mangle]
static mut sub64_result: i64 = 0;
#[no_mangle]
static mut sub32_value: i32 = 1;
#[no_mangle]
static mut sub32_result: i32 = 0;
#[no_mangle]
static mut sub_stack_value_copy: i64 = 0;
#[no_mangle]
static mut sub_stack_result: i64 = 0;
#[no_mangle]
static mut sub_noreturn_value: i64 = 1;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn sub(_ctx: *const c_void) -> i32 {
    unsafe {
        if pid as u64 != (bpf_get_current_pid_tgid() >> 32) {
            return 0;
        }

        let mut sub_stack_value: i64 = 1;

        let r = (*(core::ptr::addr_of_mut!(sub64_value) as *mut AtomicI64))
            .fetch_sub(2, Ordering::SeqCst);
        sub64_result = r;

        let r = (*(core::ptr::addr_of_mut!(sub32_value) as *mut AtomicI32))
            .fetch_sub(2, Ordering::SeqCst);
        sub32_result = r;

        let r = (*(core::ptr::addr_of_mut!(sub_stack_value) as *mut AtomicI64))
            .fetch_sub(2, Ordering::SeqCst);
        sub_stack_result = r;
        sub_stack_value_copy = sub_stack_value;

        (*(core::ptr::addr_of_mut!(sub_noreturn_value) as *mut AtomicI64))
            .fetch_sub(2, Ordering::SeqCst);
    }
    0
}

#[no_mangle]
static mut and64_value: u64 = 0x110u64 << 32;
#[no_mangle]
static mut and64_result: u64 = 0;
#[no_mangle]
static mut and32_value: u32 = 0x110;
#[no_mangle]
static mut and32_result: u32 = 0;
#[no_mangle]
static mut and_noreturn_value: u64 = 0x110u64 << 32;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn and(_ctx: *const c_void) -> i32 {
    unsafe {
        if pid as u64 != (bpf_get_current_pid_tgid() >> 32) {
            return 0;
        }

        let r = (*(core::ptr::addr_of_mut!(and64_value) as *mut AtomicU64))
            .fetch_and(0x011u64 << 32, Ordering::SeqCst);
        and64_result = r;

        let r = (*(core::ptr::addr_of_mut!(and32_value) as *mut AtomicU32))
            .fetch_and(0x011, Ordering::SeqCst);
        and32_result = r;

        (*(core::ptr::addr_of_mut!(and_noreturn_value) as *mut AtomicU64))
            .fetch_and(0x011u64 << 32, Ordering::SeqCst);
    }
    0
}

#[no_mangle]
static mut or64_value: u64 = 0x110u64 << 32;
#[no_mangle]
static mut or64_result: u64 = 0;
#[no_mangle]
static mut or32_value: u32 = 0x110;
#[no_mangle]
static mut or32_result: u32 = 0;
#[no_mangle]
static mut or_noreturn_value: u64 = 0x110u64 << 32;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn or(_ctx: *const c_void) -> i32 {
    unsafe {
        if pid as u64 != (bpf_get_current_pid_tgid() >> 32) {
            return 0;
        }

        let r = (*(core::ptr::addr_of_mut!(or64_value) as *mut AtomicU64))
            .fetch_or(0x011u64 << 32, Ordering::SeqCst);
        or64_result = r;

        let r = (*(core::ptr::addr_of_mut!(or32_value) as *mut AtomicU32))
            .fetch_or(0x011, Ordering::SeqCst);
        or32_result = r;

        (*(core::ptr::addr_of_mut!(or_noreturn_value) as *mut AtomicU64))
            .fetch_or(0x011u64 << 32, Ordering::SeqCst);
    }
    0
}

#[no_mangle]
static mut xor64_value: u64 = 0x110u64 << 32;
#[no_mangle]
static mut xor64_result: u64 = 0;
#[no_mangle]
static mut xor32_value: u32 = 0x110;
#[no_mangle]
static mut xor32_result: u32 = 0;
#[no_mangle]
static mut xor_noreturn_value: u64 = 0x110u64 << 32;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn xor(_ctx: *const c_void) -> i32 {
    unsafe {
        if pid as u64 != (bpf_get_current_pid_tgid() >> 32) {
            return 0;
        }

        let r = (*(core::ptr::addr_of_mut!(xor64_value) as *mut AtomicU64))
            .fetch_xor(0x011u64 << 32, Ordering::SeqCst);
        xor64_result = r;

        let r = (*(core::ptr::addr_of_mut!(xor32_value) as *mut AtomicU32))
            .fetch_xor(0x011, Ordering::SeqCst);
        xor32_result = r;

        (*(core::ptr::addr_of_mut!(xor_noreturn_value) as *mut AtomicU64))
            .fetch_xor(0x011u64 << 32, Ordering::SeqCst);
    }
    0
}

#[no_mangle]
static mut cmpxchg64_value: u64 = 1;
#[no_mangle]
static mut cmpxchg64_result_fail: u64 = 0;
#[no_mangle]
static mut cmpxchg64_result_succeed: u64 = 0;
#[no_mangle]
static mut cmpxchg32_value: u32 = 1;
#[no_mangle]
static mut cmpxchg32_result_fail: u32 = 0;
#[no_mangle]
static mut cmpxchg32_result_succeed: u32 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn cmpxchg(_ctx: *const c_void) -> i32 {
    unsafe {
        if pid as u64 != (bpf_get_current_pid_tgid() >> 32) {
            return 0;
        }

        let p64 = core::ptr::addr_of_mut!(cmpxchg64_value) as *mut AtomicU64;
        let r = (*p64)
            .compare_exchange(0, 3, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap_or_else(|v| v);
        cmpxchg64_result_fail = r;
        let r = (*p64)
            .compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap_or_else(|v| v);
        cmpxchg64_result_succeed = r;

        let p32 = core::ptr::addr_of_mut!(cmpxchg32_value) as *mut AtomicU32;
        let r = (*p32)
            .compare_exchange(0, 3, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap_or_else(|v| v);
        cmpxchg32_result_fail = r;
        let r = (*p32)
            .compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap_or_else(|v| v);
        cmpxchg32_result_succeed = r;
    }
    0
}

#[no_mangle]
static mut xchg64_value: u64 = 1;
#[no_mangle]
static mut xchg64_result: u64 = 0;
#[no_mangle]
static mut xchg32_value: u32 = 1;
#[no_mangle]
static mut xchg32_result: u32 = 0;

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn xchg(_ctx: *const c_void) -> i32 {
    unsafe {
        if pid as u64 != (bpf_get_current_pid_tgid() >> 32) {
            return 0;
        }

        let val64: u64 = 2;
        let val32: u32 = 2;

        let r = (*(core::ptr::addr_of_mut!(xchg64_value) as *mut AtomicU64))
            .swap(val64, Ordering::SeqCst);
        xchg64_result = r;

        let r = (*(core::ptr::addr_of_mut!(xchg32_value) as *mut AtomicU32))
            .swap(val32, Ordering::SeqCst);
        xchg32_result = r;
    }
    0
}

bpf_object!("GPL");
