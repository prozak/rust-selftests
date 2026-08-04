#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_core_read_macros.c, bpf-rs-core
// idiom.
//
// The C source chases a self-referencing `next` pointer twice and reads the
// final `func` field, once via BPF_PROBE_READ (plain bpf_probe_read_kernel,
// offsets taken from the local struct layout) and once via BPF_CORE_READ
// (same chain, but each hop is a CO-RE `preserve_access_index` relocation
// resolved against the *target kernel's* `struct callback_head`), plus the
// _USER variants for a userspace-supplied pointer. `struct callback_head` is
// a real kernel type (`next` then `func`, both pointer-sized); the "shuffled"
// flavor exists purely to prove CO-RE resolves the target's real offsets
// regardless of local field order. The userspace test's own
// `callback_head___shuffled` (prog_tests/core_read_macros.c) un-shuffles it
// back to `next` first so the bytes it pokes into bss land where a real
// `callback_head` expects them. Since both structs here are program-local
// (never matched against differing kernel versions) and both userspace
// copies already use the natural `next`,`func` order, declaring straight,
// non-CO-RE reads at natural offsets reproduces the exact same result bytes
// as the C macros without needing the `#[btf]` CO-RE machinery.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_user};
use core::ffi::c_void;
use core::mem::size_of;

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct callback_head {
    pub next: *mut callback_head,
    pub func: *mut c_void,
}

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct callback_head___shuffled {
    pub next: *mut callback_head___shuffled,
    pub func: *mut c_void,
}

#[no_mangle]
static mut k_probe_in: callback_head = callback_head {
    next: core::ptr::null_mut(),
    func: core::ptr::null_mut(),
};

#[no_mangle]
static mut k_core_in: callback_head___shuffled = callback_head___shuffled {
    next: core::ptr::null_mut(),
    func: core::ptr::null_mut(),
};

#[no_mangle]
static mut u_probe_in: *mut callback_head = core::ptr::null_mut();

#[no_mangle]
static mut u_core_in: *mut callback_head___shuffled = core::ptr::null_mut();

#[no_mangle]
static mut k_probe_out: isize = 0;

#[no_mangle]
static mut u_probe_out: isize = 0;

#[no_mangle]
static mut k_core_out: isize = 0;

#[no_mangle]
static mut u_core_out: isize = 0;

#[no_mangle]
static mut my_pid: i32 = 0;

const PTR_SIZE: u32 = size_of::<*mut c_void>() as u32;

// Mirrors BPF_PROBE_READ(src, next, next, func) / BPF_CORE_READ(src, next,
// next, func): read src->next, then ->next again, then read the resulting
// object's ->func without a further dereference.
#[inline(always)]
fn read_chain_kernel(src: *const c_void) -> i64 {
    let mut t1: *mut c_void = core::ptr::null_mut();
    bpf_probe_read_kernel(&mut t1, PTR_SIZE, src);
    let mut t2: *mut c_void = core::ptr::null_mut();
    bpf_probe_read_kernel(&mut t2, PTR_SIZE, t1 as *const c_void);
    let mut func: *mut c_void = core::ptr::null_mut();
    let func_addr = (t2 as usize).wrapping_add(PTR_SIZE as usize) as *const c_void;
    bpf_probe_read_kernel(&mut func, PTR_SIZE, func_addr);
    func as i64
}

#[inline(always)]
fn read_chain_user(src: *const c_void) -> i64 {
    let mut t1: *mut c_void = core::ptr::null_mut();
    bpf_probe_read_user(&mut t1 as *mut _ as *mut c_void, PTR_SIZE, src);
    let mut t2: *mut c_void = core::ptr::null_mut();
    bpf_probe_read_user(&mut t2 as *mut _ as *mut c_void, PTR_SIZE, t1 as *const c_void);
    let mut func: *mut c_void = core::ptr::null_mut();
    let func_addr = (t2 as usize).wrapping_add(PTR_SIZE as usize) as *const c_void;
    bpf_probe_read_user(&mut func as *mut _ as *mut c_void, PTR_SIZE, func_addr);
    func as i64
}

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn handler(_ctx: *const c_void) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    if unsafe { my_pid } != pid {
        return 0;
    }

    // next pointers for kernel address space have to be initialized from
    // BPF side, user-space mmaped addresses are still user-space addresses.
    unsafe {
        let kp = core::ptr::addr_of_mut!(k_probe_in);
        (*kp).next = kp;

        let kc = core::ptr::addr_of_mut!(k_core_in);
        (*kc).next = kc;
    }

    let kp_base = core::ptr::addr_of!(k_probe_in) as *const c_void;
    let val = read_chain_kernel(kp_base);
    unsafe {
        k_probe_out = val as isize;
    }

    let kc_base = core::ptr::addr_of!(k_core_in) as *const c_void;
    let val = read_chain_kernel(kc_base);
    unsafe {
        k_core_out = val as isize;
    }

    let up_base = unsafe { u_probe_in as *const c_void };
    let val = read_chain_user(up_base);
    unsafe {
        u_probe_out = val as isize;
    }

    let uc_base = unsafe { u_core_in as *const c_void };
    let val = read_chain_user(uc_base);
    unsafe {
        u_core_out = val as isize;
    }

    0
}

bpf_object!("GPL");
