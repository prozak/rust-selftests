#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/cgroup_getset_retval_getsockopt.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_retval, bpf_set_retval, sync_fetch_and_add_u32};

/// UAPI struct bpf_sockopt (linux/bpf.h). sk/optval/optval_end are
/// __bpf_md_ptr unions, represented as u64.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sockopt {
    pub sk: u64,
    pub optval: u64,
    pub optval_end: u64,
    pub level: i32,
    pub optname: i32,
    pub optlen: i32,
    pub retval: i32,
}

const EISCONN: i32 = 106;

#[no_mangle]
static mut invocations: u32 = 0;
#[no_mangle]
static mut assertion_error: u32 = 0;
#[no_mangle]
static mut retval_value: u32 = 0;
#[no_mangle]
static mut ctx_retval_value: u32 = 0;
#[no_mangle]
static mut page_size: u32 = 0;

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn get_retval(ctx: *mut bpf_sockopt) -> i32 {
    unsafe {
        retval_value = bpf_get_retval() as u32;
    }

    let ctx = unsafe { &mut *ctx };
    unsafe {
        ctx_retval_value = ctx.retval as u32;
    }

    sync_fetch_and_add_u32(unsafe { core::ptr::addr_of_mut!(invocations) }, 1);

    if ctx.optlen as u32 > unsafe { page_size } {
        ctx.optlen = 0;
    }

    1
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn set_eisconn(ctx: *mut bpf_sockopt) -> i32 {
    sync_fetch_and_add_u32(unsafe { core::ptr::addr_of_mut!(invocations) }, 1);

    if bpf_set_retval(-EISCONN) != 0 {
        unsafe { assertion_error = 1 };
    }

    let ctx = unsafe { &mut *ctx };
    if ctx.optlen as u32 > unsafe { page_size } {
        ctx.optlen = 0;
    }

    1
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn clear_retval(ctx: *mut bpf_sockopt) -> i32 {
    sync_fetch_and_add_u32(unsafe { core::ptr::addr_of_mut!(invocations) }, 1);

    let ctx = unsafe { &mut *ctx };
    ctx.retval = 0;

    if ctx.optlen as u32 > unsafe { page_size } {
        ctx.optlen = 0;
    }

    1
}

bpf_object!("GPL");
