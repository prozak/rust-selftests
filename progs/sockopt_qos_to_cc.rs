#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/sockopt_qos_to_cc.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_getsockopt, bpf_setsockopt, bpf_strncmp};
use core::ffi::c_void;

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

const SOL_IPV6: i32 = 41;
const IPV6_TCLASS: i32 = 67;
const SOL_TCP: i32 = 6;
const TCP_CONGESTION: i32 = 13;
const TCP_CA_NAME_MAX: usize = 16;

#[no_mangle]
static mut page_size: i32 = 0;

const fn cc_name(s: &[u8]) -> [u8; TCP_CA_NAME_MAX] {
    let mut out = [0u8; TCP_CA_NAME_MAX];
    let mut i = 0;
    while i < s.len() {
        out[i] = s[i];
        i += 1;
    }
    out
}

#[no_mangle]
static cc_reno: [u8; TCP_CA_NAME_MAX] = cc_name(b"reno");
#[no_mangle]
static cc_cubic: [u8; TCP_CA_NAME_MAX] = cc_name(b"cubic");

#[link_section = "cgroup/setsockopt"]
#[no_mangle]
extern "C" fn sockopt_qos_to_cc(ctx: *mut bpf_sockopt) -> i32 {
    let ctx_ref = unsafe { &mut *ctx };

    let optval_end = ctx_ref.optval_end as usize;
    let optval = ctx_ref.optval as *mut i32;

    if ctx_ref.level != SOL_IPV6 || ctx_ref.optname != IPV6_TCLASS {
        if ctx_ref.optlen > unsafe { page_size } {
            ctx_ref.optlen = 0;
        }
        return 1;
    }

    if (optval as usize).wrapping_add(4) > optval_end {
        return 0; /* EPERM, bounds check */
    }

    let mut buf: [u8; TCP_CA_NAME_MAX] = [0; TCP_CA_NAME_MAX];
    if bpf_getsockopt(
        ctx_ref.sk as *mut c_void,
        SOL_TCP,
        TCP_CONGESTION,
        buf.as_mut_ptr() as *mut c_void,
        TCP_CA_NAME_MAX as i32,
    ) != 0
    {
        return 0;
    }

    if bpf_strncmp(
        buf.as_ptr() as *const c_void,
        TCP_CA_NAME_MAX as u32,
        core::ptr::addr_of!(cc_cubic) as *const c_void,
    ) != 0
    {
        return 0;
    }

    if unsafe { *optval } == 0x2d {
        if bpf_setsockopt(
            ctx_ref.sk as *mut c_void,
            SOL_TCP,
            TCP_CONGESTION,
            core::ptr::addr_of!(cc_reno) as *mut c_void,
            TCP_CA_NAME_MAX as i32,
        ) != 0
        {
            return 0;
        }
    }

    1
}

bpf_object!("GPL");
