#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/sockopt_multi.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;

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

const SOL_IP: i32 = 0;
const IP_TOS: i32 = 1;

#[no_mangle]
static mut page_size: i32 = 0;

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn _getsockopt_child(ctx: *mut bpf_sockopt) -> i32 {
    let ctx = unsafe { &mut *ctx };
    let optval = ctx.optval;
    let optval_end = ctx.optval_end;

    if ctx.level != SOL_IP || ctx.optname != IP_TOS {
        if ctx.optlen > unsafe { page_size } {
            ctx.optlen = 0;
        }
        return 1;
    }

    if optval + 1 > optval_end {
        return 0; /* EPERM, bounds check */
    }

    let p = optval as *mut u8;
    if unsafe { *p } != 0x80 {
        return 0; /* EPERM, unexpected optval from the kernel */
    }

    ctx.retval = 0; /* Reset system call return value to zero */

    unsafe { *p = 0x90 };
    ctx.optlen = 1;

    1
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn _getsockopt_parent(ctx: *mut bpf_sockopt) -> i32 {
    let ctx = unsafe { &mut *ctx };
    let optval = ctx.optval;
    let optval_end = ctx.optval_end;

    if ctx.level != SOL_IP || ctx.optname != IP_TOS {
        if ctx.optlen > unsafe { page_size } {
            ctx.optlen = 0;
        }
        return 1;
    }

    if optval + 1 > optval_end {
        return 0; /* EPERM, bounds check */
    }

    let p = optval as *mut u8;
    if unsafe { *p } != 0x90 {
        return 0; /* EPERM, unexpected optval from the kernel */
    }

    ctx.retval = 0; /* Reset system call return value to zero */

    unsafe { *p = 0xA0 };
    ctx.optlen = 1;

    1
}

#[link_section = "cgroup/setsockopt"]
#[no_mangle]
extern "C" fn _setsockopt(ctx: *mut bpf_sockopt) -> i32 {
    let ctx = unsafe { &mut *ctx };
    let optval = ctx.optval;
    let optval_end = ctx.optval_end;

    if ctx.level != SOL_IP || ctx.optname != IP_TOS {
        if ctx.optlen > unsafe { page_size } {
            ctx.optlen = 0;
        }
        return 1;
    }

    if optval + 1 > optval_end {
        return 0; /* EPERM, bounds check */
    }

    let p = optval as *mut u8;
    unsafe { *p = (*p).wrapping_add(0x10) };
    ctx.optlen = 1;

    1
}

bpf_object!("GPL");
