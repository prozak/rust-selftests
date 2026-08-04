#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_ldsx_insn.c,
// bpf-rs-core idiom.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{vload, vload_as, vstore};

// This target's environment always runs on x86 with a recent enough
// toolchain to emit LDSX (sign-extending load) instructions, matching the
// C source's `#if ... __clang_major__ >= 18` gate.
#[link_section = ".rodata"]
#[no_mangle]
static skip: i32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static val1: i16 = -1;

#[link_section = ".rodata"]
#[no_mangle]
static val2: i32 = -1;

#[no_mangle]
static mut val3: i16 = -1;

#[no_mangle]
static mut val4: i32 = -1;

#[no_mangle]
static mut done1: i32 = 0;
#[no_mangle]
static mut done2: i32 = 0;
#[no_mangle]
static mut ret1: i32 = 0;
#[no_mangle]
static mut ret2: i32 = 0;

#[link_section = "?raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn rdonly_map_prog(_ctx: *const c_void) -> i32 {
    if unsafe { done1 } != 0 {
        return 0;
    }
    unsafe {
        done1 = 1;
    }

    // val1/val2 readonly map
    let v1 = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(val1)) };
    let v2 = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(val2)) };
    if v1 as i32 == v2 {
        unsafe {
            ret1 = 1;
        }
    }
    0
}

#[link_section = "?raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn map_val_prog(_ctx: *const c_void) -> i32 {
    if unsafe { done2 } != 0 {
        return 0;
    }
    unsafe {
        done2 = 1;
    }

    // val1/val2 regular read/write map
    if unsafe { val3 as i32 == val4 } {
        unsafe {
            ret2 = 1;
        }
    }
    0
}

#[repr(C)]
struct bpf_testmod_struct_arg_1 {
    a: i32,
}

#[no_mangle]
static mut int_member: i64 = 0;

#[link_section = "?fentry/bpf_testmod_test_arg_ptr_to_struct"]
#[no_mangle]
extern "C" fn test_ptr_struct_arg(ctx: *const u64) -> i32 {
    let p = arg(ctx, 0) as *const bpf_testmod_struct_arg_1;
    // probed memory access
    unsafe {
        int_member = (*p).a as i64;
    }
    0
}

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

#[no_mangle]
static mut set_optlen: i64 = 0;
#[no_mangle]
static mut set_retval: i64 = 0;

#[link_section = "?cgroup/getsockopt"]
#[no_mangle]
extern "C" fn _getsockopt(ctx: *mut bpf_sockopt) -> i32 {
    let old_optlen = vload!((*ctx).optlen);
    let old_retval = vload!((*ctx).retval);

    vstore!((*ctx).optlen, -1);
    vstore!((*ctx).retval, -1);

    // sign extension for ctx member
    unsafe {
        set_optlen = vload!((*ctx).optlen) as i64;
        set_retval = vload!((*ctx).retval) as i64;
    }

    vstore!((*ctx).optlen, old_optlen);
    vstore!((*ctx).retval, old_retval);

    0
}

#[no_mangle]
static mut set_mark: i64 = 0;

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn _tc(skb: *mut __sk_buff) -> i32 {
    let old_mark = vload!((*skb).mark);

    vstore!((*skb).mark, 0xf6fe);

    // narrowed sign extension for ctx member: force a narrow one-byte
    // signed load of the low byte of mark (little-endian: byte 0).
    let tmp_mark = vload_as!((*skb).mark, i8) as i64;
    unsafe {
        set_mark = tmp_mark;
    }

    vstore!((*skb).mark, old_mark);

    0
}

bpf_object!("GPL");
