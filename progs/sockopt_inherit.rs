#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/sockopt_inherit.c
// (bpf-rs-core idiom).

use bpf_rs_core::helpers::bpf_sk_storage_get;
use bpf_rs_core::{bpf_map, bpf_object};

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

#[repr(C)]
pub struct sockopt_inherit {
    pub val: u8,
}

const SOL_CUSTOM: i32 = 0xdeadbeefu32 as i32;
const CUSTOM_INHERIT1: i32 = 0;
const CUSTOM_INHERIT2: i32 = 1;

const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

// map_flags: BPF_F_NO_PREALLOC (1) | BPF_F_CLONE (1 << 9) = 513.
bpf_map! {
    cloned1_map {
        r#type: *const [i32; 24],     // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 513], // BPF_F_NO_PREALLOC | BPF_F_CLONE
        key: *const i32,
        value: *const sockopt_inherit,
    }
}

bpf_map! {
    cloned2_map {
        r#type: *const [i32; 24],     // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 513], // BPF_F_NO_PREALLOC | BPF_F_CLONE
        key: *const i32,
        value: *const sockopt_inherit,
    }
}

bpf_map! {
    listener_only_map {
        r#type: *const [i32; 24],   // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const sockopt_inherit,
    }
}

#[no_mangle]
static mut page_size: i32 = 0;

#[inline(always)]
fn get_storage(ctx: &bpf_sockopt) -> *mut sockopt_inherit {
    let sk = ctx.sk as *mut core::ffi::c_void;
    if ctx.optname == CUSTOM_INHERIT1 {
        bpf_sk_storage_get(&cloned1_map, sk, core::ptr::null_mut(), BPF_SK_STORAGE_GET_F_CREATE)
            as *mut sockopt_inherit
    } else if ctx.optname == CUSTOM_INHERIT2 {
        bpf_sk_storage_get(&cloned2_map, sk, core::ptr::null_mut(), BPF_SK_STORAGE_GET_F_CREATE)
            as *mut sockopt_inherit
    } else {
        bpf_sk_storage_get(
            &listener_only_map,
            sk,
            core::ptr::null_mut(),
            BPF_SK_STORAGE_GET_F_CREATE,
        ) as *mut sockopt_inherit
    }
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn _getsockopt(ctx: *mut bpf_sockopt) -> i32 {
    let ctx = unsafe { &mut *ctx };
    let optval = ctx.optval;
    let optval_end = ctx.optval_end;

    if ctx.level != SOL_CUSTOM {
        // only interested in SOL_CUSTOM
        if ctx.optlen > unsafe { page_size } {
            ctx.optlen = 0;
        }
        return 1;
    }

    if optval + 1 > optval_end {
        return 0; /* EPERM, bounds check */
    }

    let storage = get_storage(ctx);
    if storage.is_null() {
        return 0; /* EPERM, couldn't get sk storage */
    }

    ctx.retval = 0; /* Reset system call return value to zero */

    let p = optval as *mut u8;
    unsafe { *p = (*storage).val };
    ctx.optlen = 1;

    1
}

#[link_section = "cgroup/setsockopt"]
#[no_mangle]
extern "C" fn _setsockopt(ctx: *mut bpf_sockopt) -> i32 {
    let ctx = unsafe { &mut *ctx };
    let optval = ctx.optval;
    let optval_end = ctx.optval_end;

    if ctx.level != SOL_CUSTOM {
        // only interested in SOL_CUSTOM
        if ctx.optlen > unsafe { page_size } {
            ctx.optlen = 0;
        }
        return 1;
    }

    if optval + 1 > optval_end {
        return 0; /* EPERM, bounds check */
    }

    let storage = get_storage(ctx);
    if storage.is_null() {
        return 0; /* EPERM, couldn't get sk storage */
    }

    let p = optval as *mut u8;
    unsafe { (*storage).val = *p };
    ctx.optlen = -1;

    1
}

bpf_object!("GPL");
