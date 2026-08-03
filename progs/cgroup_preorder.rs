#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/cgroup_preorder.c
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

#[no_mangle]
static mut idx: u32 = 0;
#[no_mangle]
static mut result: [u8; 4] = [0; 4];

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn child(_ctx: *mut bpf_sockopt) -> i32 {
    unsafe {
        if idx < 4 {
            result[idx as usize] = 1;
            idx += 1;
        }
    }
    1
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn child_2(_ctx: *mut bpf_sockopt) -> i32 {
    unsafe {
        if idx < 4 {
            result[idx as usize] = 2;
            idx += 1;
        }
    }
    1
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn parent(_ctx: *mut bpf_sockopt) -> i32 {
    unsafe {
        if idx < 4 {
            result[idx as usize] = 3;
            idx += 1;
        }
    }
    1
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn parent_2(_ctx: *mut bpf_sockopt) -> i32 {
    unsafe {
        if idx < 4 {
            result[idx as usize] = 4;
            idx += 1;
        }
    }
    1
}

bpf_object!("GPL");
