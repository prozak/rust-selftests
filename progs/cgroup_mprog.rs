#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/cgroup_mprog.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;

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

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn getsockopt_1(_ctx: *mut bpf_sockopt) -> i32 {
    1
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn getsockopt_2(_ctx: *mut bpf_sockopt) -> i32 {
    1
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn getsockopt_3(_ctx: *mut bpf_sockopt) -> i32 {
    1
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn getsockopt_4(_ctx: *mut bpf_sockopt) -> i32 {
    1
}

bpf_object!("GPL");
