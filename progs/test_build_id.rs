#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_build_id.c,
// bpf-rs-core idiom.
//
// NOTE: exercises bpf_get_stack()/user-stack unwinding and uprobe.multi
// attach, both of which require the QEMU oracle (FLAVOR=qemu); see
// stacktrace_map.rs for precedent.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_stack;
use core::ffi::c_void;

const BPF_BUILD_ID_SIZE: usize = 20;
const BPF_F_USER_STACK: u64 = 1 << 8;
const BPF_F_USER_BUILD_ID: u64 = 1 << 11;

#[repr(C)]
struct bpf_stack_build_id {
    status: i32,
    build_id: [u8; BPF_BUILD_ID_SIZE],
    offset_or_ip: u64,
}

#[no_mangle]
static mut stack_sleepable: [bpf_stack_build_id; 128] = unsafe { core::mem::zeroed() };
#[no_mangle]
static mut res_sleepable: i32 = 0;

#[no_mangle]
static mut stack_nofault: [bpf_stack_build_id; 128] = unsafe { core::mem::zeroed() };
#[no_mangle]
static mut res_nofault: i32 = 0;

#[link_section = "uprobe.multi/./uprobe_multi:uprobe"]
#[no_mangle]
extern "C" fn uprobe_nofault(ctx: *const c_void) -> i32 {
    let buf = core::ptr::addr_of_mut!(stack_nofault) as *mut c_void;
    let size = core::mem::size_of::<[bpf_stack_build_id; 128]>() as u32;
    let ret = bpf_get_stack(ctx, buf, size, BPF_F_USER_STACK | BPF_F_USER_BUILD_ID) as i32;
    unsafe { res_nofault = ret };

    0
}

#[link_section = "uprobe.multi.s/./uprobe_multi:uprobe"]
#[no_mangle]
extern "C" fn uprobe_sleepable(ctx: *const c_void) -> i32 {
    let buf = core::ptr::addr_of_mut!(stack_sleepable) as *mut c_void;
    let size = core::mem::size_of::<[bpf_stack_build_id; 128]>() as u32;
    let ret = bpf_get_stack(ctx, buf, size, BPF_F_USER_STACK | BPF_F_USER_BUILD_ID) as i32;
    unsafe { res_sleepable = ret };

    0
}

bpf_object!("GPL");
