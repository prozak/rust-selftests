#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_map_ops.c,
// bpf-rs-core idiom.

use bpf_rs_core::{bpf_map, bpf_object};
use bpf_rs_core::helpers::{
    bpf_for_each_map_elem, bpf_get_current_pid_tgid, bpf_map_delete_elem, bpf_map_peek_elem,
    bpf_map_pop_elem, bpf_map_push_elem, bpf_map_update_elem,
};
use bpf_rs_core::maps::{self, BpfMap};

const BPF_NOEXIST: u64 = 1;
const BPF_MAP_TYPE_STACK: usize = 23;

#[link_section = ".maps"]
#[no_mangle]
static hash_map: BpfMap<i32, i32, { maps::HASH }, 1> = BpfMap::new();

bpf_map! {
    stack_map {
        r#type: *const [i32; BPF_MAP_TYPE_STACK],
        max_entries: *const [i32; 1],
        value: *const i32,
    }
}

#[link_section = ".maps"]
#[no_mangle]
static array_map: BpfMap<i32, i32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".rodata"]
#[no_mangle]
static pid: i32 = 0;

#[no_mangle]
static mut err: i64 = 0;

extern "C" fn callback(
    _map: *mut BpfMap<i32, i32, { maps::ARRAY }, 1>,
    _key: *mut i32,
    _val: *mut i32,
    _ctx: *mut i32,
) -> i64 {
    0
}

#[link_section = "tp/syscalls/sys_enter_getpid"]
#[no_mangle]
extern "C" fn map_update(_ctx: *const core::ffi::c_void) -> i32 {
    let key: i32 = 0;
    let val: i32 = 1;

    unsafe {
        if core::ptr::read_volatile(&pid) as u64 != bpf_get_current_pid_tgid() >> 32 {
            return 0;
        }
        err = bpf_map_update_elem(&hash_map, &key, &val, BPF_NOEXIST);
    }

    0
}

#[link_section = "tp/syscalls/sys_enter_getppid"]
#[no_mangle]
extern "C" fn map_delete(_ctx: *const core::ffi::c_void) -> i32 {
    let key: i32 = 0;

    unsafe {
        if core::ptr::read_volatile(&pid) as u64 != bpf_get_current_pid_tgid() >> 32 {
            return 0;
        }
        err = bpf_map_delete_elem(&hash_map, &key);
    }

    0
}

#[link_section = "tp/syscalls/sys_enter_getuid"]
#[no_mangle]
extern "C" fn map_push(_ctx: *const core::ffi::c_void) -> i32 {
    let val: i32 = 1;

    unsafe {
        if core::ptr::read_volatile(&pid) as u64 != bpf_get_current_pid_tgid() >> 32 {
            return 0;
        }
        err = bpf_map_push_elem(&stack_map, &val, 0);
    }

    0
}

#[link_section = "tp/syscalls/sys_enter_geteuid"]
#[no_mangle]
extern "C" fn map_pop(_ctx: *const core::ffi::c_void) -> i32 {
    let mut val: i32 = 0;

    unsafe {
        if core::ptr::read_volatile(&pid) as u64 != bpf_get_current_pid_tgid() >> 32 {
            return 0;
        }
        err = bpf_map_pop_elem(&stack_map, &mut val);
    }

    0
}

#[link_section = "tp/syscalls/sys_enter_getgid"]
#[no_mangle]
extern "C" fn map_peek(_ctx: *const core::ffi::c_void) -> i32 {
    let mut val: i32 = 0;

    unsafe {
        if core::ptr::read_volatile(&pid) as u64 != bpf_get_current_pid_tgid() >> 32 {
            return 0;
        }
        err = bpf_map_peek_elem(&stack_map, &mut val);
    }

    0
}

#[link_section = "tp/syscalls/sys_enter_gettid"]
#[no_mangle]
extern "C" fn map_for_each_pass(_ctx: *const core::ffi::c_void) -> i32 {
    let key: i32 = 0;
    let val: i32 = 1;
    let flags: u64 = 0;
    let mut callback_ctx: i32 = 0;

    unsafe {
        if core::ptr::read_volatile(&pid) as u64 != bpf_get_current_pid_tgid() >> 32 {
            return 0;
        }
        bpf_map_update_elem(&array_map, &key, &val, flags);
        err = bpf_for_each_map_elem(&array_map, callback, &mut callback_ctx, flags);
    }

    0
}

#[link_section = "tp/syscalls/sys_enter_getpgid"]
#[no_mangle]
extern "C" fn map_for_each_fail(_ctx: *const core::ffi::c_void) -> i32 {
    let key: i32 = 0;
    let val: i32 = 1;
    let flags: u64 = BPF_NOEXIST;
    let mut callback_ctx: i32 = 0;

    unsafe {
        if core::ptr::read_volatile(&pid) as u64 != bpf_get_current_pid_tgid() >> 32 {
            return 0;
        }
        bpf_map_update_elem(&array_map, &key, &val, flags);
        err = bpf_for_each_map_elem(&array_map, callback, &mut callback_ctx, flags);
    }

    0
}

bpf_object!("GPL");
