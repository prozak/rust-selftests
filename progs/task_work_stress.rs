#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/task_work_stress.c
// (bpf-rs-core idiom).
//
// bpf_task_work_schedule_signal is a kfunc whose real kernel signature has a
// 5th `struct bpf_prog_aux *aux` parameter that the verifier fills in itself
// (KF_IMPLICIT_ARGS: the BPF-facing BTF prototype exposed to programs omits
// it) -- callers, including this one, only ever pass the first 4 args.

use core::ffi::c_void;

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_task_btf, bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_map_delete_elem,
    bpf_map_lookup_elem, bpf_map_update_elem, sync_fetch_and_add_u64,
};
use bpf_rs_core::maps;

const ENTRIES: i64 = 128;
const BPF_NOEXIST: u64 = 1;

struct task_struct;

// struct bpf_task_work { __u64 __opaque; } __attribute__((aligned(8)));
// Recognized by the kernel purely by this member's BTF struct name/size
// (same mechanism as struct bpf_timer / struct bpf_spin_lock).
#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_task_work {
    __opaque: u64,
}

#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct elem {
    count: u32,
    tw: bpf_task_work,
}

bpf_map! {
    hmap {
        r#type: *const [i32; maps::HASH],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        max_entries: *const [i32; ENTRIES as usize],
        key: *const i32,
        value: *const elem,
    }
}

extern "C" {
    fn bpf_task_work_schedule_signal(
        task: *mut task_struct,
        tw: *mut bpf_task_work,
        map: *const hmap,
        callback: extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32,
    ) -> i32;
}

#[no_mangle]
static mut callback_scheduled: u64 = 0;
#[no_mangle]
static mut callback_success: u64 = 0;
#[no_mangle]
static mut schedule_error: u64 = 0;
#[no_mangle]
static mut delete_success: u64 = 0;

extern "C" fn process_work(_map: *mut c_void, _key: *mut c_void, _value: *mut c_void) -> i32 {
    sync_fetch_and_add_u64(core::ptr::addr_of_mut!(callback_success), 1);
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn schedule_task_work(_ctx: *const c_void) -> i32 {
    let empty_work = elem {
        count: 0,
        tw: bpf_task_work { __opaque: 0 },
    };

    let key: i32 = (bpf_ktime_get_ns() as i64 % ENTRIES) as i32;
    let mut work = bpf_map_lookup_elem(&hmap, &key) as *mut elem;
    if work.is_null() {
        bpf_map_update_elem(&hmap, &key, &empty_work, BPF_NOEXIST);
        work = bpf_map_lookup_elem(&hmap, &key) as *mut elem;
        if work.is_null() {
            return 0;
        }
    }

    let task: *mut task_struct = bpf_get_current_task_btf();
    let err = unsafe {
        bpf_task_work_schedule_signal(
            task,
            core::ptr::addr_of_mut!((*work).tw),
            &hmap,
            process_work,
        )
    };
    if err != 0 {
        sync_fetch_and_add_u64(core::ptr::addr_of_mut!(schedule_error), 1);
    } else {
        sync_fetch_and_add_u64(core::ptr::addr_of_mut!(callback_scheduled), 1);
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn delete_task_work(_ctx: *const c_void) -> i32 {
    let key = (bpf_get_prandom_u32() as i64 % ENTRIES) as i32;
    let err = bpf_map_delete_elem(&hmap, &key);
    if err == 0 {
        sync_fetch_and_add_u64(core::ptr::addr_of_mut!(delete_success), 1);
    }
    0
}

bpf_object!("GPL");
