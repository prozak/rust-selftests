// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/task_work_race.c
// (bpf-rs-core idiom). prog_tests/test_task_work.c (serial_test_task_work_race)
// arms a round through the status map and has the trigger thread call
// getppid(): the tracepoint program schedules task work on the target
// thread with the hash map's element, publishes the sequence and the
// error of the schedule in RACE_RESULT, and the callback marks the
// sequence done in the completed map while the test races a deletion of
// the element against it.

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_map_lookup_elem};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_map, bpf_object};

const TASK_WORK_RACE_MAX_SEQ: i32 = 2048;

const RACE_ARM_SEQ: i32 = 0;
const RACE_READY_SEQ: i32 = 1;
/* High 32 bits hold the sequence, low 32 bits the signed error. */
const RACE_RESULT: i32 = 2;
const RACE_STATUS_MAX: usize = 3;

const ESRCH: i32 = 3;
const ENOENT: i32 = 2;
const EBUSY: i32 = 16;

#[no_mangle]
static mut trigger_tid: i32 = 0;
#[no_mangle]
static mut target_tid: i32 = 0;

#[link_section = ".maps"]
#[no_mangle]
static status: BpfMap<i32, i64, { maps::ARRAY }, RACE_STATUS_MAX> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static completed: BpfMap<i32, u64, { maps::ARRAY }, 2048> = BpfMap::new();

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_task_work {
    __opaque: u64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct task_work_race_value {
    seq: u32,
    data: [i8; 60],
    tw: bpf_task_work,
}

bpf_map! {
    hmap {
        r#type: *const [i32; maps::HASH],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        max_entries: *const [i32; 4],
        key: *const i32,
        value: *const task_work_race_value,
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct task_struct {
    _priv: [u8; 0],
}

type WorkFn = extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32;

extern "C" {
    fn bpf_task_from_pid(pid: i32) -> *mut task_struct;
    fn bpf_task_release(p: *mut task_struct);
    fn bpf_task_work_schedule_signal(
        task: *mut task_struct,
        tw: *mut bpf_task_work,
        map: *mut c_void,
        callback: WorkFn,
    ) -> i32;
}

#[inline(always)]
fn set_status(key: i32, value: i64) {
    let slot = bpf_map_lookup_elem(&status, &key) as *mut i64;
    if !slot.is_null() {
        unsafe { *slot = value };
    }
}

extern "C" fn process_work(_map: *mut c_void, _key: *mut c_void, value: *mut c_void) -> i32 {
    let work = value as *mut task_work_race_value;
    let seq = unsafe { (*work).seq } as i32;

    if seq <= 0 || seq >= TASK_WORK_RACE_MAX_SEQ {
        return 0;
    }
    let done = bpf_map_lookup_elem(&completed, &seq) as *mut u64;
    if !done.is_null() {
        unsafe { *done = 1 };
    }
    0
}

#[link_section = "tracepoint/syscalls/sys_enter_getppid"]
#[no_mangle]
extern "C" fn race_sched_work(_ctx: *mut c_void) -> i32 {
    let tid = bpf_get_current_pid_tgid() as u32;

    if tid != unsafe { trigger_tid } as u32 {
        return 0;
    }

    let mut key = RACE_ARM_SEQ;
    let arm = bpf_map_lookup_elem(&status, &key) as *mut i64;
    key = RACE_RESULT;
    let result = bpf_map_lookup_elem(&status, &key) as *mut i64;
    if arm.is_null() || result.is_null() {
        return 0;
    }
    let arm_val = unsafe { *arm };
    if arm_val <= 0 || ((unsafe { *result } as u64) >> 32) as u32 as i64 == arm_val {
        return 0;
    }
    let seq = arm_val as u32;

    let err: i32 = 'done: {
        let task = unsafe { bpf_task_from_pid(target_tid) };
        if task.is_null() {
            break 'done -ESRCH;
        }

        key = 0;
        let work = bpf_map_lookup_elem(&hmap, &key) as *mut task_work_race_value;
        let err = if work.is_null() {
            -ENOENT
        } else {
            unsafe { (*work).seq = seq };
            set_status(RACE_READY_SEQ, seq as i64);
            let err = unsafe {
                bpf_task_work_schedule_signal(
                    task,
                    addr_of_mut!((*work).tw),
                    &hmap as *const hmap as *mut c_void,
                    process_work,
                )
            };
            if err == -EBUSY {
                unsafe { bpf_task_release(task) };
                return 0;
            }
            err
        };

        unsafe { bpf_task_release(task) };
        err
    };

    /* Publish the sequence and its error in one store. */
    unsafe { *result = (((seq as u64) << 32) | (err as u32 as u64)) as i64 };
    0
}

bpf_object!("GPL");
