// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/task_work_busy.c
// (bpf-rs-core idiom). prog_tests/test_task_work.c (serial_test_task_work_busy)
// arms a sequence in the status map; the trigger thread's getppid()
// schedules the first task-work round on the target thread, the fexit
// program on task_work_add() opens the busy window and busy-waits (a
// bpf_loop bounded by time and iterations) for the target's in-window
// attempt, which must be rejected with -EBUSY; the test then gates a
// recovery round. The two task-work callbacks publish their sequence and
// count deliveries in the status map.
//
// `CONFIG_PREEMPT_RT` is the C's weak `.kconfig` extern (`// BTF_KCONFIG:`
// below; scripts/ksym_vars.py mirrors the C object's type and weakness):
// clang tests the byte as `w != 0`. BPF_CORE_READ(task, pid) is a probe
// read of the CO-RE-relocated field (the `#[btf]` task_struct view). The
// `__always_inline` helpers are inlined; the three callbacks are the C's
// .text subprograms.
// `busy_wait_ctx w = {}` is zero-initialized through core::mem::zeroed(),
// padding included, so the translint padding warning does not apply.
// translint: allow(padding)
// BTF_KCONFIG: CONFIG_PREEMPT_RT

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_loop, bpf_map_lookup_elem,
    bpf_probe_read_kernel, sync_fetch_and_add,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;

extern "C" {
    static CONFIG_PREEMPT_RT: u8;
}

/*
 * Bounds for the hardirq busy-wait that holds the scheduling handler
 * inside the real window: task_work_add() has published the callback,
 * but the handler's tail state transition has not run yet.
 * irq_work_single() clears BUSY only after the handler returns, so
 * while this wait runs, the context's scheduling irq_work is BUSY,
 * even though the first callback may already have completed and
 * returned the context to STANDBY.
 *
 * The wait is bounded both by a bpf_ktime_get_ns() check and by an
 * iteration budget.  The time bound is checked against a monotonic
 * clock: host vCPU preemption can stretch the wall-clock duration of
 * the window, which only makes the window longer, never shorter.
 */
const BUSY_WAIT_NS: u64 = 4000000;
const BUSY_WAIT_ITERS: u32 = 1000000;

/* enum task_work_notify_mode */
const TWA_SIGNAL: i32 = 2;

const ESRCH: i32 = 3;
const ENOENT: i32 = 2;
const EBUSY: i32 = 16;

#[no_mangle]
static mut trigger_tid: i32 = 0;
#[no_mangle]
static mut target_tid: i32 = 0;

/*
 * High 32 bits of the result slots hold the sequence, low 32 bits the
 * signed error.  BUSY_WINDOW low bits: 1 open, 2 the in-window attempt
 * was seen before the handler returned, 3 the wait bound was reached
 * without it.  Must match the test.
 */
const BUSY_ARM_SEQ: i32 = 0;
const BUSY_WINDOW: i32 = 1;
const BUSY_ACK: i32 = 2;
const BUSY_GEN1_RESULT: i32 = 3;
const BUSY_GEN2_RESULT: i32 = 4;
const BUSY_CB1_SEQ: i32 = 5;
const BUSY_CB2_COUNT: i32 = 6;
const BUSY_CB2_SEQ: i32 = 7;
const BUSY_RECOVER_SEQ: i32 = 8;
const BUSY_LAST_WAIT_NS: i32 = 9;
const BUSY_STATUS_MAX: usize = 10;

#[link_section = ".maps"]
#[no_mangle]
static status: BpfMap<i32, i64, { maps::ARRAY }, BUSY_STATUS_MAX> = BpfMap::new();

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_task_work {
    __opaque: u64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct task_work_busy_value {
    seq: u32,
    data: [i8; 60],
    tw: bpf_task_work,
}

/*
 * max_entries must cover TASK_WORK_BUSY_MAX_ATTEMPTS in the test: each
 * attempt schedules into its own fresh value.
 */
bpf_map! {
    hmap {
        r#type: *const [i32; maps::HASH],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        max_entries: *const [i32; 128],
        key: *const i32,
        value: *const task_work_busy_value,
    }
}

#[btf]
struct task_struct {
    pid: i32,
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

#[inline(always)]
fn get_status(key: i32) -> i64 {
    let slot = bpf_map_lookup_elem(&status, &key) as *mut i64;
    if slot.is_null() {
        0
    } else {
        unsafe { *slot }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct busy_wait_ctx {
    seq: u64,
    start: u64,
    acked: bool,
}

/* bpf_loop() callback: return 0 continues the loop, return 1 stops it. */
extern "C" fn busy_wait_cb(_i: u64, w: *mut busy_wait_ctx) -> i64 {
    let w = unsafe { &mut *w };

    if (get_status(BUSY_ACK) as u64) >> 32 == w.seq {
        w.acked = true;
        return 1;
    }
    if bpf_ktime_get_ns().wrapping_sub(w.start) > BUSY_WAIT_NS {
        return 1;
    }
    0
}

extern "C" fn busy_cb_gen1(_map: *mut c_void, _key: *mut c_void, value: *mut c_void) -> i32 {
    let work = value as *mut task_work_busy_value;
    let we = (get_status(BUSY_WINDOW) as u64) >> 32;

    /*
     * Backstop for deliveries from abandoned attempts: accept only
     * while no window for a different sequence is published.  The
     * test waits for the old workers to disappear from PID lookup,
     * after their exit task_work, before resetting the shared state.
     * This callback may run before fexit publishes the window state.
     */
    let seq = unsafe { (*work).seq } as u64;
    if we != 0 && we != seq {
        return 0;
    }
    set_status(BUSY_CB1_SEQ, seq as i64);
    0
}

extern "C" fn busy_cb_gen2(_map: *mut c_void, _key: *mut c_void, value: *mut c_void) -> i32 {
    let work = value as *mut task_work_busy_value;
    let key2 = BUSY_CB2_COUNT;

    /*
     * Count only deliveries belonging to the sequence whose window is
     * (or was) published: a late delivery from an abandoned attempt
     * must not satisfy a later exactly-once check.
     */
    let seq = unsafe { (*work).seq } as u64;
    if seq != (get_status(BUSY_WINDOW) as u64) >> 32 {
        return 0;
    }
    set_status(BUSY_CB2_SEQ, seq as i64);
    let count = bpf_map_lookup_elem(&status, &key2) as *mut isize;
    if !count.is_null() {
        sync_fetch_and_add(count, 1);
    }
    0
}

#[link_section = "fexit/task_work_add"]
#[no_mangle]
extern "C" fn busy_fexit_task_work_add(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *const task_struct;
    let notify = arg(ctx, 2) as i32;
    let retval = arg(ctx, 3) as i32;
    let mut w: busy_wait_ctx = unsafe { core::mem::zeroed() };

    let seq = get_status(BUSY_ARM_SEQ) as u64;
    if seq == 0 {
        return 0;
    }

    /*
     * One-shot arm.  Only this test's own first-round add may consume
     * it and hold the window: a successful TWA_SIGNAL add of the
     * bpf_task_work callback, issued from the trigger thread's CPU by
     * the self-IPI'd scheduling handler and targeting the target
     * thread.  Everything else leaves the arm untouched.
     */
    if retval != 0 || notify != TWA_SIGNAL {
        return 0;
    }
    let mut pid: i32 = 0;
    bpf_probe_read_kernel(&mut pid, 4, unsafe { &*task }.pid().as_ptr() as *const c_void);
    if pid != unsafe { target_tid } {
        return 0;
    }
    if bpf_get_current_pid_tgid() as u32 != unsafe { trigger_tid } as u32 {
        return 0;
    }

    set_status(BUSY_ARM_SEQ, 0);
    set_status(BUSY_WINDOW, ((seq << 32) | 1) as i64);

    w.seq = seq;
    w.start = bpf_ktime_get_ns();
    bpf_loop(BUSY_WAIT_ITERS, busy_wait_cb, &mut w, 0);
    let elapsed = bpf_ktime_get_ns().wrapping_sub(w.start);

    /*
     * Publish elapsed time for logging after worker cleanup.  Window
     * validity depends on seeing ACK here, not on this diagnostic.
     */
    set_status(BUSY_LAST_WAIT_NS, elapsed as i64);
    if w.acked {
        set_status(BUSY_WINDOW, ((seq << 32) | 2) as i64);
    } else {
        set_status(BUSY_WINDOW, ((seq << 32) | 3) as i64);
    }
    0
}

#[inline(always)]
fn result(seq: u64, err: i32) -> i64 {
    ((seq << 32) | (err as u32 as u64)) as i64
}

/*
 * Attempt the second scheduling round on the same context, targeting the
 * trigger thread.  The attempt uses the value keyed by its own sequence,
 * so it can never touch another attempt's context.  Returns true if a
 * terminal result was published into res_key; a transient -EBUSY is left
 * unpublished for the caller's retry policy, mirroring the race test's
 * convention.
 */
#[inline(always)]
fn busy_try_gen2(seq: u64, res_key: i32) -> bool {
    let key = seq as i32;

    let task = unsafe { bpf_task_from_pid(trigger_tid) };
    if task.is_null() {
        set_status(res_key, result(seq, -ESRCH));
        return true;
    }
    let work = bpf_map_lookup_elem(&hmap, &key) as *mut task_work_busy_value;
    if work.is_null() {
        unsafe { bpf_task_release(task) };
        set_status(res_key, result(seq, -ENOENT));
        return true;
    }
    let err = unsafe {
        (*work).seq = seq as u32;
        let err = bpf_task_work_schedule_signal(
            task,
            addr_of_mut!((*work).tw),
            &hmap as *const hmap as *mut c_void,
            busy_cb_gen2,
        );
        bpf_task_release(task);
        err
    };
    if err == -EBUSY {
        return false;
    }
    set_status(res_key, result(seq, err));
    true
}

#[link_section = "tracepoint/syscalls/sys_enter_getppid"]
#[no_mangle]
extern "C" fn busy_sched_work(_ctx: *mut c_void) -> i32 {
    let tid = bpf_get_current_pid_tgid() as u32;

    /* Also keep the kconfig extern in object BTF for the userspace skip. */
    if unsafe { CONFIG_PREEMPT_RT } != 0 {
        return 0;
    }

    if tid == unsafe { trigger_tid } as u32 {
        /*
         * Trigger thread: schedule the first round once per armed
         * sequence, targeting the target thread.  The kfunc queues
         * the scheduling irq_work and returns; the handler then
         * parks inside the fexit window above.  A fresh value has no
         * expected BUSY source, so publish every scheduling result.
         */
        let seq = get_status(BUSY_ARM_SEQ) as u64;
        if seq == 0 || (get_status(BUSY_GEN1_RESULT) as u64) >> 32 == seq {
            return 0;
        }
        let key = seq as i32;
        let task = unsafe { bpf_task_from_pid(target_tid) };
        if task.is_null() {
            set_status(BUSY_GEN1_RESULT, result(seq, -ESRCH));
            set_status(BUSY_ARM_SEQ, 0);
            return 0;
        }
        let work = bpf_map_lookup_elem(&hmap, &key) as *mut task_work_busy_value;
        if work.is_null() {
            unsafe { bpf_task_release(task) };
            set_status(BUSY_GEN1_RESULT, result(seq, -ENOENT));
            set_status(BUSY_ARM_SEQ, 0);
            return 0;
        }
        let err = unsafe {
            (*work).seq = seq as u32;
            let err = bpf_task_work_schedule_signal(
                task,
                addr_of_mut!((*work).tw),
                &hmap as *const hmap as *mut c_void,
                busy_cb_gen1,
            );
            bpf_task_release(task);
            err
        };
        set_status(BUSY_GEN1_RESULT, result(seq, err));
        return 0;
    }

    if tid != unsafe { target_tid } as u32 {
        return 0;
    }

    let window = get_status(BUSY_WINDOW) as u64;
    let seq = window >> 32;
    if seq == 0 || window as u32 == 0 {
        return 0;
    }
    /*
     * The first callback must have completed for this sequence.  Being
     * inside the target thread's own subsequent syscall proves the
     * callback wrapper has returned and the context is STANDBY, which
     * is stronger than observing the completion marker from another
     * thread.
     */
    if get_status(BUSY_CB1_SEQ) as u64 != seq {
        return 0;
    }

    if (get_status(BUSY_ACK) as u64) >> 32 != seq {
        /*
         * The in-window attempt, exactly once per sequence.  On a
         * fixed kernel it must be rejected with -EBUSY: the context
         * is STANDBY, the map and program references are alive and
         * no other scheduler exists, so only the BUSY gate can
         * reject here.
         */
        if !busy_try_gen2(seq, BUSY_ACK) {
            set_status(BUSY_ACK, result(seq, -EBUSY));
        }
        return 0;
    }

    /*
     * Recovery, gated by the test: the fexit program releasing the
     * window does not mean the whole old handler has returned and
     * BUSY has cleared yet, so retry until the schedule succeeds.
     */
    if get_status(BUSY_RECOVER_SEQ) as u64 != seq {
        return 0;
    }
    if get_status(BUSY_ACK) as i32 == 0 {
        return 0; /* scheduled in-window; nothing to recover */
    }
    if (get_status(BUSY_GEN2_RESULT) as u64) >> 32 == seq {
        return 0; /* terminal recovery result published */
    }
    busy_try_gen2(seq, BUSY_GEN2_RESULT);
    0
}

bpf_object!("GPL");
