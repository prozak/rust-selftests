// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![allow(non_camel_case_types, non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/task_kfunc_failure.c
// (+ task_kfunc_common.h), bpf-rs-core idiom.
//
// bpf_task_acquire()/bpf_task_release() misuse rejections
// (prog_tests/task_kfunc.c: RUN_TESTS(task_kfunc_failure)). The common
// header's two maps, kfunc externs and insert/lookup helpers are those of
// task_kfunc_success.rs; the __kptr members are tagged by btf_type_tags!,
// the kptr pointee is a #[btf] view of task_struct also used for the
// pid/comm reads. BPF_PROG arguments are fentry_arg(ctx, i); the "frame
// pointer" arguments are the address of the local clone_flags copy, as
// in the C; __sink() is helpers::sink. bpf_obj_new(typeof(*local)) is
// the BTF_TYPE_ID local id of the map value type.
// BTF_TYPE_ID: tasks_kfunc_map_value_id local struct __tasks_kfunc_map_value

use bpf_rs_core::helpers::{
    bpf_kptr_xchg, bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem,
    bpf_probe_read_kernel, bpf_spin_lock, bpf_spin_unlock, bpf_strncmp, sink,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_object, btf_type_tags, test_tags};
use btf_macros::btf;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{addr_of_mut, null_mut};

const BPF_NOEXIST: u64 = 1;
const ENOENT: i64 = 2;
const EEXIST: i64 = 17;

#[btf]
struct task_struct {
    pid: i32,
    comm: [u8; 16],
}

#[repr(C)]
struct __tasks_kfunc_map_value {
    task: *mut task_struct,
}

#[link_section = ".maps"]
#[no_mangle]
static __tasks_kfunc_map: BpfMap<i32, __tasks_kfunc_map_value, { maps::HASH }, 1> = BpfMap::new();

#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[repr(C)]
struct task_kptr_lock_value {
    lock: bpf_spin_lock,
    task: *mut task_struct,
}

#[link_section = ".maps"]
#[no_mangle]
static task_kptr_lock_map: BpfMap<i32, task_kptr_lock_value, { maps::ARRAY }, 1> = BpfMap::new();

btf_type_tags! {
    __tasks_kfunc_map_value.task: kptr;
    task_kptr_lock_value.task: kptr;
}

extern "C" {
    fn tasks_kfunc_map_value_id() -> u64;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);

    fn bpf_task_acquire(p: *mut task_struct) -> *mut task_struct;
    fn bpf_task_release(p: *mut task_struct);
    fn bpf_task_from_pid(pid: i32) -> *mut task_struct;
    fn bpf_task_from_vpid(vpid: i32) -> *mut task_struct;
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn bpf_local_irq_save(flags: *mut u64);
    fn bpf_local_irq_restore(flags: *mut u64);
    fn bpf_preempt_disable();
    fn bpf_preempt_enable();
}

static FOO: [u8; 4] = *b"foo\0";

#[inline(always)]
fn task_pid(p: *mut task_struct) -> i32 {
    *unsafe { &*p }.pid().get().unwrap()
}

#[inline(always)]
fn task_comm(p: *mut task_struct) -> *const u8 {
    unsafe { &*p }.comm().as_ptr() as *const u8
}

/// task_kfunc_common.h: tasks_kfunc_map_value_lookup()
#[inline(always)]
unsafe fn tasks_kfunc_map_value_lookup(p: *mut task_struct) -> *mut __tasks_kfunc_map_value {
    let mut pid_: i32 = 0;

    let status = bpf_probe_read_kernel(&mut pid_, 4, (&*p).pid().as_ptr() as *const c_void);
    if status != 0 {
        return null_mut();
    }

    bpf_map_lookup_elem(&__tasks_kfunc_map, &pid_) as *mut __tasks_kfunc_map_value
}

/// task_kfunc_common.h: tasks_kfunc_map_insert()
#[inline(always)]
unsafe fn tasks_kfunc_map_insert(p: *mut task_struct) -> i64 {
    let mut pid_: i32 = 0;

    let status = bpf_probe_read_kernel(&mut pid_, 4, (&*p).pid().as_ptr() as *const c_void);
    if status != 0 {
        return status;
    }

    let local = __tasks_kfunc_map_value { task: null_mut() };
    let status = bpf_map_update_elem(&__tasks_kfunc_map, &pid_, &local, BPF_NOEXIST);
    if status != 0 {
        return status;
    }

    let v = bpf_map_lookup_elem(&__tasks_kfunc_map, &pid_) as *mut __tasks_kfunc_map_value;
    if v.is_null() {
        bpf_map_delete_elem(&__tasks_kfunc_map, &pid_);
        return -ENOENT;
    }

    let acquired = bpf_task_acquire(p);
    if acquired.is_null() {
        return -ENOENT;
    }

    let old = bpf_kptr_xchg(addr_of_mut!((*v).task).cast(), acquired.cast()) as *mut task_struct;
    if !old.is_null() {
        bpf_task_release(old);
        return -EEXIST;
    }

    0
}

unsafe fn insert_lookup_task(task: *mut task_struct) -> *mut __tasks_kfunc_map_value {
    let status = tasks_kfunc_map_insert(task);
    if status != 0 {
        return null_mut();
    }

    tasks_kfunc_map_value_lookup(task)
}

// Prototype for all of the program trace events below:
//
// TRACE_EVENT(task_newtask,
//         TP_PROTO(struct task_struct *p, u64 clone_flags)

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_untrusted(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    unsafe {
        let v = insert_lookup_task(task);
        if v.is_null() {
            return 0;
        }

        // Can't invoke bpf_task_acquire() on an untrusted pointer.
        let acquired = bpf_task_acquire((*v).task);
        if acquired.is_null() {
            return 0;
        }

        bpf_task_release(acquired);
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_fp(ctx: *const u64) -> i32 {
    let mut clone_flags = arg(ctx, 1);
    let mut stack_task = &mut clone_flags as *mut u64 as *mut task_struct;

    unsafe {
        // Can't invoke bpf_task_acquire() on a random frame pointer.
        let acquired =
            bpf_task_acquire(&mut stack_task as *mut *mut task_struct as *mut task_struct);
        if acquired.is_null() {
            return 0;
        }

        bpf_task_release(acquired);
    }

    0
}

#[link_section = "kretprobe/free_task"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_unsafe_kretprobe(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    unsafe {
        // Can't call bpf_task_acquire() or bpf_task_release() in an untrusted prog.
        let acquired = bpf_task_acquire(task);
        if acquired.is_null() {
            return 0;
        }
        bpf_task_release(acquired);
    }

    0
}

#[link_section = "kretprobe/free_task"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_unsafe_kretprobe_rcu(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    unsafe {
        bpf_rcu_read_lock();
        if task.is_null() {
            bpf_rcu_read_unlock();
            return 0;
        }
        // Can't call bpf_task_acquire() or bpf_task_release() in an untrusted prog.
        let acquired = bpf_task_acquire(task);
        if !acquired.is_null() {
            bpf_task_release(acquired);
        }
        bpf_rcu_read_unlock();
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_null(_ctx: *const u64) -> i32 {
    unsafe {
        // Can't invoke bpf_task_acquire() on a NULL pointer.
        let acquired = bpf_task_acquire(null_mut());
        if acquired.is_null() {
            return 0;
        }
        bpf_task_release(acquired);
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_unreleased(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    let mut acquired = unsafe { bpf_task_acquire(task) };

    // Acquired task is never released.
    sink(&mut acquired);

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_xchg_unreleased(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    unsafe {
        let v = insert_lookup_task(task);
        if v.is_null() {
            return 0;
        }

        let kptr = bpf_kptr_xchg(addr_of_mut!((*v).task).cast(), null_mut()) as *mut task_struct;
        if kptr.is_null() {
            return 0;
        }
    }

    // Kptr retrieved from map is never released.

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_release_no_null_check(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    unsafe {
        let acquired = bpf_task_acquire(task);
        // Can't invoke bpf_task_release() on an acquired task without a NULL check.
        bpf_task_release(acquired);
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_release_untrusted(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    unsafe {
        let v = insert_lookup_task(task);
        if v.is_null() {
            return 0;
        }

        // Can't invoke bpf_task_release() on an untrusted pointer.
        bpf_task_release((*v).task);
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_release_fp(ctx: *const u64) -> i32 {
    let mut clone_flags = arg(ctx, 1);
    let acquired = &mut clone_flags as *mut u64 as *mut task_struct;

    // Cannot release random frame pointer.
    unsafe { bpf_task_release(acquired) };

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_release_null(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;
    let mut pid_: i32 = 0;

    unsafe {
        let status = bpf_probe_read_kernel(&mut pid_, 4, (&*task).pid().as_ptr() as *const c_void);
        if status != 0 {
            return 0;
        }

        let local = __tasks_kfunc_map_value { task: null_mut() };
        let status = bpf_map_update_elem(&__tasks_kfunc_map, &pid_, &local, BPF_NOEXIST);
        if status != 0 {
            return status as i32;
        }

        let v = bpf_map_lookup_elem(&__tasks_kfunc_map, &pid_) as *mut __tasks_kfunc_map_value;
        if v.is_null() {
            return -ENOENT as i32;
        }

        let acquired = bpf_task_acquire(task);
        if acquired.is_null() {
            return -EEXIST as i32;
        }

        let old = bpf_kptr_xchg(addr_of_mut!((*v).task).cast(), acquired.cast()) as *mut task_struct;

        // old cannot be passed to bpf_task_release() without a NULL check.
        bpf_task_release(old);
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_release_unacquired(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    // Cannot release trusted task pointer which was not acquired.
    unsafe { bpf_task_release(task) };

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_obj_drop_with_kptr(_ctx: *const u64) -> i32 {
    unsafe {
        let local = bpf_obj_new(tasks_kfunc_map_value_id()) as *mut __tasks_kfunc_map_value;
        if local.is_null() {
            return 0;
        }

        bpf_obj_drop(local.cast());
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_obj_drop_nmi_with_kptr(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    unsafe {
        let local = bpf_obj_new(tasks_kfunc_map_value_id()) as *mut __tasks_kfunc_map_value;
        if local.is_null() {
            return 0;
        }

        let acquired = bpf_task_acquire(task);
        if !acquired.is_null() {
            let old =
                bpf_kptr_xchg(addr_of_mut!((*local).task).cast(), acquired.cast()) as *mut task_struct;
            if !old.is_null() {
                bpf_task_release(old);
            }
        }

        bpf_obj_drop(local.cast());
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_from_pid_no_null_check(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    unsafe {
        let acquired = bpf_task_from_pid(task_pid(task));

        // Releasing bpf_task_from_pid() lookup without a NULL check.
        bpf_task_release(acquired);
    }

    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_from_vpid_no_null_check(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    unsafe {
        let acquired = bpf_task_from_vpid(task_pid(task));

        // Releasing bpf_task_from_vpid() lookup without a NULL check.
        bpf_task_release(acquired);
    }

    0
}

#[link_section = "lsm/task_free"]
#[no_mangle]
extern "C" fn task_kfunc_from_lsm_task_free(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    unsafe {
        // the argument of lsm task_free hook is untrusted.
        let acquired = bpf_task_acquire(task);
        if acquired.is_null() {
            return 0;
        }

        bpf_task_release(acquired);
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_access_comm1(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    bpf_strncmp(task_comm(task) as *const c_void, 17, FOO.as_ptr() as *const c_void);
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_access_comm2(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    bpf_strncmp(
        unsafe { task_comm(task).add(1) } as *const c_void,
        16,
        FOO.as_ptr() as *const c_void,
    );
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_access_comm3(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    let comm = task_comm(task);
    bpf_probe_read_kernel(unsafe { &mut *(comm as *mut u8) }, 16, comm as *const c_void);
    0
}

// BPF_PROG(task_access_comm4, struct task_struct *task, const char *buf, bool exec)
#[link_section = "fentry/__set_task_comm"]
#[no_mangle]
extern "C" fn task_access_comm4(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    // task->comm is a legacy ptr_to_btf_id. The verifier cannot guarantee
    // its safety. Hence it cannot be accessed with normal load insns.
    bpf_strncmp(task_comm(task) as *const c_void, 16, FOO.as_ptr() as *const c_void);
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_release_in_map(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    unsafe {
        if tasks_kfunc_map_insert(task) != 0 {
            return 0;
        }

        let v = tasks_kfunc_map_value_lookup(task);
        if v.is_null() {
            return 0;
        }

        bpf_rcu_read_lock();
        let local = (*v).task;
        if local.is_null() {
            bpf_rcu_read_unlock();
            return 0;
        }
        // Can't release a kptr that's still stored in a map.
        bpf_task_release(local);
        bpf_rcu_read_unlock();
    }

    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_after_final_spin_unlock(_ctx: *const c_void) -> i32 {
    let key: i32 = 0;

    let v = bpf_map_lookup_elem(&task_kptr_lock_map, &key) as *mut task_kptr_lock_value;
    if v.is_null() {
        return 0;
    }

    unsafe {
        bpf_spin_lock(addr_of_mut!((*v).lock));
        let task = (*v).task;
        bpf_spin_unlock(addr_of_mut!((*v).lock));
        if task.is_null() {
            return 0;
        }

        let acquired = bpf_task_acquire(task);
        if !acquired.is_null() {
            bpf_task_release(acquired);
        }
    }
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_after_preempt_enable(_ctx: *const c_void) -> i32 {
    let key: i32 = 0;

    let v = bpf_map_lookup_elem(&task_kptr_lock_map, &key) as *mut task_kptr_lock_value;
    if v.is_null() {
        return 0;
    }

    unsafe {
        bpf_preempt_disable();
        let task = (*v).task;
        bpf_preempt_enable();
        if task.is_null() {
            return 0;
        }

        let acquired = bpf_task_acquire(task);
        if !acquired.is_null() {
            bpf_task_release(acquired);
        }
    }
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_after_irq_restore(_ctx: *const c_void) -> i32 {
    let key: i32 = 0;
    let mut flags = MaybeUninit::<u64>::uninit();

    let v = bpf_map_lookup_elem(&task_kptr_lock_map, &key) as *mut task_kptr_lock_value;
    if v.is_null() {
        return 0;
    }

    unsafe {
        bpf_local_irq_save(flags.as_mut_ptr());
        let task = (*v).task;
        bpf_local_irq_restore(flags.as_mut_ptr());
        if task.is_null() {
            return 0;
        }

        let acquired = bpf_task_acquire(task);
        if !acquired.is_null() {
            bpf_task_release(acquired);
        }
    }
    0
}

test_tags! {
    task_kfunc_acquire_untrusted: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    task_kfunc_acquire_fp: __failure, __msg("R1 type=fp expected=ptr_, trusted_ptr_, rcu_ptr_");
    task_kfunc_acquire_unsafe_kretprobe: __failure, __msg("calling kernel function bpf_task_acquire is not allowed");
    task_kfunc_acquire_unsafe_kretprobe_rcu: __failure, __msg("calling kernel function bpf_task_acquire is not allowed");
    task_kfunc_acquire_null: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    task_kfunc_acquire_unreleased: __failure, __msg("Unreleased reference");
    task_kfunc_xchg_unreleased: __failure, __msg("Unreleased reference");
    task_kfunc_acquire_release_no_null_check: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    task_kfunc_release_untrusted: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    task_kfunc_release_fp: __failure, __msg("R1 type=fp expected=ptr_, trusted_ptr_, rcu_ptr_");
    task_kfunc_release_null: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    task_kfunc_release_unacquired: __failure, __msg("release function bpf_task_release expects referenced PTR_TO_BTF_ID passed to R1");
    task_kfunc_obj_drop_with_kptr: __failure, __msg("bpf_obj_drop cannot be used in tracing programs on types with NMI unsafe fields");
    task_kfunc_obj_drop_nmi_with_kptr: __failure, __msg("bpf_obj_drop cannot be used in tracing programs on types with NMI unsafe fields");
    task_kfunc_from_pid_no_null_check: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    task_kfunc_from_vpid_no_null_check: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    task_kfunc_from_lsm_task_free: __failure, __msg("R1 must be a rcu pointer");
    task_access_comm1: __failure, __msg("access beyond the end of member comm");
    task_access_comm2: __failure, __msg("access beyond the end of member comm");
    task_access_comm3: __failure, __msg("only read is supported");
    task_access_comm4: __failure, __msg("R1 type=ptr_ expected");
    task_kfunc_release_in_map: __failure, __msg("release function bpf_task_release expects referenced PTR_TO_BTF_ID passed to R1");
    task_kfunc_acquire_after_final_spin_unlock: __failure, __msg("R1 must be a rcu pointer");
    task_kfunc_acquire_after_preempt_enable: __failure, __msg("R1 must be a rcu pointer");
    task_kfunc_acquire_after_irq_restore: __failure, __msg("R1 must be a rcu pointer");
}

bpf_object!("GPL");
