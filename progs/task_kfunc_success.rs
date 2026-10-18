// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of tools/testing/selftests/bpf/progs/task_kfunc_success.c
// (bpf-rs-core idiom, task_kfunc_common.h inlined). prog_tests/task_kfunc.c
// attaches one tp_btf/task_newtask program at a time and forks (the pid
// global filters the event), runs the syscall programs with test_run, and
// the vpid ones in a new pid namespace; every program reports through the
// err global. The kptr pointee is a #[btf] view of task_struct, also used
// for the pid/comm/group_leader/rcu_users accesses.
//
// bpf_ksym_exists() is a run-time test of the address libbpf fills in (0
// for a weak kfunc the kernel lacks): rustc would fold a fn pointer's null
// test, so the address passes through sink() first (test_ksyms_weak.rs).
// The three bpf_task_acquire flavors and the two kfuncs that do not exist
// are the C's `__ksym __weak` declarations. The flavors' prototypes come
// from the C object (scripts/ksym_vars.py): libbpf strips the suffix for the
// kernel lookup and then checks the DECLARED prototype against the
// kernel's, which only ___one must pass; a prototype mirrored from the
// kernel by name (rust-bpf's add_ksyms.py) would type their pointers void.
// BTF_TYPE_ID: tasks_kfunc_map_value_id local struct __tasks_kfunc_map_value
// BTF_KSYM: bpf_task_acquire___one
// BTF_KSYM: bpf_task_acquire___two
// BTF_KSYM: bpf_task_acquire___three
// BTF_WEAK_KFUNC: bpf_task_acquire___one
// BTF_WEAK_KFUNC: bpf_task_acquire___two
// BTF_WEAK_KFUNC: bpf_task_acquire___three
// BTF_WEAK_KFUNC: invalid_kfunc
// BTF_WEAK_KFUNC: bpf_testmod_test_mod_kfunc

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_task_btf, bpf_kptr_xchg, bpf_map_delete_elem,
    bpf_map_lookup_elem, bpf_map_update_elem, bpf_probe_read_kernel, bpf_spin_lock, bpf_spin_unlock,
    bpf_strncmp, sink,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_object, btf_type_tags};
use btf_macros::btf;

const BPF_NOEXIST: u64 = 1;
const ENOENT: i64 = 2;
const EEXIST: i64 = 17;

#[no_mangle]
static mut err: i32 = 0;
#[no_mangle]
static mut pid: i32 = 0;

#[btf]
struct task_struct {
    pid: i32,
    group_leader: *mut task_struct,
    comm: [u8; 16],
    rcu_users: refcount_struct,
}

#[btf]
struct refcount_struct {
    refs: atomic_t,
}

#[btf]
struct atomic_t {
    counter: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct __tasks_kfunc_map_value {
    task: *mut task_struct,
}

#[link_section = ".maps"]
#[no_mangle]
static __tasks_kfunc_map: BpfMap<i32, __tasks_kfunc_map_value, { maps::HASH }, 1> = BpfMap::new();

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
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

    fn bpf_task_acquire___one(task: *mut task_struct) -> *mut task_struct;
    /* The two-param bpf_task_acquire doesn't exist */
    fn bpf_task_acquire___two(p: *mut task_struct, ctx: *mut c_void) -> *mut task_struct;
    /* Incorrect type for first param */
    fn bpf_task_acquire___three(ctx: *mut c_void) -> *mut task_struct;

    fn invalid_kfunc();
    fn bpf_testmod_test_mod_kfunc(i: i32);
}

/// C's bpf_ksym_exists(sym): the relocated address, tested at run time
macro_rules! ksym_exists {
    ($f:ident) => {{
        let mut p = $f as usize as *mut c_void;
        sink(&mut p);
        !p.is_null()
    }};
}

#[inline(always)]
fn is_test_kfunc_task() -> bool {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    (unsafe { pid }) == cur_pid
}

/// task_kfunc_common.h: tasks_kfunc_map_value_lookup()
#[inline(always)]
unsafe fn tasks_kfunc_map_value_lookup(p: *mut task_struct) -> *mut __tasks_kfunc_map_value {
    let mut pid_: i32 = 0;

    let status = bpf_probe_read_kernel(&mut pid_, 4, (&*p).pid().as_ptr() as *const c_void);
    if status != 0 {
        return core::ptr::null_mut();
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

    let local = __tasks_kfunc_map_value { task: core::ptr::null_mut() };
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

#[inline(always)]
unsafe fn test_acquire_release(task: *mut task_struct) -> i32 {
    if !ksym_exists!(bpf_task_acquire) {
        err = 3;
        return 0;
    }
    if !ksym_exists!(bpf_testmod_test_mod_kfunc) {
        err = 4;
        return 0;
    }
    if ksym_exists!(invalid_kfunc) {
        /* the verifier's dead code elimination should remove this */
        err = 5;
        // noreturn: otherwise rustc puts the block out of line and lands an
        // unreachable jump back after the loop, which check_cfg rejects
        core::arch::asm!("goto -1", options(noreturn)); /* for (;;); */
    }

    let acquired = bpf_task_acquire(task);
    if !acquired.is_null() {
        bpf_task_release(acquired);
    } else {
        err = 6;
    }

    0
}

// BPF_PROG(test_task_kfunc_flavor_relo, struct task_struct *task, u64 clone_flags)
#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_task_kfunc_flavor_relo(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;
    let mut acquired: *mut task_struct = core::ptr::null_mut();
    let mut fake_ctx: i32 = 42;

    unsafe {
        if ksym_exists!(bpf_task_acquire___one) {
            acquired = bpf_task_acquire___one(task);
        } else if ksym_exists!(bpf_task_acquire___two) {
            /* Here, bpf_object__resolve_ksym_func_btf_id's find_ksym_btf_id
             * call will find vmlinux's bpf_task_acquire, but subsequent
             * bpf_core_types_are_compat will fail
             */
            acquired = bpf_task_acquire___two(task, &mut fake_ctx as *mut i32 as *mut c_void);
            sink(&mut acquired);
            err = 3;
            return 0;
        } else if ksym_exists!(bpf_task_acquire___three) {
            /* bpf_core_types_are_compat will fail similarly to above case */
            acquired = bpf_task_acquire___three(&mut fake_ctx as *mut i32 as *mut c_void);
            sink(&mut acquired);
            err = 4;
            return 0;
        }

        if !acquired.is_null() {
            bpf_task_release(acquired);
        } else {
            err = 5;
        }
    }
    0
}

// BPF_PROG(test_task_kfunc_flavor_relo_not_found, struct task_struct *task, u64 clone_flags)
#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_task_kfunc_flavor_relo_not_found(_ctx: *const u64) -> i32 {
    /* Neither symbol should successfully resolve.
     * Success or failure of one ___flavor should not affect others
     */
    unsafe {
        if ksym_exists!(bpf_task_acquire___two) {
            err = 1;
        } else if ksym_exists!(bpf_task_acquire___three) {
            err = 2;
        }
    }

    0
}

// BPF_PROG(test_task_acquire_release_argument, struct task_struct *task, u64 clone_flags)
#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_task_acquire_release_argument(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    if !is_test_kfunc_task() {
        return 0;
    }

    unsafe { test_acquire_release(task) }
}

// BPF_PROG(test_task_acquire_release_current, struct task_struct *task, u64 clone_flags)
#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_task_acquire_release_current(_ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }

    unsafe { test_acquire_release(bpf_get_current_task_btf()) }
}

// BPF_PROG(test_task_acquire_leave_in_map, struct task_struct *task, u64 clone_flags)
#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_task_acquire_leave_in_map(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    if !is_test_kfunc_task() {
        return 0;
    }

    unsafe {
        let status = tasks_kfunc_map_insert(task);
        if status != 0 {
            err = 1;
        }
    }

    0
}

/* the literal is in a map */
#[link_section = ".rodata.str1.1"]
static FOO: [u8; 4] = *b"foo\0";

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_task_xchg_release(_ctx: *const c_void) -> i32 {
    let mut refcnt: i32 = 0;
    let mut refcnt_after_drop: i32 = 0;

    unsafe {
        let task: *mut task_struct = bpf_get_current_task_btf();
        let status = tasks_kfunc_map_insert(task);
        if status != 0 {
            err = 1;
            return 0;
        }

        let v = tasks_kfunc_map_value_lookup(task);
        if v.is_null() {
            err = 2;
            return 0;
        }

        let kptr = bpf_kptr_xchg(addr_of_mut!((*v).task).cast(), core::ptr::null_mut()) as *mut task_struct;
        if kptr.is_null() {
            err = 3;
            return 0;
        }

        let local = bpf_obj_new(tasks_kfunc_map_value_id()) as *mut __tasks_kfunc_map_value;
        if local.is_null() {
            err = 4;
            bpf_task_release(kptr);
            return 0;
        }

        let kptr = bpf_kptr_xchg(addr_of_mut!((*local).task).cast(), kptr.cast()) as *mut task_struct;
        if !kptr.is_null() {
            err = 5;
            bpf_obj_drop(local.cast());
            bpf_task_release(kptr);
            return 0;
        }

        let kptr = bpf_kptr_xchg(addr_of_mut!((*local).task).cast(), core::ptr::null_mut()) as *mut task_struct;
        if kptr.is_null() {
            err = 6;
            bpf_obj_drop(local.cast());
            return 0;
        }

        /* Stash a copy into local kptr and check if it is released recursively. */
        let acquired = bpf_task_acquire(kptr);
        if acquired.is_null() {
            err = 7;
            bpf_obj_drop(local.cast());
            bpf_task_release(kptr);
            return 0;
        }
        bpf_probe_read_kernel(&mut refcnt, 4, (&*acquired).rcu_users().refs().counter().as_ptr() as *const c_void);

        let acquired = bpf_kptr_xchg(addr_of_mut!((*local).task).cast(), acquired.cast()) as *mut task_struct;
        if !acquired.is_null() {
            err = 8;
            bpf_obj_drop(local.cast());
            bpf_task_release(kptr);
            bpf_task_release(acquired);
            return 0;
        }

        bpf_obj_drop(local.cast());

        bpf_probe_read_kernel(&mut refcnt_after_drop, 4, (&*kptr).rcu_users().refs().counter().as_ptr() as *const c_void);
        if refcnt != refcnt_after_drop.wrapping_add(1) {
            err = 9;
            bpf_task_release(kptr);
            return 0;
        }

        bpf_task_release(kptr);
    }
    0
}

// BPF_PROG(test_task_map_acquire_release, struct task_struct *task, u64 clone_flags)
#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_task_map_acquire_release(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *mut task_struct;

    if !is_test_kfunc_task() {
        return 0;
    }

    unsafe {
        let status = tasks_kfunc_map_insert(task);
        if status != 0 {
            err = 1;
            return 0;
        }

        let v = tasks_kfunc_map_value_lookup(task);
        if v.is_null() {
            err = 2;
            return 0;
        }

        bpf_rcu_read_lock();
        let kptr = (*v).task;
        if kptr.is_null() {
            err = 3;
        } else {
            let kptr = bpf_task_acquire(kptr);
            if kptr.is_null() {
                err = 4;
            } else {
                bpf_task_release(kptr);
            }
        }
        bpf_rcu_read_unlock();
    }

    0
}

// BPF_PROG(test_task_current_acquire_release, struct task_struct *task, u64 clone_flags)
#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_task_current_acquire_release(_ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }

    unsafe {
        let current: *mut task_struct = bpf_get_current_task_btf();
        let acquired = bpf_task_acquire(current);
        if !acquired.is_null() {
            bpf_task_release(acquired);
        } else {
            err = 1;
        }
    }

    0
}

#[inline(always)]
unsafe fn lookup_compare_pid(p: *const task_struct) {
    let p_pid = *(&*p).pid().as_ptr();
    let acquired = bpf_task_from_pid(p_pid);
    if acquired.is_null() {
        err = 1;
        return;
    }

    if *(&*acquired).pid().as_ptr() != *(&*p).pid().as_ptr() {
        err = 2;
    }
    bpf_task_release(acquired);
}

// BPF_PROG(test_task_from_pid_arg, struct task_struct *task, u64 clone_flags)
#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_task_from_pid_arg(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *const task_struct;

    if !is_test_kfunc_task() {
        return 0;
    }

    unsafe { lookup_compare_pid(task) };
    0
}

// BPF_PROG(test_task_from_pid_current, struct task_struct *task, u64 clone_flags)
#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_task_from_pid_current(_ctx: *const u64) -> i32 {
    if !is_test_kfunc_task() {
        return 0;
    }

    unsafe { lookup_compare_pid(bpf_get_current_task_btf()) };
    0
}

#[inline(always)]
unsafe fn is_pid_lookup_valid(lookup_pid: i32) -> i32 {
    let acquired = bpf_task_from_pid(lookup_pid);
    if !acquired.is_null() {
        bpf_task_release(acquired);
        return 1;
    }

    0
}

// BPF_PROG(test_task_from_pid_invalid, struct task_struct *task, u64 clone_flags)
#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_task_from_pid_invalid(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *const task_struct;

    if !is_test_kfunc_task() {
        return 0;
    }

    unsafe {
        let comm = (&*task).comm().as_ptr() as *const u8;
        bpf_strncmp(comm as *const c_void, 12, FOO.as_ptr() as *const c_void);
        bpf_strncmp(comm as *const c_void, 16, FOO.as_ptr() as *const c_void);
        bpf_strncmp(comm.add(8) as *const c_void, 4, FOO.as_ptr() as *const c_void);

        if is_pid_lookup_valid(-1) != 0 {
            err = 1;
            return 0;
        }

        if is_pid_lookup_valid(0xcafef00du32 as i32) != 0 {
            err = 2;
            return 0;
        }
    }

    0
}

// BPF_PROG(task_kfunc_acquire_trusted_walked, struct task_struct *task, u64 clone_flags)
#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_trusted_walked(ctx: *const u64) -> i32 {
    let task = arg(ctx, 0) as *const task_struct;

    unsafe {
        /* task->group_leader is listed as a trusted, non-NULL field of task struct. */
        let acquired = bpf_task_acquire(*(&*task).group_leader().as_ptr());
        if !acquired.is_null() {
            bpf_task_release(acquired);
        } else {
            err = 1;
        }
    }

    0
}

/// the lock map's one element, or null
#[inline(always)]
fn lock_value() -> *mut task_kptr_lock_value {
    let key: i32 = 0;

    bpf_map_lookup_elem(&task_kptr_lock_map, &key) as *mut task_kptr_lock_value
}

/// `acquired = bpf_task_acquire(task); if (acquired) bpf_task_release(acquired);`
#[inline(always)]
unsafe fn acquire_release(task: *mut task_struct) {
    let acquired = bpf_task_acquire(task);
    if !acquired.is_null() {
        bpf_task_release(acquired);
    }
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_after_spin_unlock_non_sleepable(_ctx: *const u64) -> i32 {
    let v = lock_value();
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

        acquire_release(task);
    }
    0
}

#[link_section = "fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_after_spin_unlock_explicit_rcu(_ctx: *const u64) -> i32 {
    let v = lock_value();
    if v.is_null() {
        return 0;
    }

    unsafe {
        bpf_rcu_read_lock();
        bpf_spin_lock(addr_of_mut!((*v).lock));
        let task = (*v).task;
        bpf_spin_unlock(addr_of_mut!((*v).lock));
        if !task.is_null() {
            acquire_release(task);
        }
        bpf_rcu_read_unlock();
    }
    0
}

#[link_section = "fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_after_spin_unlock_preempt_disabled(_ctx: *const u64) -> i32 {
    let v = lock_value();
    if v.is_null() {
        return 0;
    }

    unsafe {
        bpf_preempt_disable();
        bpf_spin_lock(addr_of_mut!((*v).lock));
        let task = (*v).task;
        bpf_spin_unlock(addr_of_mut!((*v).lock));
        if !task.is_null() {
            acquire_release(task);
        }
        bpf_preempt_enable();
    }
    0
}

#[link_section = "fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_after_spin_unlock_irq_disabled(_ctx: *const u64) -> i32 {
    // flags is the C's last local: at fp-8, where the prover keys the kfunc's
    // out-pointer, so it is declared after the key (rustc places the last
    // local at fp-8, clang the first)
    let key: i32 = 0;
    let v = bpf_map_lookup_elem(&task_kptr_lock_map, &key) as *mut task_kptr_lock_value;
    if v.is_null() {
        return 0;
    }
    let mut flags = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags.as_mut_ptr());
        bpf_spin_lock(addr_of_mut!((*v).lock));
        let task = (*v).task;
        bpf_spin_unlock(addr_of_mut!((*v).lock));
        if !task.is_null() {
            acquire_release(task);
        }
        bpf_local_irq_restore(flags.as_mut_ptr());
    }
    0
}

#[link_section = "fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_after_rcu_unlock_preempt_disabled(_ctx: *const u64) -> i32 {
    let v = lock_value();
    if v.is_null() {
        return 0;
    }

    unsafe {
        bpf_preempt_disable();
        bpf_rcu_read_lock();
        let task = (*v).task;
        bpf_rcu_read_unlock();
        if !task.is_null() {
            acquire_release(task);
        }
        bpf_preempt_enable();
    }
    0
}

#[link_section = "fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_after_rcu_unlock_irq_disabled(_ctx: *const u64) -> i32 {
    // flags is the C's last local: at fp-8, where the prover keys the kfunc's
    // out-pointer, so it is declared after the key (rustc places the last
    // local at fp-8, clang the first)
    let key: i32 = 0;
    let v = bpf_map_lookup_elem(&task_kptr_lock_map, &key) as *mut task_kptr_lock_value;
    if v.is_null() {
        return 0;
    }
    let mut flags = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags.as_mut_ptr());
        bpf_rcu_read_lock();
        let task = (*v).task;
        bpf_rcu_read_unlock();
        if !task.is_null() {
            acquire_release(task);
        }
        bpf_local_irq_restore(flags.as_mut_ptr());
    }
    0
}

#[link_section = "fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_after_preempt_enable_explicit_rcu(_ctx: *const u64) -> i32 {
    let v = lock_value();
    if v.is_null() {
        return 0;
    }

    unsafe {
        bpf_preempt_disable();
        let task = (*v).task;
        bpf_rcu_read_lock();
        bpf_preempt_enable();
        if !task.is_null() {
            acquire_release(task);
        }
        bpf_rcu_read_unlock();
    }
    0
}

#[link_section = "fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_kfunc_acquire_after_irq_restore_explicit_rcu(_ctx: *const u64) -> i32 {
    // flags is the C's last local: at fp-8, where the prover keys the kfunc's
    // out-pointer, so it is declared after the key (rustc places the last
    // local at fp-8, clang the first)
    let key: i32 = 0;
    let v = bpf_map_lookup_elem(&task_kptr_lock_map, &key) as *mut task_kptr_lock_value;
    if v.is_null() {
        return 0;
    }
    let mut flags = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags.as_mut_ptr());
        let task = (*v).task;
        bpf_rcu_read_lock();
        bpf_local_irq_restore(flags.as_mut_ptr());
        if !task.is_null() {
            acquire_release(task);
        }
        bpf_rcu_read_unlock();
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_task_from_vpid_current(_ctx: *const c_void) -> i32 {
    unsafe {
        let v_task = bpf_task_from_vpid(1);
        if v_task.is_null() {
            err = 1;
            return 0;
        }

        let current: *mut task_struct = bpf_get_current_task_btf();

        /* The current process should be the init process (pid 1) in the new pid namespace. */
        if current != v_task {
            err = 2;
        }

        bpf_task_release(v_task);
    }
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_task_from_vpid_invalid(_ctx: *const c_void) -> i32 {
    unsafe {
        let v_task: *mut task_struct = 'err: {
            let v_task = bpf_task_from_vpid(-1);
            if !v_task.is_null() {
                err = 1;
                break 'err v_task;
            }

            /* There should be only one process (current process) in the new pid namespace. */
            let v_task = bpf_task_from_vpid(2);
            if !v_task.is_null() {
                err = 2;
                break 'err v_task;
            }

            let v_task = bpf_task_from_vpid(9999);
            if !v_task.is_null() {
                err = 3;
                break 'err v_task;
            }

            return 0;
        };
        // err:
        bpf_task_release(v_task);
    }
    0
}

bpf_object!("GPL");
