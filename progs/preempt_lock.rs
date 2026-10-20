// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/preempt_lock.c
// (bpf-rs-core idiom): bpf_preempt_disable/enable balance checked by the
// verifier across exits, static subprograms and global subprograms, and
// the sleepable helpers / kfuncs it refuses inside a non-preemptible or
// RCU region. The C's bpf_guard_preempt() is a cleanup-attribute pair of
// the two kfuncs. The test_loader decl tags are declared with test_tags!
// and appended to the object's BTF by scripts/btf_test_tags.py.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_copy_from_user, bpf_get_current_task_btf, bpf_get_stack, bpf_get_task_stack,
    bpf_trace_printk,
};
use bpf_rs_core::test_tags;
use btf_macros::btf;
use core::ffi::c_void;
use core::mem::MaybeUninit;

const BPF_F_USER_STACK: u64 = 1 << 8;
const BPF_F_USER_BUILD_ID: u64 = 1 << 11;
const BPF_BUILD_ID_SIZE: usize = 20;

#[btf]
struct task_struct {}

#[btf]
struct pt_regs {}

#[repr(C)]
struct bpf_stack_build_id {
    status: i32,
    build_id: [u8; BPF_BUILD_ID_SIZE],
    offset_or_ip: u64,
}

// C: extern int bpf_copy_from_user_str(...) __weak __ksym;
// BTF_WEAK_KFUNC: bpf_copy_from_user_str
extern "C" {
    fn bpf_copy_from_user_str(dst: *mut c_void, dst__sz: u32, unsafe_ptr__ign: *const c_void, flags: u64) -> i32;
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn bpf_preempt_disable();
    fn bpf_preempt_enable();
}

test_tags! {
    preempt_lock_missing_1: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_preempt_disable-ed region");
    preempt_lock_missing_2: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_preempt_disable-ed region");
    preempt_lock_missing_3: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_preempt_disable-ed region");
    preempt_lock_missing_3_minus_2: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_preempt_disable-ed region");
    preempt_lock_missing_1_subprog: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_preempt_disable-ed region");
    preempt_lock_missing_2_subprog: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_preempt_disable-ed region");
    preempt_lock_missing_2_minus_1_subprog: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_preempt_disable-ed region");
    preempt_balance: __success;
    preempt_balance_subprog_test: __success;
    preempt_sleepable_helper: __failure, __msg("sleepable helper bpf_copy_from_user#");
    preempt_sleepable_get_stack: __failure, __msg("sleepable helper bpf_get_stack#");
    preempt_sleepable_get_task_stack: __failure, __msg("sleepable helper bpf_get_task_stack#");
    sleepable_get_stack: __success;
    sleepable_get_task_stack: __success;
    preempt_sleepable_kfunc: __failure, __msg("kernel func bpf_copy_from_user_str is sleepable within non-preemptible region");
    non_sleepable_kfunc: __failure, __msg("program must be sleepable to call sleepable kfunc bpf_copy_from_user_str"), __msg("cannot be used in non-sleepable program");
    sleepable_kfunc_in_rcu: __failure, __msg("kernel func bpf_copy_from_user_str is sleepable within rcu_read_lock region"), __msg("cannot be used in RCU read lock region");
    preempt_global_subprog_test: __success;
    preempt_global_sleepable_helper_subprog: __failure, __msg("sleepable global function");
    preempt_global_sleepable_kfunc_subprog: __failure, __msg("sleepable global function");
    preempt_global_sleepable_subprog_indirect: __failure, __msg("sleepable global function");
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn preempt_lock_missing_1(_ctx: *mut __sk_buff) -> i32 {
    unsafe { bpf_preempt_disable() };
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn preempt_lock_missing_2(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        bpf_preempt_disable();
        bpf_preempt_disable();
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn preempt_lock_missing_3(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        bpf_preempt_disable();
        bpf_preempt_disable();
        bpf_preempt_disable();
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn preempt_lock_missing_3_minus_2(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        bpf_preempt_disable();
        bpf_preempt_disable();
        bpf_preempt_disable();
        bpf_preempt_enable();
        bpf_preempt_enable();
    }
    0
}

// C: static __noinline void preempt_disable(void) / preempt_enable(void)
#[no_mangle]
#[inline(never)]
extern "C" fn preempt_disable() {
    unsafe { bpf_preempt_disable() };
}

#[no_mangle]
#[inline(never)]
extern "C" fn preempt_enable() {
    unsafe { bpf_preempt_enable() };
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn preempt_lock_missing_1_subprog(_ctx: *mut __sk_buff) -> i32 {
    preempt_disable();
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn preempt_lock_missing_2_subprog(_ctx: *mut __sk_buff) -> i32 {
    preempt_disable();
    preempt_disable();
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn preempt_lock_missing_2_minus_1_subprog(_ctx: *mut __sk_buff) -> i32 {
    preempt_disable();
    preempt_disable();
    preempt_enable();
    0
}

// C: static __noinline void preempt_balance_subprog(void)
#[no_mangle]
#[inline(never)]
extern "C" fn preempt_balance_subprog() {
    preempt_disable();
    preempt_enable();
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn preempt_balance(_ctx: *mut __sk_buff) -> i32 {
    // C: bpf_guard_preempt(); -- disable now, the cleanup enables at scope exit
    unsafe {
        bpf_preempt_disable();
        bpf_preempt_enable();
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn preempt_balance_subprog_test(_ctx: *mut __sk_buff) -> i32 {
    preempt_balance_subprog();
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn preempt_sleepable_helper(_ctx: *mut c_void) -> i32 {
    let mut data = MaybeUninit::<u32>::uninit();
    unsafe { bpf_preempt_disable() };
    bpf_copy_from_user(data.as_mut_ptr() as *mut c_void, 4, core::ptr::null());
    unsafe { bpf_preempt_enable() };
    0
}

#[link_section = "?uprobe.s"]
#[no_mangle]
extern "C" fn preempt_sleepable_get_stack(ctx: *mut pt_regs) -> i32 {
    let mut stack = MaybeUninit::<bpf_stack_build_id>::uninit();
    unsafe { bpf_preempt_disable() };
    bpf_get_stack(
        ctx as *const c_void,
        stack.as_mut_ptr() as *mut c_void,
        core::mem::size_of::<bpf_stack_build_id>() as u32,
        BPF_F_USER_STACK | BPF_F_USER_BUILD_ID,
    );
    unsafe { bpf_preempt_enable() };
    0
}

#[link_section = "?uprobe.s"]
#[no_mangle]
extern "C" fn preempt_sleepable_get_task_stack(_ctx: *mut c_void) -> i32 {
    let mut stack = MaybeUninit::<bpf_stack_build_id>::uninit();
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_preempt_disable() };
    bpf_get_task_stack(
        task,
        stack.as_mut_ptr() as *mut c_void,
        core::mem::size_of::<bpf_stack_build_id>() as u32,
        BPF_F_USER_STACK | BPF_F_USER_BUILD_ID,
    );
    unsafe { bpf_preempt_enable() };
    0
}

#[link_section = "?uprobe.s"]
#[no_mangle]
extern "C" fn sleepable_get_stack(ctx: *mut pt_regs) -> i32 {
    let mut stack = MaybeUninit::<bpf_stack_build_id>::uninit();
    bpf_get_stack(
        ctx as *const c_void,
        stack.as_mut_ptr() as *mut c_void,
        core::mem::size_of::<bpf_stack_build_id>() as u32,
        BPF_F_USER_STACK | BPF_F_USER_BUILD_ID,
    );
    0
}

#[link_section = "?uprobe.s"]
#[no_mangle]
extern "C" fn sleepable_get_task_stack(_ctx: *mut c_void) -> i32 {
    let mut stack = MaybeUninit::<bpf_stack_build_id>::uninit();
    let task: *mut task_struct = bpf_get_current_task_btf();
    bpf_get_task_stack(
        task,
        stack.as_mut_ptr() as *mut c_void,
        core::mem::size_of::<bpf_stack_build_id>() as u32,
        BPF_F_USER_STACK | BPF_F_USER_BUILD_ID,
    );
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn preempt_sleepable_kfunc(_ctx: *mut c_void) -> i32 {
    let mut data = MaybeUninit::<u32>::uninit();
    unsafe {
        bpf_preempt_disable();
        bpf_copy_from_user_str(data.as_mut_ptr() as *mut c_void, 4, core::ptr::null(), 0);
        bpf_preempt_enable();
    }
    0
}

#[link_section = "?fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn non_sleepable_kfunc(_ctx: *mut c_void) -> i32 {
    let mut data = MaybeUninit::<u32>::uninit();
    unsafe { bpf_copy_from_user_str(data.as_mut_ptr() as *mut c_void, 4, core::ptr::null(), 0) };
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn sleepable_kfunc_in_rcu(_ctx: *mut c_void) -> i32 {
    let mut data = MaybeUninit::<u32>::uninit();
    unsafe {
        bpf_rcu_read_lock();
        bpf_copy_from_user_str(data.as_mut_ptr() as *mut c_void, 4, core::ptr::null(), 0);
        bpf_rcu_read_unlock();
    }
    0
}

// C: int __noinline preempt_global_subprog(void)
#[no_mangle]
#[inline(never)]
pub extern "C" fn preempt_global_subprog() -> i32 {
    preempt_balance_subprog();
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn preempt_global_subprog_test(_ctx: *mut __sk_buff) -> i32 {
    preempt_disable();
    preempt_global_subprog();
    preempt_enable();
    0
}

// C: int __noinline global_subprog(int i) { if (i) bpf_printk("%p", &i); return i; }
#[no_mangle]
#[inline(never)]
pub extern "C" fn global_subprog(mut i: i32) -> i32 {
    if i != 0 {
        static FMT: &[u8] = b"%p\0";
        bpf_trace_printk(
            FMT.as_ptr() as *const c_void,
            FMT.len() as u32,
            core::ptr::addr_of_mut!(i) as u64,
            0,
            0,
        );
    }
    i
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn global_sleepable_helper_subprog(mut i: i32) -> i32 {
    if i != 0 {
        bpf_copy_from_user(core::ptr::addr_of_mut!(i) as *mut c_void, 4, core::ptr::null());
    }
    i
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn global_sleepable_kfunc_subprog(mut i: i32) -> i32 {
    if i != 0 {
        unsafe { bpf_copy_from_user_str(core::ptr::addr_of_mut!(i) as *mut c_void, 4, core::ptr::null(), 0) };
    }
    global_subprog(i);
    i
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn global_subprog_calling_sleepable_global(i: i32) -> i32 {
    if i == 0 {
        global_sleepable_kfunc_subprog(i);
    }
    i
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn preempt_global_sleepable_helper_subprog(ctx: *mut __sk_buff) -> i32 {
    preempt_disable();
    let mark = unsafe { (*ctx).mark };
    if mark != 0 {
        global_sleepable_helper_subprog(mark as i32);
    }
    preempt_enable();
    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn preempt_global_sleepable_kfunc_subprog(ctx: *mut __sk_buff) -> i32 {
    preempt_disable();
    let mark = unsafe { (*ctx).mark };
    if mark != 0 {
        global_sleepable_kfunc_subprog(mark as i32);
    }
    preempt_enable();
    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn preempt_global_sleepable_subprog_indirect(ctx: *mut __sk_buff) -> i32 {
    preempt_disable();
    let mark = unsafe { (*ctx).mark };
    if mark != 0 {
        global_subprog_calling_sleepable_global(mark as i32);
    }
    preempt_enable();
    0
}

bpf_object!("GPL");
