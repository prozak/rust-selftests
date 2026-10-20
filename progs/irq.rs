// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/irq.c
// (bpf-rs-core idiom): the verifier's tracking of bpf_local_irq_save /
// bpf_local_irq_restore -- flags on the stack only, every save restored
// before exit, restores in reverse order, no sleepable helper, kfunc or
// global subprogram inside the region, the saved-flag slot neither read
// nor overwritten, and the irqsave variants of bpf_res_spin_lock. The
// irqsave flags are MaybeUninit<u64> locals declared in the reverse of
// the C's order (rustc gives the later-declared local the higher frame
// slot, clang the earlier one) so the positives' kfunc pointer arguments
// sit at clang's fp-8 / fp-16 / fp-24 for the prover. C's `__noinline`
// static helpers are #[inline(never)], the global ones #[no_mangle] too
// (exceptions_fail.rs); the `__weak __ksym` externs carry BTF_WEAK_KFUNC;
// the anonymous `struct { int i; }` of bpf_obj_new is named for its
// BTF_TYPE_ID as in res_spin_lock_fail.rs; the hidden per-section locks
// are private statics in .data.A / .data.B. The test_loader decl tags
// are declared with test_tags! (scripts/btf_test_tags.py).

// BTF_TYPE_ID: anon_i_id local struct anon_i (anonymous)
// BTF_WEAK_KFUNC: bpf_local_irq_save
// BTF_WEAK_KFUNC: bpf_local_irq_restore
// BTF_WEAK_KFUNC: bpf_copy_from_user_str

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_copy_from_user, bpf_trace_printk};
use bpf_rs_core::test_tags;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_res_spin_lock {
    val: u32,
}

// struct bpf_iter_num { __u64 __opaque[1]; } __attribute__((aligned(8)));
#[repr(C, align(8))]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

// C: struct { int i; } *p = bpf_obj_new(typeof(*p)); -- the anonymous
// local type, named here for the BTF_TYPE_ID above.
#[allow(non_camel_case_types)]
#[repr(C)]
struct anon_i {
    i: i32,
}

#[no_mangle]
static mut global_flags: u64 = 0;

// C: struct bpf_res_spin_lock lockA __hidden SEC(".data.A");
//    struct bpf_res_spin_lock lockB __hidden SEC(".data.B");
#[allow(non_upper_case_globals)]
#[link_section = ".data.A"]
static mut lockA: bpf_res_spin_lock = bpf_res_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[link_section = ".data.B"]
static mut lockB: bpf_res_spin_lock = bpf_res_spin_lock { val: 0 };

extern "C" {
    fn anon_i_id() -> u64;
    fn bpf_local_irq_save(flags: *mut u64);
    fn bpf_local_irq_restore(flags: *mut u64);
    fn bpf_copy_from_user_str(dst: *mut c_void, dst__sz: u32, unsafe_ptr__ign: *const c_void, flags: u64) -> i32;
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_obj_new(local_type_id: u64) -> *mut c_void;
    fn bpf_obj_drop(obj: *mut c_void);
    fn bpf_res_spin_lock_irqsave(lock: *mut bpf_res_spin_lock, flags: *mut u64) -> i32;
    fn bpf_res_spin_unlock_irqrestore(lock: *mut bpf_res_spin_lock, flags: *mut u64);
}

test_tags! {
    irq_flag_direct_read: __failure, __msg("invalid read from stack"), __msg("Verification failed: Memory Safety: Direct read of IRQ flag stack state"), __msg("verifier-managed IRQ flag state"), __msg("Pass the saved IRQ flag to the matching restore kfunc");
    irq_save_bad_arg: __failure, __msg("R1 type=map_value expected=fp");
    irq_restore_bad_arg: __failure, __msg("R1 type=map_value expected=fp");
    irq_restore_missing_2: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region");
    irq_restore_missing_3: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region");
    irq_restore_missing_3_minus_2: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region");
    irq_restore_missing_1_subprog: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region");
    irq_restore_missing_2_subprog: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region");
    irq_restore_missing_3_subprog: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region");
    irq_restore_missing_3_minus_2_subprog: __failure, __msg("BPF_EXIT instruction in main prog cannot be used inside bpf_local_irq_save-ed region");
    irq_balance: __success;
    irq_balance_n: __success;
    irq_balance_subprog: __success;
    irq_sleepable_helper: __failure, __msg("sleepable helper bpf_copy_from_user#");
    irq_sleepable_kfunc: __failure, __msg("kernel func bpf_copy_from_user_str is sleepable within IRQ-disabled region");
    irq_global_subprog: __success;
    irq_restore_ooo: __failure, __msg("cannot restore irq state out of order");
    irq_restore_ooo_3: __failure, __msg("cannot restore irq state out of order");
    irq_restore_3_subprog: __success;
    irq_restore_4_subprog: __failure, __msg("cannot restore irq state out of order");
    irq_restore_ooo_3_subprog: __failure, __msg("cannot restore irq state out of order");
    irq_restore_invalid: __failure, __msg("expected an initialized");
    irq_save_invalid: __failure, __msg("expected uninitialized");
    irq_restore_iter: __failure, __msg("expected an initialized");
    irq_save_iter: __failure, __msg("Unreleased reference id=1");
    irq_flag_overwrite: __failure, __msg("expected an initialized");
    irq_flag_overwrite_partial: __failure, __msg("expected an initialized");
    irq_ooo_refs_array: __failure, __msg("cannot restore irq state out of order");
    irq_non_sleepable_global_subprog: __success;
    irq_sleepable_helper_global_subprog: __failure, __msg("sleepable global function");
    irq_sleepable_global_subprog_indirect: __failure, __msg("sleepable global function");
    irq_ooo_lock_cond_inv: __failure, __msg("cannot restore irq state out of order");
    irq_wrong_kfunc_class_1: __failure, __msg("function calls are not allowed");
    irq_wrong_kfunc_class_2: __failure, __msg("function calls are not allowed");
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_flag_direct_read(_ctx: *mut __sk_buff) -> i32 {
    let mut flags = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags.as_mut_ptr());
        // C: return flags; -- a direct read of the verifier-managed slot
        flags.assume_init() as i32
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_save_bad_arg(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        bpf_local_irq_save(addr_of_mut!(global_flags));
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_bad_arg(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        bpf_local_irq_restore(addr_of_mut!(global_flags));
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_missing_2(_ctx: *mut __sk_buff) -> i32 {
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags1.as_mut_ptr());
        bpf_local_irq_save(flags2.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_missing_3(_ctx: *mut __sk_buff) -> i32 {
    let mut flags3 = MaybeUninit::<u64>::uninit();
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags1.as_mut_ptr());
        bpf_local_irq_save(flags2.as_mut_ptr());
        bpf_local_irq_save(flags3.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_missing_3_minus_2(_ctx: *mut __sk_buff) -> i32 {
    let mut flags3 = MaybeUninit::<u64>::uninit();
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags1.as_mut_ptr());
        bpf_local_irq_save(flags2.as_mut_ptr());
        bpf_local_irq_save(flags3.as_mut_ptr());
        bpf_local_irq_restore(flags3.as_mut_ptr());
        bpf_local_irq_restore(flags2.as_mut_ptr());
    }
    0
}

// C: static __noinline void local_irq_save(unsigned long *flags)
#[inline(never)]
fn local_irq_save(flags: *mut u64) {
    unsafe {
        bpf_local_irq_save(flags);
    }
}

// C: static __noinline void local_irq_restore(unsigned long *flags)
#[inline(never)]
fn local_irq_restore(flags: *mut u64) {
    unsafe {
        bpf_local_irq_restore(flags);
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_missing_1_subprog(_ctx: *mut __sk_buff) -> i32 {
    let mut flags = MaybeUninit::<u64>::uninit();

    local_irq_save(flags.as_mut_ptr());
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_missing_2_subprog(_ctx: *mut __sk_buff) -> i32 {
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    local_irq_save(flags1.as_mut_ptr());
    local_irq_save(flags2.as_mut_ptr());
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_missing_3_subprog(_ctx: *mut __sk_buff) -> i32 {
    let mut flags3 = MaybeUninit::<u64>::uninit();
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    local_irq_save(flags1.as_mut_ptr());
    local_irq_save(flags2.as_mut_ptr());
    local_irq_save(flags3.as_mut_ptr());
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_missing_3_minus_2_subprog(_ctx: *mut __sk_buff) -> i32 {
    let mut flags3 = MaybeUninit::<u64>::uninit();
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    local_irq_save(flags1.as_mut_ptr());
    local_irq_save(flags2.as_mut_ptr());
    local_irq_save(flags3.as_mut_ptr());
    local_irq_restore(flags3.as_mut_ptr());
    local_irq_restore(flags2.as_mut_ptr());
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_balance(_ctx: *mut __sk_buff) -> i32 {
    let mut flags = MaybeUninit::<u64>::uninit();

    local_irq_save(flags.as_mut_ptr());
    local_irq_restore(flags.as_mut_ptr());
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_balance_n(_ctx: *mut __sk_buff) -> i32 {
    let mut flags3 = MaybeUninit::<u64>::uninit();
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    local_irq_save(flags1.as_mut_ptr());
    local_irq_save(flags2.as_mut_ptr());
    local_irq_save(flags3.as_mut_ptr());
    local_irq_restore(flags3.as_mut_ptr());
    local_irq_restore(flags2.as_mut_ptr());
    local_irq_restore(flags1.as_mut_ptr());
    0
}

// C: static __noinline void local_irq_balance(void)
#[inline(never)]
fn local_irq_balance() {
    let mut flags = MaybeUninit::<u64>::uninit();

    local_irq_save(flags.as_mut_ptr());
    local_irq_restore(flags.as_mut_ptr());
}

// C: static __noinline void local_irq_balance_n(void)
#[inline(never)]
fn local_irq_balance_n() {
    let mut flags3 = MaybeUninit::<u64>::uninit();
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    local_irq_save(flags1.as_mut_ptr());
    local_irq_save(flags2.as_mut_ptr());
    local_irq_save(flags3.as_mut_ptr());
    local_irq_restore(flags3.as_mut_ptr());
    local_irq_restore(flags2.as_mut_ptr());
    local_irq_restore(flags1.as_mut_ptr());
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_balance_subprog(_ctx: *mut __sk_buff) -> i32 {
    local_irq_balance();
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn irq_sleepable_helper(_ctx: *mut c_void) -> i32 {
    let mut data = MaybeUninit::<u32>::uninit();
    let mut flags = MaybeUninit::<u64>::uninit();

    local_irq_save(flags.as_mut_ptr());
    bpf_copy_from_user(data.as_mut_ptr() as *mut c_void, 4, core::ptr::null());
    local_irq_restore(flags.as_mut_ptr());
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn irq_sleepable_kfunc(_ctx: *mut c_void) -> i32 {
    let mut data = MaybeUninit::<u32>::uninit();
    let mut flags = MaybeUninit::<u64>::uninit();

    local_irq_save(flags.as_mut_ptr());
    unsafe {
        bpf_copy_from_user_str(data.as_mut_ptr() as *mut c_void, 4, core::ptr::null(), 0);
    }
    local_irq_restore(flags.as_mut_ptr());
    0
}

// C: int __noinline global_local_irq_balance(void)
#[no_mangle]
#[inline(never)]
pub extern "C" fn global_local_irq_balance() -> i32 {
    local_irq_balance_n();
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_global_subprog(_ctx: *mut __sk_buff) -> i32 {
    let mut flags = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags.as_mut_ptr());
        global_local_irq_balance();
        bpf_local_irq_restore(flags.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_ooo(_ctx: *mut __sk_buff) -> i32 {
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags1.as_mut_ptr());
        bpf_local_irq_save(flags2.as_mut_ptr());
        bpf_local_irq_restore(flags1.as_mut_ptr());
        bpf_local_irq_restore(flags2.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_ooo_3(_ctx: *mut __sk_buff) -> i32 {
    let mut flags3 = MaybeUninit::<u64>::uninit();
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags1.as_mut_ptr());
        bpf_local_irq_save(flags2.as_mut_ptr());
        bpf_local_irq_restore(flags2.as_mut_ptr());
        bpf_local_irq_save(flags3.as_mut_ptr());
        bpf_local_irq_restore(flags1.as_mut_ptr());
        bpf_local_irq_restore(flags3.as_mut_ptr());
    }
    0
}

// C: static __noinline void local_irq_save_3(unsigned long *flags1,
//                                            unsigned long *flags2,
//                                            unsigned long *flags3)
#[inline(never)]
fn local_irq_save_3(flags1: *mut u64, flags2: *mut u64, flags3: *mut u64) {
    local_irq_save(flags1);
    local_irq_save(flags2);
    local_irq_save(flags3);
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_3_subprog(_ctx: *mut __sk_buff) -> i32 {
    let mut flags3 = MaybeUninit::<u64>::uninit();
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    local_irq_save_3(flags1.as_mut_ptr(), flags2.as_mut_ptr(), flags3.as_mut_ptr());
    unsafe {
        bpf_local_irq_restore(flags3.as_mut_ptr());
        bpf_local_irq_restore(flags2.as_mut_ptr());
        bpf_local_irq_restore(flags1.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_4_subprog(_ctx: *mut __sk_buff) -> i32 {
    let mut flags4 = MaybeUninit::<u64>::uninit();
    let mut flags3 = MaybeUninit::<u64>::uninit();
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    local_irq_save_3(flags1.as_mut_ptr(), flags2.as_mut_ptr(), flags3.as_mut_ptr());
    unsafe {
        bpf_local_irq_restore(flags3.as_mut_ptr());
        bpf_local_irq_save(flags4.as_mut_ptr());
        bpf_local_irq_restore(flags4.as_mut_ptr());
        bpf_local_irq_restore(flags1.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_ooo_3_subprog(_ctx: *mut __sk_buff) -> i32 {
    let mut flags3 = MaybeUninit::<u64>::uninit();
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    local_irq_save_3(flags1.as_mut_ptr(), flags2.as_mut_ptr(), flags3.as_mut_ptr());
    unsafe {
        bpf_local_irq_restore(flags3.as_mut_ptr());
        bpf_local_irq_restore(flags2.as_mut_ptr());
        bpf_local_irq_save(flags3.as_mut_ptr());
        bpf_local_irq_restore(flags1.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_invalid(_ctx: *mut __sk_buff) -> i32 {
    let mut flags: u64 = 0xfaceb00c;
    let mut flags1 = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags1.as_mut_ptr());
        bpf_local_irq_restore(addr_of_mut!(flags));
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_save_invalid(_ctx: *mut __sk_buff) -> i32 {
    let mut flags1 = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags1.as_mut_ptr());
        bpf_local_irq_save(flags1.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_restore_iter(_ctx: *mut __sk_buff) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr(), 0, 42);
        bpf_local_irq_restore(it.as_mut_ptr() as *mut u64);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_save_iter(_ctx: *mut __sk_buff) -> i32 {
    let mut it = MaybeUninit::<bpf_iter_num>::uninit();

    /* Ensure same sized slot has st->ref_obj_id set, so we reject based on
     * slot_type != STACK_IRQ_FLAG...
     */
    const _: () = assert!(core::mem::size_of::<bpf_iter_num>() == core::mem::size_of::<u64>(), "broken iterator size");

    unsafe {
        bpf_iter_num_new(it.as_mut_ptr(), 0, 42);
        bpf_local_irq_save(it.as_mut_ptr() as *mut u64);
        bpf_local_irq_restore(it.as_mut_ptr() as *mut u64);
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_flag_overwrite(_ctx: *mut __sk_buff) -> i32 {
    let mut flags = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags.as_mut_ptr());
        // C: flags = 0xdeadbeef;
        flags.as_mut_ptr().write(0xdeadbeef_u64);
        bpf_local_irq_restore(flags.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_flag_overwrite_partial(_ctx: *mut __sk_buff) -> i32 {
    let mut flags = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags.as_mut_ptr());
        // C: *(((char *)&flags) + 1) = 0xff;
        (flags.as_mut_ptr() as *mut u8).add(1).write(0xff);
        bpf_local_irq_restore(flags.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_ooo_refs_array(_ctx: *mut __sk_buff) -> i32 {
    let mut flags = MaybeUninit::<[u64; 4]>::uninit();
    let f = flags.as_mut_ptr() as *mut u64;

    unsafe {
        /* refs=1 */
        bpf_local_irq_save(f.add(0));

        /* refs=1,2 */
        let p = bpf_obj_new(anon_i_id()) as *mut anon_i;
        if p.is_null() {
            bpf_local_irq_restore(f.add(0));
            return 0;
        }

        /* refs=1,2,3 */
        bpf_local_irq_save(f.add(1));

        /* refs=1,2,3,4 */
        bpf_local_irq_save(f.add(2));

        /* Now when we remove ref=2, the verifier must not break the ordering in
         * the refs array between 1,3,4. With an older implementation, the
         * verifier would swap the last element with the removed element, but to
         * maintain the stack property we need to use memmove.
         */
        bpf_obj_drop(p as *mut c_void);

        /* Save and restore to reset active_irq_id to 3, as the ordering is now
         * refs=1,4,3. When restoring the linear scan will find prev_id in order
         * as 3 instead of 4.
         */
        bpf_local_irq_save(f.add(3));
        bpf_local_irq_restore(f.add(3));

        /* With the incorrect implementation, we can release flags[1], flags[2],
         * and flags[0], i.e. in the wrong order.
         */
        bpf_local_irq_restore(f.add(1));
        bpf_local_irq_restore(f.add(2));
        bpf_local_irq_restore(f.add(0));
    }
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
            addr_of_mut!(i) as u64,
            0,
            0,
        );
    }
    i
}

// C: int __noinline global_sleepable_helper_subprog(int i)
#[no_mangle]
#[inline(never)]
pub extern "C" fn global_sleepable_helper_subprog(mut i: i32) -> i32 {
    if i != 0 {
        bpf_copy_from_user(addr_of_mut!(i) as *mut c_void, 4, core::ptr::null());
    }
    i
}

// C: int __noinline global_sleepable_kfunc_subprog(int i)
#[no_mangle]
#[inline(never)]
pub extern "C" fn global_sleepable_kfunc_subprog(mut i: i32) -> i32 {
    if i != 0 {
        unsafe {
            bpf_copy_from_user_str(addr_of_mut!(i) as *mut c_void, 4, core::ptr::null(), 0);
        }
    }
    global_subprog(i);
    i
}

// C: int __noinline global_subprog_calling_sleepable_global(int i)
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
extern "C" fn irq_non_sleepable_global_subprog(_ctx: *mut c_void) -> i32 {
    let mut flags = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags.as_mut_ptr());
        global_subprog(0);
        bpf_local_irq_restore(flags.as_mut_ptr());
    }
    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn irq_sleepable_helper_global_subprog(_ctx: *mut c_void) -> i32 {
    let mut flags = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags.as_mut_ptr());
        global_sleepable_helper_subprog(0);
        bpf_local_irq_restore(flags.as_mut_ptr());
    }
    0
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn irq_sleepable_global_subprog_indirect(_ctx: *mut c_void) -> i32 {
    let mut flags = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags.as_mut_ptr());
        global_subprog_calling_sleepable_global(0);
        bpf_local_irq_restore(flags.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_ooo_lock_cond_inv(_ctx: *mut __sk_buff) -> i32 {
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    unsafe {
        if bpf_res_spin_lock_irqsave(addr_of_mut!(lockA), flags1.as_mut_ptr()) != 0 {
            return 0;
        }
        if bpf_res_spin_lock_irqsave(addr_of_mut!(lockB), flags2.as_mut_ptr()) != 0 {
            bpf_res_spin_unlock_irqrestore(addr_of_mut!(lockA), flags1.as_mut_ptr());
            return 0;
        }

        bpf_res_spin_unlock_irqrestore(addr_of_mut!(lockB), flags1.as_mut_ptr());
        bpf_res_spin_unlock_irqrestore(addr_of_mut!(lockA), flags2.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_wrong_kfunc_class_1(_ctx: *mut __sk_buff) -> i32 {
    let mut flags1 = MaybeUninit::<u64>::uninit();

    unsafe {
        if bpf_res_spin_lock_irqsave(addr_of_mut!(lockA), flags1.as_mut_ptr()) != 0 {
            return 0;
        }
        /* For now, bpf_local_irq_restore is not allowed in critical section,
         * but this test ensures error will be caught with kfunc_class when it's
         * opened up. Tested by temporarily permitting this kfunc in critical
         * section.
         */
        bpf_local_irq_restore(flags1.as_mut_ptr());
        bpf_res_spin_unlock_irqrestore(addr_of_mut!(lockA), flags1.as_mut_ptr());
    }
    0
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn irq_wrong_kfunc_class_2(_ctx: *mut __sk_buff) -> i32 {
    let mut flags2 = MaybeUninit::<u64>::uninit();
    let mut flags1 = MaybeUninit::<u64>::uninit();

    unsafe {
        bpf_local_irq_save(flags1.as_mut_ptr());
        if bpf_res_spin_lock_irqsave(addr_of_mut!(lockA), flags2.as_mut_ptr()) != 0 {
            return 0;
        }
        bpf_local_irq_restore(flags2.as_mut_ptr());
        bpf_res_spin_unlock_irqrestore(addr_of_mut!(lockA), flags1.as_mut_ptr());
    }
    0
}

bpf_object!("GPL");
