// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_async_cb_context.c, translated
// by hand; include!d by the generated progs/verifier_async_cb_context.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_copy_from_user, bpf_get_current_task_btf, bpf_map_lookup_elem, bpf_sys_bpf, bpf_sys_close, bpf_timer_init};

const BPF_MAP_FREEZE: u32 = 22;
const BTF_KIND_STRUCT: u32 = 4;

/// bpf_timer_set_callback (helper 170) with the C's `int (*)(void *, int *, struct bpf_timer *)`
/// callback type (bpf-rs-core's wants an i64-returning one).
#[inline(always)]
fn timer_set_callback(timer: *mut bpf_timer, cb: extern "C" fn(*mut c_void, *mut i32, *mut bpf_timer) -> i32) -> i64 {
    let f: extern "C" fn(*mut bpf_timer, extern "C" fn(*mut c_void, *mut i32, *mut bpf_timer) -> i32) -> i64 = unsafe { core::mem::transmute(170usize) };
    f(timer, cb)
}

/// bpf_btf_find_by_name_kind (helper 167): bpf-rs-core lacks it.
#[inline(always)]
fn bpf_btf_find_by_name_kind(name: *mut c_void, name_sz: i32, kind: u32, flags: i32) -> i64 {
    let f: extern "C" fn(*mut c_void, i32, u32, i32) -> i64 = unsafe { core::mem::transmute(167usize) };
    f(name, name_sz, kind, flags)
}

/// The C's `u32 data; bpf_copy_from_user(&data, sizeof(data), NULL)`.
#[inline(always)]
fn copy_from_user_null() {
    let mut data = core::mem::MaybeUninit::<u32>::uninit();
    bpf_copy_from_user(data.as_mut_ptr() as *mut c_void, 4, core::ptr::null());
}

/// The C's `char name[] = "task_struct"; bpf_btf_find_by_name_kind(name, sizeof(name), BTF_KIND_STRUCT, 0)`.
#[inline(always)]
fn btf_find_task_struct() {
    // clang stores the string as a u32 "uct\0" over a u64 "task_str" (an array
    // initializer in Rust would become a memcpy, i.e. a bpf_arena_memcpy kfunc)
    #[repr(C)]
    struct Name {
        lo: u64,
        hi: u32,
    }
    let mut name = core::mem::MaybeUninit::<Name>::uninit();
    unsafe {
        core::ptr::addr_of_mut!((*name.as_mut_ptr()).hi).write_volatile(u32::from_le_bytes(*b"uct\0"));
        core::ptr::addr_of_mut!((*name.as_mut_ptr()).lo).write_volatile(u64::from_le_bytes(*b"task_str"));
    }
    bpf_btf_find_by_name_kind(name.as_mut_ptr() as *mut c_void, 12, BTF_KIND_STRUCT, 0);
}

/// The C's `__u64 attr = 0; bpf_sys_bpf(BPF_MAP_FREEZE, &attr, sizeof(attr))`.
#[inline(always)]
fn sys_bpf_freeze() {
    let mut attr: u64 = 0;
    bpf_sys_bpf(BPF_MAP_FREEZE, &mut attr as *mut u64 as *mut c_void, 8);
}

// HAND: timer_cb -- translate the C below (see the file comment)
//   static int timer_cb(void *map, int *key, struct bpf_timer *timer)
//   {
//       u32 data;
//       /* Timer callbacks are never sleepable, even from non-sleepable programs */
//       bpf_copy_from_user(&data, sizeof(data), NULL);
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn timer_cb(_map: *mut c_void, _key: *mut i32, _timer: *mut bpf_timer) -> i32 {
    // Timer callbacks are never sleepable, even from non-sleepable programs
    copy_from_user_null();
    0
}

// HAND: timer_non_sleepable_prog -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test1")
//   __failure __msg("sleepable helper bpf_copy_from_user#{{[0-9]+}} in non-sleepable prog")
//   int timer_non_sleepable_prog(void *ctx)
//   {
//       struct timer_elem *val;
//       int key = 0;
//
//       val = bpf_map_lookup_elem(&timer_map, &key);
//       if (!val)
//           return 0;
//
//       bpf_timer_init(&val->t, &timer_map, 0);
//       bpf_timer_set_callback(&val->t, timer_cb);
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn timer_non_sleepable_prog(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let val = bpf_map_lookup_elem(&timer_map, &key) as *mut timer_elem;
    if val.is_null() {
        return 0;
    }
    unsafe {
        bpf_timer_init(core::ptr::addr_of_mut!((*val).t), &timer_map, 0);
    }
    timer_set_callback(unsafe { core::ptr::addr_of_mut!((*val).t) }, timer_cb);
    0
}

// HAND: timer_sleepable_prog -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __failure __msg("sleepable helper bpf_copy_from_user#{{[0-9]+}} in non-sleepable prog")
//   int timer_sleepable_prog(void *ctx)
//   {
//       struct timer_elem *val;
//       int key = 0;
//
//       val = bpf_map_lookup_elem(&timer_map, &key);
//       if (!val)
//           return 0;
//
//       bpf_timer_init(&val->t, &timer_map, 0);
//       bpf_timer_set_callback(&val->t, timer_cb);
//       return 0;
//   }
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn timer_sleepable_prog(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let val = bpf_map_lookup_elem(&timer_map, &key) as *mut timer_elem;
    if val.is_null() {
        return 0;
    }
    unsafe {
        bpf_timer_init(core::ptr::addr_of_mut!((*val).t), &timer_map, 0);
    }
    timer_set_callback(unsafe { core::ptr::addr_of_mut!((*val).t) }, timer_cb);
    0
}

// HAND: timer_sys_bpf_cb -- translate the C below (see the file comment)
//   static int timer_sys_bpf_cb(void *map, int *key, struct bpf_timer *timer)
//   {
//       __u64 attr = 0;
//
//       bpf_sys_bpf(BPF_MAP_FREEZE, &attr, sizeof(attr));
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn timer_sys_bpf_cb(_map: *mut c_void, _key: *mut i32, _timer: *mut bpf_timer) -> i32 {
    sys_bpf_freeze();
    0
}

// HAND: timer_sys_bpf_prog -- translate the C below (see the file comment)
//   SEC("syscall")
//   __failure __msg("sleepable helper bpf_sys_bpf#{{[0-9]+}} in non-sleepable prog")
//   int timer_sys_bpf_prog(void *ctx)
//   {
//       struct timer_elem *val;
//       int key = 0;
//
//       val = bpf_map_lookup_elem(&timer_map, &key);
//       if (!val)
//           return 0;
//
//       bpf_timer_init(&val->t, &timer_map, 0);
//       bpf_timer_set_callback(&val->t, timer_sys_bpf_cb);
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn timer_sys_bpf_prog(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let val = bpf_map_lookup_elem(&timer_map, &key) as *mut timer_elem;
    if val.is_null() {
        return 0;
    }
    unsafe {
        bpf_timer_init(core::ptr::addr_of_mut!((*val).t), &timer_map, 0);
    }
    timer_set_callback(unsafe { core::ptr::addr_of_mut!((*val).t) }, timer_sys_bpf_cb);
    0
}

// HAND: timer_sys_close_cb -- translate the C below (see the file comment)
//   static int timer_sys_close_cb(void *map, int *key, struct bpf_timer *timer)
//   {
//       bpf_sys_close(0);
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn timer_sys_close_cb(_map: *mut c_void, _key: *mut i32, _timer: *mut bpf_timer) -> i32 {
    bpf_sys_close(0);
    0
}

// HAND: timer_sys_close_prog -- translate the C below (see the file comment)
//   SEC("syscall")
//   __failure __msg("sleepable helper bpf_sys_close#{{[0-9]+}} in non-sleepable prog")
//   int timer_sys_close_prog(void *ctx)
//   {
//       struct timer_elem *val;
//       int key = 0;
//
//       val = bpf_map_lookup_elem(&timer_map, &key);
//       if (!val)
//           return 0;
//
//       bpf_timer_init(&val->t, &timer_map, 0);
//       bpf_timer_set_callback(&val->t, timer_sys_close_cb);
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn timer_sys_close_prog(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let val = bpf_map_lookup_elem(&timer_map, &key) as *mut timer_elem;
    if val.is_null() {
        return 0;
    }
    unsafe {
        bpf_timer_init(core::ptr::addr_of_mut!((*val).t), &timer_map, 0);
    }
    timer_set_callback(unsafe { core::ptr::addr_of_mut!((*val).t) }, timer_sys_close_cb);
    0
}

// HAND: timer_btf_find_cb -- translate the C below (see the file comment)
//   static int timer_btf_find_cb(void *map, int *key, struct bpf_timer *timer)
//   {
//       char name[] = "task_struct";
//
//       bpf_btf_find_by_name_kind(name, sizeof(name), BTF_KIND_STRUCT, 0);
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn timer_btf_find_cb(_map: *mut c_void, _key: *mut i32, _timer: *mut bpf_timer) -> i32 {
    btf_find_task_struct();
    0
}

// HAND: timer_btf_find_prog -- translate the C below (see the file comment)
//   SEC("syscall")
//   __failure __msg("sleepable helper bpf_btf_find_by_name_kind#{{[0-9]+}} in non-sleepable prog")
//   int timer_btf_find_prog(void *ctx)
//   {
//       struct timer_elem *val;
//       int key = 0;
//
//       val = bpf_map_lookup_elem(&timer_map, &key);
//       if (!val)
//           return 0;
//
//       bpf_timer_init(&val->t, &timer_map, 0);
//       bpf_timer_set_callback(&val->t, timer_btf_find_cb);
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn timer_btf_find_prog(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let val = bpf_map_lookup_elem(&timer_map, &key) as *mut timer_elem;
    if val.is_null() {
        return 0;
    }
    unsafe {
        bpf_timer_init(core::ptr::addr_of_mut!((*val).t), &timer_map, 0);
    }
    timer_set_callback(unsafe { core::ptr::addr_of_mut!((*val).t) }, timer_btf_find_cb);
    0
}

// HAND: syscall_sys_bpf_prog -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success
//   int syscall_sys_bpf_prog(void *ctx)
//   {
//       __u64 attr = 0;
//
//       bpf_sys_bpf(BPF_MAP_FREEZE, &attr, sizeof(attr));
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_sys_bpf_prog(_ctx: *mut c_void) -> i32 {
    sys_bpf_freeze();
    0
}

// HAND: syscall_sys_close_prog -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success
//   int syscall_sys_close_prog(void *ctx)
//   {
//       bpf_sys_close(0);
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_sys_close_prog(_ctx: *mut c_void) -> i32 {
    bpf_sys_close(0);
    0
}

// HAND: syscall_btf_find_prog -- translate the C below (see the file comment)
//   SEC("syscall")
//   __success
//   int syscall_btf_find_prog(void *ctx)
//   {
//       char name[] = "task_struct";
//
//       bpf_btf_find_by_name_kind(name, sizeof(name), BTF_KIND_STRUCT, 0);
//       return 0;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_btf_find_prog(_ctx: *mut c_void) -> i32 {
    btf_find_task_struct();
    0
}

// HAND: wq_cb -- translate the C below (see the file comment)
//   static int wq_cb(void *map, int *key, void *value)
//   {
//       u32 data;
//       /* Workqueue callbacks are always sleepable, even from non-sleepable programs */
//       bpf_copy_from_user(&data, sizeof(data), NULL);
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn wq_cb(_map: *mut c_void, _key: *mut i32, _value: *mut c_void) -> i32 {
    // Workqueue callbacks are always sleepable, even from non-sleepable programs
    copy_from_user_null();
    0
}

// HAND: wq_non_sleepable_prog -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test1")
//   __success
//   int wq_non_sleepable_prog(void *ctx)
//   {
//       struct wq_elem *val;
//       int key = 0;
//
//       val = bpf_map_lookup_elem(&wq_map, &key);
//       if (!val)
//           return 0;
//
//       if (bpf_wq_init(&val->w, &wq_map, 0) != 0)
//           return 0;
//       if (bpf_wq_set_callback(&val->w, wq_cb, 0) != 0)
//           return 0;
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn wq_non_sleepable_prog(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let val = bpf_map_lookup_elem(&wq_map, &key) as *mut wq_elem;
    if val.is_null() {
        return 0;
    }
    unsafe {
        if bpf_wq_init(core::ptr::addr_of_mut!((*val).w) as *mut c_void, core::ptr::addr_of!(wq_map) as *mut c_void, 0) != 0 {
            return 0;
        }
        if bpf_wq_set_callback(core::ptr::addr_of_mut!((*val).w) as *mut c_void, wq_cb as *mut c_void, 0) != 0 {
            return 0;
        }
    }
    0
}

// HAND: wq_sleepable_prog -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __success
//   int wq_sleepable_prog(void *ctx)
//   {
//       struct wq_elem *val;
//       int key = 0;
//
//       val = bpf_map_lookup_elem(&wq_map, &key);
//       if (!val)
//           return 0;
//
//       if (bpf_wq_init(&val->w, &wq_map, 0) != 0)
//           return 0;
//       if (bpf_wq_set_callback(&val->w, wq_cb, 0) != 0)
//           return 0;
//       return 0;
//   }
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn wq_sleepable_prog(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let val = bpf_map_lookup_elem(&wq_map, &key) as *mut wq_elem;
    if val.is_null() {
        return 0;
    }
    unsafe {
        if bpf_wq_init(core::ptr::addr_of_mut!((*val).w) as *mut c_void, core::ptr::addr_of!(wq_map) as *mut c_void, 0) != 0 {
            return 0;
        }
        if bpf_wq_set_callback(core::ptr::addr_of_mut!((*val).w) as *mut c_void, wq_cb as *mut c_void, 0) != 0 {
            return 0;
        }
    }
    0
}

// HAND: wq_global_acquire -- translate the C below (see the file comment)
//   __noinline int wq_global_acquire(void)
//   {
//       struct task_struct *task, *acquired;
//       struct wq_elem *val;
//       int key = 0;
//
//       val = bpf_map_lookup_elem(&wq_map, &key);
//       if (!val)
//           return 0;
//
//       task = val->task;
//       if (!task)
//           return 0;
//
//       acquired = bpf_task_acquire(task);
//       if (acquired)
//           bpf_task_release(acquired);
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn wq_global_acquire() -> i32 {
    let key: i32 = 0;
    let val = bpf_map_lookup_elem(&wq_map, &key) as *mut wq_elem;
    if val.is_null() {
        return 0;
    }
    let task = unsafe { (*val).task };
    if task.is_null() {
        return 0;
    }
    unsafe {
        let acquired = bpf_task_acquire(task as *mut c_void);
        if !acquired.is_null() {
            bpf_task_release(acquired);
        }
    }
    0
}

// HAND: wq_global_rcu_cb -- translate the C below (see the file comment)
//   static int wq_global_rcu_cb(void *map, int *key, void *value)
//   {
//       wq_global_acquire();
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn wq_global_rcu_cb(_map: *mut c_void, _key: *mut i32, _value: *mut c_void) -> i32 {
    wq_global_acquire();
    0
}

// HAND: wq_global_rcu_prog -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test1")
//   __failure __msg("R1 must be a rcu pointer")
//   int wq_global_rcu_prog(void *ctx)
//   {
//       struct wq_elem *val;
//       int key = 0;
//
//       val = bpf_map_lookup_elem(&wq_map, &key);
//       if (!val)
//           return 0;
//
//       bpf_wq_init(&val->w, &wq_map, 0);
//       bpf_wq_set_callback(&val->w, wq_global_rcu_cb, 0);
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn wq_global_rcu_prog(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let val = bpf_map_lookup_elem(&wq_map, &key) as *mut wq_elem;
    if val.is_null() {
        return 0;
    }
    unsafe {
        bpf_wq_init(core::ptr::addr_of_mut!((*val).w) as *mut c_void, core::ptr::addr_of!(wq_map) as *mut c_void, 0);
        bpf_wq_set_callback(core::ptr::addr_of_mut!((*val).w) as *mut c_void, wq_global_rcu_cb as *mut c_void, 0);
    }
    0
}

// HAND: wq_global_rcu_lock_cb -- translate the C below (see the file comment)
//   static int wq_global_rcu_lock_cb(void *map, int *key, void *value)
//   {
//       bpf_rcu_read_lock();
//       wq_global_acquire();
//       bpf_rcu_read_unlock();
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn wq_global_rcu_lock_cb(_map: *mut c_void, _key: *mut i32, _value: *mut c_void) -> i32 {
    unsafe { bpf_rcu_read_lock() };
    wq_global_acquire();
    unsafe { bpf_rcu_read_unlock() };
    0
}

// HAND: wq_global_rcu_lock_prog -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test1")
//   __success
//   int wq_global_rcu_lock_prog(void *ctx)
//   {
//       struct wq_elem *val;
//       int key = 0;
//
//       /* Verify the same global subprog in non-sleepable and protected contexts. */
//       wq_global_acquire();
//
//       val = bpf_map_lookup_elem(&wq_map, &key);
//       if (!val)
//           return 0;
//
//       bpf_wq_init(&val->w, &wq_map, 0);
//       bpf_wq_set_callback(&val->w, wq_global_rcu_lock_cb, 0);
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn wq_global_rcu_lock_prog(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    // Verify the same global subprog in non-sleepable and protected contexts.
    wq_global_acquire();
    let val = bpf_map_lookup_elem(&wq_map, &key) as *mut wq_elem;
    if val.is_null() {
        return 0;
    }
    unsafe {
        bpf_wq_init(core::ptr::addr_of_mut!((*val).w) as *mut c_void, core::ptr::addr_of!(wq_map) as *mut c_void, 0);
        bpf_wq_set_callback(core::ptr::addr_of_mut!((*val).w) as *mut c_void, wq_global_rcu_lock_cb as *mut c_void, 0);
    }
    0
}

// HAND: wq_global_no_rcu -- translate the C below (see the file comment)
//   __weak __noinline int wq_global_no_rcu(void)
//   {
//       return 0;
//   }
#[linkage = "weak"]
#[no_mangle]
#[inline(never)]
extern "C" fn wq_global_no_rcu() -> i32 {
    0
}

// HAND: wq_global_no_rcu_cb -- translate the C below (see the file comment)
//   static int wq_global_no_rcu_cb(void *map, int *key, void *value)
//   {
//       wq_global_no_rcu();
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn wq_global_no_rcu_cb(_map: *mut c_void, _key: *mut i32, _value: *mut c_void) -> i32 {
    wq_global_no_rcu();
    0
}

// HAND: wq_global_no_rcu_prog -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test1")
//   __success __log_level(4)
//   __msg("subprog {{[0-9]+}} (wq_global_no_rcu) global insns_self 4 insns_total 4 stack 0")
//   int wq_global_no_rcu_prog(void *ctx)
//   {
//       struct wq_elem *val;
//       int key = 0;
//
//       /* Verify the same global in non-sleepable and unprotected contexts. */
//       wq_global_no_rcu();
//
//       val = bpf_map_lookup_elem(&wq_map, &key);
//       if (!val)
//           return 0;
//
//       bpf_wq_init(&val->w, &wq_map, 0);
//       bpf_wq_set_callback(&val->w, wq_global_no_rcu_cb, 0);
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn wq_global_no_rcu_prog(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    // Verify the same global in non-sleepable and unprotected contexts.
    wq_global_no_rcu();
    let val = bpf_map_lookup_elem(&wq_map, &key) as *mut wq_elem;
    if val.is_null() {
        return 0;
    }
    unsafe {
        bpf_wq_init(core::ptr::addr_of_mut!((*val).w) as *mut c_void, core::ptr::addr_of!(wq_map) as *mut c_void, 0);
        bpf_wq_set_callback(core::ptr::addr_of_mut!((*val).w) as *mut c_void, wq_global_no_rcu_cb as *mut c_void, 0);
    }
    0
}

// HAND: task_work_cb -- translate the C below (see the file comment)
//   static int task_work_cb(struct bpf_map *map, void *key, void *value)
//   {
//       u32 data;
//       /* Task work callbacks are always sleepable, even from non-sleepable programs */
//       bpf_copy_from_user(&data, sizeof(data), NULL);
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn task_work_cb(_map: *mut c_void, _key: *mut c_void, _value: *mut c_void) -> i32 {
    // Task work callbacks are always sleepable, even from non-sleepable programs
    copy_from_user_null();
    0
}

// HAND: task_work_non_sleepable_prog -- translate the C below (see the file comment)
//   SEC("fentry/bpf_fentry_test1")
//   __success
//   int task_work_non_sleepable_prog(void *ctx)
//   {
//       struct task_work_elem *val;
//       struct task_struct *task;
//       int key = 0;
//
//       val = bpf_map_lookup_elem(&task_work_map, &key);
//       if (!val)
//           return 0;
//
//       task = bpf_get_current_task_btf();
//       if (!task)
//           return 0;
//
//       bpf_task_work_schedule_resume(task, &val->tw, &task_work_map, task_work_cb);
//       return 0;
//   }
#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn task_work_non_sleepable_prog(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let val = bpf_map_lookup_elem(&task_work_map, &key) as *mut task_work_elem;
    if val.is_null() {
        return 0;
    }
    let task: *mut task_struct = bpf_get_current_task_btf();
    if task.is_null() {
        return 0;
    }
    unsafe {
        bpf_task_work_schedule_resume(
            task as *mut c_void,
            core::ptr::addr_of_mut!((*val).tw) as *mut c_void,
            core::ptr::addr_of!(task_work_map) as *mut c_void,
            task_work_cb as *mut c_void,
        );
    }
    0
}

// HAND: task_work_sleepable_prog -- translate the C below (see the file comment)
//   SEC("lsm.s/file_open")
//   __success
//   int task_work_sleepable_prog(void *ctx)
//   {
//       struct task_work_elem *val;
//       struct task_struct *task;
//       int key = 0;
//
//       val = bpf_map_lookup_elem(&task_work_map, &key);
//       if (!val)
//           return 0;
//
//       task = bpf_get_current_task_btf();
//       if (!task)
//           return 0;
//
//       bpf_task_work_schedule_resume(task, &val->tw, &task_work_map, task_work_cb);
//       return 0;
//   }
#[link_section = "lsm.s/file_open"]
#[no_mangle]
extern "C" fn task_work_sleepable_prog(_ctx: *mut c_void) -> i32 {
    let key: i32 = 0;
    let val = bpf_map_lookup_elem(&task_work_map, &key) as *mut task_work_elem;
    if val.is_null() {
        return 0;
    }
    let task: *mut task_struct = bpf_get_current_task_btf();
    if task.is_null() {
        return 0;
    }
    unsafe {
        bpf_task_work_schedule_resume(
            task as *mut c_void,
            core::ptr::addr_of_mut!((*val).tw) as *mut c_void,
            core::ptr::addr_of!(task_work_map) as *mut c_void,
            task_work_cb as *mut c_void,
        );
    }
    0
}
