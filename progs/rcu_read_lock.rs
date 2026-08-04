#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/rcu_read_lock.c,
// bpf-rs-core idiom.
//
// prog_tests/rcu_read_lock.c is NOT a test_loader/__failure decl-tag test --
// it hand-picks one program per subtest via bpf_object__find_program_by_name
// + bpf_program__set_autoload, then asserts bpf_object_load()'s return code
// directly (ASSERT_OK for "success"/"rcuptr_acquire", ASSERT_ERR for the
// "negative_tests_*" groups). Every SEC() below keeps the C original's
// leading '?' (libbpf disables autoload by default for '?'-prefixed
// sections; the test enables exactly the one program it wants per run), the
// same call graph (static vs __noinline-global subprog, matching
// bpf_rcu_read_lock/unlock kfunc placement), so the same real kernel
// verifier checks (rcu lock balance, global-subprog independent
// verification, sleepable-call-inside-rcu-region) accept/reject each
// program exactly as they do for the clang-built object -- none of this
// depends on BTF decl tags rustc can't emit.

use core::ffi::c_void;

use bpf_rs_core::helpers::{
    bpf_copy_from_user, bpf_copy_from_user_task, bpf_get_current_task_btf, bpf_get_prandom_u32,
    bpf_task_pt_regs, bpf_task_storage_get, sink_val,
};
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;

const BPF_MAP_TYPE_TASK_STORAGE: i32 = 29;
const BPF_F_NO_PREALLOC: i32 = 1;
const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;

#[btf]
struct task_struct {
    pid: i32,
    real_parent: *mut task_struct,
    cgroups: *mut css_set,
    group_leader: *mut task_struct,
}

#[btf]
struct css_set {
    dfl_cgrp: *mut cgroup,
}

#[btf]
struct cgroup {
    kn: *mut kernfs_node,
}

#[btf]
struct kernfs_node {
    id: u64,
}

// Opaque marker type: only ever passed through as a pointer between the
// kfuncs below, no field of it is ever read.
struct bpf_key;

extern "C" {
    fn bpf_lookup_user_key(serial: i32, flags: u64) -> *mut bpf_key;
    fn bpf_key_put(key: *mut bpf_key);
    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();
    fn bpf_task_acquire(p: *mut task_struct) -> *mut task_struct;
    fn bpf_task_release(p: *mut task_struct);
    fn bpf_copy_from_user_str(
        dst: *mut c_void,
        dst_sz: u32,
        unsafe_ptr: *const c_void,
        flags: u64,
    ) -> i32;
}

bpf_map! {
    map_a {
        r#type: *const [i32; BPF_MAP_TYPE_TASK_STORAGE as usize],
        map_flags: *const [i32; BPF_F_NO_PREALLOC as usize],
        key: *const i32,
        value: *const isize,
    }
}

#[no_mangle]
static mut user_data: u32 = 0;
#[no_mangle]
static mut target_pid: u32 = 0;
#[no_mangle]
static mut key_serial: i32 = 0;
#[no_mangle]
static mut flags: u64 = 0;
#[no_mangle]
static mut task_storage_val: u64 = 0;
#[no_mangle]
static mut cgroup_id: u64 = 0;

// One field access per root, per function -- see project memory
// btf-second-field-access-same-root-crashes-opt.
#[inline(never)]
fn task_pid(task: *mut task_struct) -> i32 {
    *unsafe { &*task }.pid().get().unwrap()
}

#[inline(never)]
fn task_real_parent(task: *mut task_struct) -> *mut task_struct {
    *unsafe { &*task }.real_parent().get().unwrap()
}

#[inline(never)]
fn task_cgroups(task: *mut task_struct) -> *mut css_set {
    *unsafe { &*task }.cgroups().get().unwrap()
}

#[inline(never)]
fn task_group_leader(task: *mut task_struct) -> *mut task_struct {
    *unsafe { &*task }.group_leader().get().unwrap()
}

#[inline(never)]
fn cgroups_dfl_cgrp(cgroups: *mut css_set) -> *mut cgroup {
    *unsafe { &*cgroups }.dfl_cgrp().get().unwrap()
}

#[inline(never)]
fn cgroup_kn(cgrp: *mut cgroup) -> *mut kernfs_node {
    *unsafe { &*cgrp }.kn().get().unwrap()
}

#[inline(never)]
fn kn_id(kn: *mut kernfs_node) -> u64 {
    *unsafe { &*kn }.id().get().unwrap()
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn get_cgroup_id(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    if task_pid(task) as u32 != unsafe { target_pid } {
        return 0;
    }

    // simulate bpf_get_current_cgroup_id() helper
    unsafe { bpf_rcu_read_lock() };
    let cgroups = task_cgroups(task);
    if !cgroups.is_null() {
        let dfl_cgrp = cgroups_dfl_cgrp(cgroups);
        let kn = cgroup_kn(dfl_cgrp);
        unsafe { cgroup_id = kn_id(kn) };
    }
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_succ(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    if task_pid(task) as u32 != unsafe { target_pid } {
        return 0;
    }

    let mut init_val: isize = 2;
    unsafe { bpf_rcu_read_lock() };
    // region including helper using rcu ptr real_parent
    let real_parent = task_real_parent(task);
    if real_parent.is_null() {
        unsafe { bpf_rcu_read_unlock() };
        return 0;
    }
    let ptr = bpf_task_storage_get(
        &map_a,
        real_parent,
        &mut init_val as *mut isize as *mut c_void,
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut isize;
    if ptr.is_null() {
        unsafe { bpf_rcu_read_unlock() };
        return 0;
    }
    let ptr = bpf_task_storage_get(&map_a, real_parent, core::ptr::null_mut(), 0) as *mut isize;
    if ptr.is_null() {
        unsafe { bpf_rcu_read_unlock() };
        return 0;
    }
    unsafe { task_storage_val = *ptr as u64 };
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?fentry.s/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn no_lock(_ctx: *const u64) -> i32 {
    // old style ptr_to_btf_id is not allowed in sleepable
    let task: *mut task_struct = bpf_get_current_task_btf();
    let real_parent = task_real_parent(task);
    let _ = bpf_task_storage_get(&map_a, real_parent, core::ptr::null_mut(), 0);
    0
}

#[link_section = "?fentry.s/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn two_regions(_ctx: *const u64) -> i32 {
    // two regions
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_rcu_read_lock() };
    unsafe { bpf_rcu_read_unlock() };
    unsafe { bpf_rcu_read_lock() };
    let real_parent = task_real_parent(task);
    if !real_parent.is_null() {
        let _ = bpf_task_storage_get(&map_a, real_parent, core::ptr::null_mut(), 0);
    }
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn non_sleepable_1(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_rcu_read_lock() };
    let real_parent = task_real_parent(task);
    if !real_parent.is_null() {
        let _ = bpf_task_storage_get(&map_a, real_parent, core::ptr::null_mut(), 0);
    }
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn non_sleepable_2(_ctx: *const u64) -> i32 {
    unsafe { bpf_rcu_read_lock() };
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_rcu_read_unlock() };

    unsafe { bpf_rcu_read_lock() };
    let real_parent = task_real_parent(task);
    if !real_parent.is_null() {
        let _ = bpf_task_storage_get(&map_a, real_parent, core::ptr::null_mut(), 0);
    }
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?fentry.s/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn task_acquire(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_rcu_read_lock() };
    let real_parent = task_real_parent(task);
    if real_parent.is_null() {
        unsafe { bpf_rcu_read_unlock() };
        return 0;
    }

    // rcu_ptr->rcu_field
    let gparent = task_real_parent(real_parent);
    if gparent.is_null() {
        unsafe { bpf_rcu_read_unlock() };
        return 0;
    }

    // acquire a reference which can be used outside rcu read lock region
    let gparent = unsafe { bpf_task_acquire(gparent) };
    if gparent.is_null() {
        unsafe { bpf_rcu_read_unlock() };
        return 0;
    }

    let _ = bpf_task_storage_get(&map_a, gparent, core::ptr::null_mut(), 0);
    unsafe { bpf_task_release(gparent) };
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn miss_lock(_ctx: *const u64) -> i32 {
    // missing bpf_rcu_read_lock()
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_rcu_read_lock() };
    let _ = bpf_task_storage_get(&map_a, task, core::ptr::null_mut(), 0);
    unsafe { bpf_rcu_read_unlock() };
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn miss_unlock(_ctx: *const u64) -> i32 {
    // missing bpf_rcu_read_unlock()
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_rcu_read_lock() };
    let _ = bpf_task_storage_get(&map_a, task, core::ptr::null_mut(), 0);
    0
}

#[link_section = "?fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn non_sleepable_rcu_mismatch(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    // non-sleepable: missing bpf_rcu_read_unlock() in one path
    unsafe { bpf_rcu_read_lock() };
    let real_parent = task_real_parent(task);
    if real_parent.is_null() {
        return 0;
    }
    let _ = bpf_task_storage_get(&map_a, real_parent, core::ptr::null_mut(), 0);
    if !real_parent.is_null() {
        unsafe { bpf_rcu_read_unlock() };
    }
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn inproper_sleepable_helper(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    // sleepable helper in rcu read lock region
    unsafe { bpf_rcu_read_lock() };
    let real_parent = task_real_parent(task);
    if real_parent.is_null() {
        unsafe { bpf_rcu_read_unlock() };
        return 0;
    }
    let regs = bpf_task_pt_regs(real_parent);
    if regs.is_null() {
        unsafe { bpf_rcu_read_unlock() };
        return 0;
    }

    // Stand-in for PT_REGS_IP(regs): this whole path is verifier-rejected at
    // load time (sleepable helper call inside an rcu_read_lock region)
    // before it can ever execute, so the exact address read back doesn't
    // affect prog_tests/rcu_read_lock.c's inproper_region_tests outcome.
    let mut value: u32 = 0;
    let _ = bpf_copy_from_user_task(
        &mut value as *mut u32 as *mut c_void,
        4,
        regs as *const c_void,
        task,
        0,
    );
    unsafe { user_data = value };
    let _ = bpf_task_storage_get(&map_a, real_parent, core::ptr::null_mut(), 0);
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?lsm.s/bpf"]
#[no_mangle]
extern "C" fn inproper_sleepable_kfunc(_ctx: *const u64) -> i32 {
    // sleepable kfunc in rcu read lock region
    unsafe { bpf_rcu_read_lock() };
    let bkey = unsafe { bpf_lookup_user_key(key_serial, flags) };
    unsafe { bpf_rcu_read_unlock() };
    if bkey.is_null() {
        return -1;
    }
    unsafe { bpf_key_put(bkey) };
    0
}

#[link_section = "?fentry.s/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn nested_rcu_region(_ctx: *const u64) -> i32 {
    // nested rcu read lock regions
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_rcu_read_lock() };
    unsafe { bpf_rcu_read_lock() };
    let real_parent = task_real_parent(task);
    if !real_parent.is_null() {
        let _ = bpf_task_storage_get(&map_a, real_parent, core::ptr::null_mut(), 0);
    }
    unsafe { bpf_rcu_read_unlock() };
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?fentry.s/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn nested_rcu_region_unbalanced_1(_ctx: *const u64) -> i32 {
    // nested rcu read lock regions
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_rcu_read_lock() };
    unsafe { bpf_rcu_read_lock() };
    let real_parent = task_real_parent(task);
    if !real_parent.is_null() {
        let _ = bpf_task_storage_get(&map_a, real_parent, core::ptr::null_mut(), 0);
    }
    unsafe { bpf_rcu_read_unlock() };
    unsafe { bpf_rcu_read_unlock() };
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?fentry.s/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn nested_rcu_region_unbalanced_2(_ctx: *const u64) -> i32 {
    // nested rcu read lock regions
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_rcu_read_lock() };
    unsafe { bpf_rcu_read_lock() };
    unsafe { bpf_rcu_read_lock() };
    let real_parent = task_real_parent(task);
    if !real_parent.is_null() {
        let _ = bpf_task_storage_get(&map_a, real_parent, core::ptr::null_mut(), 0);
    }
    unsafe { bpf_rcu_read_unlock() };
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_trusted_non_rcuptr(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_rcu_read_lock() };
    // the pointer group_leader is explicitly marked as trusted
    let real_parent = task_real_parent(task);
    let group_leader = task_group_leader(real_parent);
    let _ = bpf_task_storage_get(&map_a, group_leader, core::ptr::null_mut(), 0);
    unsafe { bpf_rcu_read_unlock() };
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn task_untrusted_rcuptr(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_rcu_read_lock() };
    let real_parent = task_real_parent(task);
    unsafe { bpf_rcu_read_unlock() };
    // helper use of rcu ptr outside the rcu read lock region
    let _ = bpf_task_storage_get(&map_a, real_parent, core::ptr::null_mut(), 0);
    0
}

#[link_section = "?fentry.s/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn cross_rcu_region(_ctx: *const u64) -> i32 {
    // rcu ptr define/use in different regions
    let task: *mut task_struct = bpf_get_current_task_btf();
    unsafe { bpf_rcu_read_lock() };
    let real_parent = task_real_parent(task);
    unsafe { bpf_rcu_read_unlock() };
    unsafe { bpf_rcu_read_lock() };
    let _ = bpf_task_storage_get(&map_a, real_parent, core::ptr::null_mut(), 0);
    unsafe { bpf_rcu_read_unlock() };
    0
}

// static in C: __noinline keeps clang from inlining it away; #[no_mangle]
// + #[inline(never)] is the Rust equivalent (confirmed by test_global_func1.rs
// to survive the internalize+O2 pipeline as a genuinely separate BPF
// subprogram) -- these calls exist specifically to exercise the verifier's
// static-vs-global subprog call-boundary handling of rcu lock state.
#[no_mangle]
#[inline(never)]
extern "C" fn static_subprog(_ctx: *const c_void) -> i32 {
    let ret: i32 = 0;
    if bpf_get_prandom_u32() != 0 {
        return ret + 42;
    }
    ret + bpf_get_prandom_u32() as i32
}

// non-static (__noinline only) in C: a genuine BPF global function.
#[no_mangle]
#[inline(never)]
pub extern "C" fn global_subprog(a: u64) -> i32 {
    let ret: i32 = a as i32;
    ret.wrapping_add(static_subprog(core::ptr::null()))
}

#[no_mangle]
#[inline(never)]
extern "C" fn static_subprog_lock(_ctx: *const c_void) -> i32 {
    let ret: i32 = 0;
    unsafe { bpf_rcu_read_lock() };
    if bpf_get_prandom_u32() != 0 {
        return ret + 42;
    }
    ret + bpf_get_prandom_u32() as i32
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn global_subprog_lock(a: u64) -> i32 {
    let ret: i32 = a as i32;
    ret.wrapping_add(static_subprog_lock(core::ptr::null()))
}

#[no_mangle]
#[inline(never)]
extern "C" fn static_subprog_unlock(_ctx: *const c_void) -> i32 {
    let ret: i32 = 0;
    unsafe { bpf_rcu_read_unlock() };
    if bpf_get_prandom_u32() != 0 {
        return ret + 42;
    }
    ret + bpf_get_prandom_u32() as i32
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn global_subprog_unlock(a: u64) -> i32 {
    let ret: i32 = a as i32;
    ret.wrapping_add(static_subprog_unlock(core::ptr::null()))
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn rcu_read_lock_subprog(ctx: *const u64) -> i32 {
    let mut ret: i32 = 0;
    unsafe { bpf_rcu_read_lock() };
    if bpf_get_prandom_u32() != 0 {
        ret = ret.wrapping_add(static_subprog(ctx as *const c_void));
    }
    unsafe { bpf_rcu_read_unlock() };
    sink_val(ret);
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn rcu_read_lock_global_subprog(_ctx: *const u64) -> i32 {
    let mut ret: i32 = 0;
    unsafe { bpf_rcu_read_lock() };
    if bpf_get_prandom_u32() != 0 {
        ret = ret.wrapping_add(global_subprog(ret as u64));
    }
    unsafe { bpf_rcu_read_unlock() };
    sink_val(ret);
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn rcu_read_lock_subprog_lock(ctx: *const u64) -> i32 {
    let mut ret: i32 = 0;
    ret = ret.wrapping_add(static_subprog_lock(ctx as *const c_void));
    unsafe { bpf_rcu_read_unlock() };
    sink_val(ret);
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn rcu_read_lock_global_subprog_lock(_ctx: *const u64) -> i32 {
    let mut ret: i32 = 0;
    ret = ret.wrapping_add(global_subprog_lock(ret as u64));
    unsafe { bpf_rcu_read_unlock() };
    sink_val(ret);
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn rcu_read_lock_subprog_unlock(ctx: *const u64) -> i32 {
    let mut ret: i32 = 0;
    unsafe { bpf_rcu_read_lock() };
    ret = ret.wrapping_add(static_subprog_unlock(ctx as *const c_void));
    sink_val(ret);
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn rcu_read_lock_global_subprog_unlock(_ctx: *const u64) -> i32 {
    let mut ret: i32 = 0;
    unsafe { bpf_rcu_read_lock() };
    ret = ret.wrapping_add(global_subprog_unlock(ret as u64));
    sink_val(ret);
    0
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn global_sleepable_helper_subprog(i: i32) -> i32 {
    let mut i = i;
    if i != 0 {
        let _ = bpf_copy_from_user(&mut i as *mut i32 as *mut c_void, 4, core::ptr::null());
    }
    i
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn global_sleepable_kfunc_subprog(i: i32) -> i32 {
    let mut i = i;
    if i != 0 {
        let _ = unsafe {
            bpf_copy_from_user_str(&mut i as *mut i32 as *mut c_void, 4, core::ptr::null(), 0)
        };
    }
    global_subprog(i as u64);
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

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn rcu_read_lock_sleepable_helper_global_subprog(_ctx: *const u64) -> i32 {
    let mut ret: i32 = 0;
    unsafe { bpf_rcu_read_lock() };
    ret = ret.wrapping_add(global_sleepable_helper_subprog(ret));
    unsafe { bpf_rcu_read_unlock() };
    sink_val(ret);
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn rcu_read_lock_sleepable_kfunc_global_subprog(_ctx: *const u64) -> i32 {
    let mut ret: i32 = 0;
    unsafe { bpf_rcu_read_lock() };
    ret = ret.wrapping_add(global_sleepable_kfunc_subprog(ret));
    unsafe { bpf_rcu_read_unlock() };
    sink_val(ret);
    0
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn rcu_read_lock_sleepable_global_subprog_indirect(_ctx: *const u64) -> i32 {
    let mut ret: i32 = 0;
    unsafe { bpf_rcu_read_lock() };
    ret = ret.wrapping_add(global_subprog_calling_sleepable_global(ret));
    unsafe { bpf_rcu_read_unlock() };
    sink_val(ret);
    0
}

bpf_object!("GPL");
