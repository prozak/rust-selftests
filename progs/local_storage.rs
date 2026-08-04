#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/local_storage.c,
// bpf-rs-core idiom.
//
// Five lsm(.s) hooks share one `struct local_storage { void *exec_inode;
// u32 value; }` map-value layout across inode/sk/task local-storage maps.
// Each SEC() wrapper routes through its own #[inline(never)] fn (per
// [[btf-chain-merge-across-branches-corrupts-debuginfo]]); every #[btf]
// field is `.get()`-ed at most once per root pointer so
// [[btf-second-field-access-same-root-crashes-opt]] never triggers.

use core::ffi::c_void;

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_task_btf, bpf_inode_storage_delete,
    bpf_inode_storage_get, bpf_sk_storage_delete, bpf_sk_storage_get, bpf_task_storage_delete,
    bpf_task_storage_get,
};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;

const DUMMY_STORAGE_VALUE: u32 = 0xdeadbeef;
const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;
const EPERM: i32 = 1;

const BPF_MAP_TYPE_SK_STORAGE: i32 = 24;
const BPF_MAP_TYPE_INODE_STORAGE: i32 = 28;
const BPF_MAP_TYPE_TASK_STORAGE: i32 = 29;

#[no_mangle]
static mut monitored_pid: u32 = 0;
#[no_mangle]
static mut inode_storage_result: i32 = -1;
#[no_mangle]
static mut sk_storage_result: i32 = -1;
#[no_mangle]
static mut task_storage_result: i32 = -1;

#[repr(C)]
struct local_storage {
    exec_inode: *mut c_void,
    value: u32,
}

struct task_struct;

#[btf]
struct inode {}

#[btf]
struct dentry {
    d_inode: *mut inode,
}

#[btf]
struct sock {}

#[btf]
struct socket {
    sk: *mut sock,
}

#[btf]
struct file {
    f_inode: *mut inode,
}

#[btf]
struct linux_binprm {
    file: *mut file,
}

bpf_map! {
    inode_storage_map {
        r#type: *const [i32; BPF_MAP_TYPE_INODE_STORAGE as usize],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const local_storage,
    }
}

bpf_map! {
    sk_storage_map {
        r#type: *const [i32; BPF_MAP_TYPE_SK_STORAGE as usize],
        map_flags: *const [i32; 513], // BPF_F_NO_PREALLOC | BPF_F_CLONE
        key: *const i32,
        value: *const local_storage,
    }
}

bpf_map! {
    sk_storage_map2 {
        r#type: *const [i32; BPF_MAP_TYPE_SK_STORAGE as usize],
        map_flags: *const [i32; 513], // BPF_F_NO_PREALLOC | BPF_F_CLONE
        key: *const i32,
        value: *const local_storage,
    }
}

bpf_map! {
    task_storage_map {
        r#type: *const [i32; BPF_MAP_TYPE_TASK_STORAGE as usize],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const local_storage,
    }
}

bpf_map! {
    task_storage_map2 {
        r#type: *const [i32; BPF_MAP_TYPE_TASK_STORAGE as usize],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const local_storage,
    }
}

#[inline(never)]
fn do_unlink_hook(ctx: *const u64) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { monitored_pid } {
        return 0;
    }

    let task: *mut task_struct = bpf_get_current_task_btf();
    if task.is_null() {
        return 0;
    }

    unsafe { task_storage_result = -1 };

    let storage =
        bpf_task_storage_get(&task_storage_map, task, core::ptr::null_mut(), 0) as *mut local_storage;
    if storage.is_null() {
        return 0;
    }

    let victim = arg(ctx, 1) as *mut dentry;
    let d_inode = *unsafe { &*victim }.d_inode().get().unwrap();
    let is_self_unlink = unsafe { (*storage).exec_inode } == d_inode as *mut c_void;

    let storage2 = bpf_task_storage_get(
        &task_storage_map2,
        task,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut local_storage;
    if storage2.is_null() || unsafe { (*storage2).value } != 0 {
        return 0;
    }

    if bpf_task_storage_delete(&task_storage_map2, task) != 0 {
        return 0;
    }
    if bpf_task_storage_delete(&task_storage_map, task) != 0 {
        return 0;
    }

    unsafe { task_storage_result = 0 };

    if is_self_unlink {
        -EPERM
    } else {
        0
    }
}

#[link_section = "lsm/inode_unlink"]
#[no_mangle]
extern "C" fn unlink_hook(ctx: *const u64) -> i32 {
    do_unlink_hook(ctx)
}

#[inline(never)]
fn do_inode_rename(ctx: *const u64) -> i32 {
    let new_dentry = arg(ctx, 3) as *mut dentry;
    let new_d_inode = *unsafe { &*new_dentry }.d_inode().get().unwrap();
    bpf_inode_storage_get(
        &inode_storage_map,
        new_d_inode,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    );

    let old_dentry = arg(ctx, 1) as *mut dentry;
    let old_d_inode = *unsafe { &*old_dentry }.d_inode().get().unwrap();
    let storage =
        bpf_inode_storage_get(&inode_storage_map, old_d_inode, core::ptr::null_mut(), 0) as *mut local_storage;
    if storage.is_null() {
        return 0;
    }

    if unsafe { (*storage).value } != DUMMY_STORAGE_VALUE {
        unsafe { inode_storage_result = -1 };
    }

    let err = bpf_inode_storage_delete(&inode_storage_map, old_d_inode) as i32;
    if err == 0 {
        unsafe { inode_storage_result = err };
    }

    0
}

#[link_section = "lsm.s/inode_rename"]
#[no_mangle]
extern "C" fn inode_rename(ctx: *const u64) -> i32 {
    do_inode_rename(ctx)
}

#[inline(never)]
fn do_socket_bind(ctx: *const u64) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let sockp = arg(ctx, 0) as *mut socket;
    let sk = *unsafe { &*sockp }.sk().get().unwrap();

    if pid != unsafe { monitored_pid } || sk.is_null() {
        return 0;
    }

    let storage = bpf_sk_storage_get(&sk_storage_map, sk, core::ptr::null_mut(), 0) as *mut local_storage;
    if storage.is_null() {
        return 0;
    }

    unsafe { sk_storage_result = -1 };
    if unsafe { (*storage).value } != DUMMY_STORAGE_VALUE {
        return 0;
    }

    let storage2 = bpf_sk_storage_get(
        &sk_storage_map2,
        sk,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut local_storage;
    if storage2.is_null() {
        return 0;
    }

    if bpf_sk_storage_delete(&sk_storage_map2, sk) != 0 {
        return 0;
    }
    if bpf_sk_storage_delete(&sk_storage_map, sk) != 0 {
        return 0;
    }

    unsafe { sk_storage_result = 0 };
    0
}

#[link_section = "lsm.s/socket_bind"]
#[no_mangle]
extern "C" fn socket_bind(ctx: *const u64) -> i32 {
    do_socket_bind(ctx)
}

#[inline(never)]
fn do_socket_post_create(ctx: *const u64) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let sockp = arg(ctx, 0) as *mut socket;
    let sk = *unsafe { &*sockp }.sk().get().unwrap();

    if pid != unsafe { monitored_pid } || sk.is_null() {
        return 0;
    }

    let storage = bpf_sk_storage_get(
        &sk_storage_map,
        sk,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut local_storage;
    if storage.is_null() {
        return 0;
    }

    unsafe { (*storage).value = DUMMY_STORAGE_VALUE };
    0
}

#[link_section = "lsm.s/socket_post_create"]
#[no_mangle]
extern "C" fn socket_post_create(ctx: *const u64) -> i32 {
    do_socket_post_create(ctx)
}

#[inline(never)]
fn do_exec(ctx: *const u64) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { monitored_pid } {
        return 0;
    }

    let task: *mut task_struct = bpf_get_current_task_btf();

    let bprm = arg(ctx, 0) as *mut linux_binprm;
    let bprm_file = *unsafe { &*bprm }.file().get().unwrap();
    let f_inode = *unsafe { &*bprm_file }.f_inode().get().unwrap();

    let storage = bpf_task_storage_get(
        &task_storage_map,
        task,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut local_storage;
    if !storage.is_null() {
        unsafe { (*storage).exec_inode = f_inode as *mut c_void };
    }

    let storage2 = bpf_inode_storage_get(
        &inode_storage_map,
        f_inode,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut local_storage;
    if storage2.is_null() {
        return 0;
    }

    unsafe { (*storage2).value = DUMMY_STORAGE_VALUE };
    0
}

#[link_section = "lsm.s/bprm_committed_creds"]
#[no_mangle]
extern "C" fn exec(ctx: *const u64) -> i32 {
    do_exec(ctx)
}

bpf_object!("GPL");
