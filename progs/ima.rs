#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/ima.c,
// bpf-rs-core idiom.
//
// Three lsm.s hooks share the C original's ima_test_common/ima_test_deny
// logic. Per [[rel-btf-shinfo-corruption-workaround-shared-fn]] and
// [[btf-chain-merge-across-branches-corrupts-debuginfo]], every extern "C"
// program with real branching logic (not just `ima_test_common` itself)
// routes through its own #[inline(never)] helper, keeping the SEC()
// wrappers to a single call.

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_ima_file_hash, bpf_ima_inode_hash, bpf_ringbuf_reserve,
    bpf_ringbuf_submit,
};
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;
use core::ffi::c_void;

const EPERM: i32 = 1;
const READING_POLICY: i32 = 5;

bpf_map! {
    ringbuf {
        r#type: *const [i32; 27], // BPF_MAP_TYPE_RINGBUF
        max_entries: *const [i32; 4096], // 1 << 12
    }
}

#[no_mangle]
static mut monitored_pid: u32 = 0;

#[no_mangle]
static mut use_ima_file_hash: bool = false;
#[no_mangle]
static mut enable_bprm_creds_for_exec: bool = false;
#[no_mangle]
static mut enable_kernel_read_file: bool = false;
#[no_mangle]
static mut test_deny: bool = false;

#[btf]
struct inode {}

#[btf]
struct file {
    f_inode: *mut inode,
}

#[btf]
struct linux_binprm {
    file: *mut file,
}

#[inline(never)]
fn ima_test_common(file_ptr: *mut file) {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { monitored_pid } {
        return;
    }

    let mut ima_hash: u64 = 0;
    let ret = if !unsafe { use_ima_file_hash } {
        let inode_ptr = *unsafe { &*file_ptr }.f_inode().get().unwrap();
        bpf_ima_inode_hash(inode_ptr, &mut ima_hash as *mut u64 as *mut c_void, 8)
    } else {
        bpf_ima_file_hash(file_ptr, &mut ima_hash as *mut u64 as *mut c_void, 8)
    };

    if ret < 0 || ima_hash == 0 {
        return;
    }

    let sample = bpf_ringbuf_reserve(&ringbuf, 8, 0);
    if sample.is_null() {
        return;
    }

    unsafe { *(sample as *mut u64) = ima_hash };
    bpf_ringbuf_submit(sample, 0);
}

#[inline(never)]
fn ima_test_deny() -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid == unsafe { monitored_pid } && unsafe { test_deny } {
        return -EPERM;
    }
    0
}

#[link_section = "lsm.s/bprm_committed_creds"]
#[no_mangle]
extern "C" fn bprm_committed_creds(ctx: *const u64) -> i32 {
    let bprm = fentry_arg(ctx, 0) as *mut linux_binprm;
    let file_ptr = *unsafe { &*bprm }.file().get().unwrap();
    ima_test_common(file_ptr);
    0
}

#[inline(never)]
fn do_bprm_creds_for_exec(ctx: *const u64) -> i32 {
    if !unsafe { enable_bprm_creds_for_exec } {
        return 0;
    }

    let bprm = fentry_arg(ctx, 0) as *mut linux_binprm;
    let file_ptr = *unsafe { &*bprm }.file().get().unwrap();
    ima_test_common(file_ptr);
    0
}

#[link_section = "lsm.s/bprm_creds_for_exec"]
#[no_mangle]
extern "C" fn bprm_creds_for_exec(ctx: *const u64) -> i32 {
    do_bprm_creds_for_exec(ctx)
}

#[inline(never)]
fn do_kernel_read_file(ctx: *const u64) -> i32 {
    if !unsafe { enable_kernel_read_file } {
        return 0;
    }

    let contents = fentry_arg(ctx, 2) as u8;
    if contents == 0 {
        return 0;
    }

    let id = fentry_arg(ctx, 1) as i32;
    if id != READING_POLICY {
        return 0;
    }

    let ret = ima_test_deny();
    if ret < 0 {
        return ret;
    }

    let file_ptr = fentry_arg(ctx, 0) as *mut file;
    ima_test_common(file_ptr);
    0
}

#[link_section = "lsm.s/kernel_read_file"]
#[no_mangle]
extern "C" fn kernel_read_file(ctx: *const u64) -> i32 {
    do_kernel_read_file(ctx)
}

bpf_object!("GPL");
