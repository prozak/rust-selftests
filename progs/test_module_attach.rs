#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_module_attach.c,
// bpf-rs-core idiom. Every program is SEC("?...") (autoload disabled by
// default); prog_tests/module_attach.c enables exactly one at a time via
// bpf_program__set_autoload before load/attach, so cross-program state
// (ctx layout mismatches etc.) never interacts at runtime.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_probe_read_kernel;
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;
use core::ffi::c_void;

// bpf_testmod.h's bpf_testmod_test_read_ctx/write_ctx, read via CO-RE
// (BPF_CORE_READ in the raw_tp case, plain field access on a trusted BTF
// pointer in the tp_btf case) against bpf_testmod's split BTF.
#[btf]
struct bpf_testmod_test_read_ctx {
    len: u64,
}

#[btf]
struct bpf_testmod_test_write_ctx {
    len: u64,
}

// struct file's f_mode field (fmode_t == unsigned int), read via a trusted
// fexit return-value pointer.
#[btf]
struct file {
    f_mode: u32,
}

// bpf_testmod_test_writable_ctx is a writable raw-tracepoint buffer (not a
// CO-RE-matched kernel struct): plain repr(C) layout, direct field access.
#[repr(C)]
struct bpf_testmod_test_writable_ctx {
    early_ret: u8,
    val: i32,
}

#[no_mangle]
static mut sz: u32 = 0;

// raw_tp ctx pointer args are plain SCALAR_VALUEs (not trusted
// PTR_TO_BTF_ID), matching the C original's use of BPF_CORE_READ (which
// probe-reads through the CO-RE-relocated offset) rather than a direct
// `->field` dereference.

#[link_section = "?raw_tp/bpf_testmod_test_read"]
#[no_mangle]
extern "C" fn handle_raw_tp(ctx: *const u64) -> i32 {
    let read_ctx = arg(ctx, 1) as *const bpf_testmod_test_read_ctx;
    let len_ptr = unsafe { &*read_ctx }.len().as_ptr();
    let mut len: u64 = 0;
    bpf_probe_read_kernel(&mut len, 8, len_ptr as *const c_void);
    unsafe { sz = len as u32 };
    0
}

#[link_section = "?raw_tp/bpf_testmod_test_write_bare_tp"]
#[no_mangle]
extern "C" fn handle_raw_tp_bare(ctx: *const u64) -> i32 {
    let write_ctx = arg(ctx, 1) as *const bpf_testmod_test_write_ctx;
    let len_ptr = unsafe { &*write_ctx }.len().as_ptr();
    let mut len: u64 = 0;
    bpf_probe_read_kernel(&mut len, 8, len_ptr as *const c_void);
    unsafe { sz = len as u32 };
    0
}

#[no_mangle]
static mut raw_tp_writable_bare_in_val: i32 = 0;
#[no_mangle]
static mut raw_tp_writable_bare_early_ret: i32 = 0;
#[no_mangle]
static mut raw_tp_writable_bare_out_val: i32 = 0;

#[link_section = "?raw_tp.w/bpf_testmod_test_writable_bare_tp"]
#[no_mangle]
extern "C" fn handle_raw_tp_writable_bare(ctx: *const u64) -> i32 {
    let writable = arg(ctx, 0) as *mut bpf_testmod_test_writable_ctx;
    unsafe {
        raw_tp_writable_bare_in_val = (*writable).val;
        (*writable).early_ret = (raw_tp_writable_bare_early_ret != 0) as u8;
        (*writable).val = raw_tp_writable_bare_out_val;
    }
    0
}

#[link_section = "?tp_btf/bpf_testmod_test_read"]
#[no_mangle]
extern "C" fn handle_tp_btf(ctx: *const u64) -> i32 {
    let read_ctx = arg(ctx, 1) as *const bpf_testmod_test_read_ctx;
    let len = *unsafe { &*read_ctx }.len().get().unwrap();
    unsafe { sz = len as u32 };
    0
}

#[link_section = "?fentry/bpf_testmod_test_read"]
#[no_mangle]
extern "C" fn handle_fentry(ctx: *const u64) -> i32 {
    let len = arg(ctx, 5);
    unsafe { sz = len as u32 };
    0
}

#[link_section = "?fentry"]
#[no_mangle]
extern "C" fn handle_fentry_manual(ctx: *const u64) -> i32 {
    let len = arg(ctx, 5);
    unsafe { sz = len as u32 };
    0
}

#[link_section = "?fentry/bpf_testmod:bpf_testmod_test_read"]
#[no_mangle]
extern "C" fn handle_fentry_explicit(ctx: *const u64) -> i32 {
    let len = arg(ctx, 5);
    unsafe { sz = len as u32 };
    0
}

#[link_section = "?fentry"]
#[no_mangle]
extern "C" fn handle_fentry_explicit_manual(ctx: *const u64) -> i32 {
    let len = arg(ctx, 5);
    unsafe { sz = len as u32 };
    0
}

#[no_mangle]
static mut retval: i32 = 0;

#[link_section = "?fexit/bpf_testmod_test_read"]
#[no_mangle]
extern "C" fn handle_fexit(ctx: *const u64) -> i32 {
    let len = arg(ctx, 5);
    let ret = arg(ctx, 6);
    unsafe {
        sz = len as u32;
        retval = ret as i32;
    }
    0
}

#[link_section = "?fexit/bpf_testmod_return_ptr"]
#[no_mangle]
extern "C" fn handle_fexit_ret(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 1) as *const file;
    let mut buf: i64 = 0;
    unsafe {
        bpf_probe_read_kernel(&mut buf, 8, ret as *const c_void);
        bpf_probe_read_kernel(&mut buf, 8, (ret as *const u8).add(256) as *const c_void);
        core::ptr::read_volatile(ret as *const i32);
    }
    let f_mode_ptr = unsafe { &*ret }.f_mode().as_ptr();
    unsafe { core::ptr::read_volatile(f_mode_ptr) };
    0
}

#[link_section = "?fmod_ret/bpf_testmod_test_read"]
#[no_mangle]
extern "C" fn handle_fmod_ret(ctx: *const u64) -> i32 {
    let len = arg(ctx, 5);
    unsafe { sz = len as u32 };
    0 // don't override the exit code
}

#[link_section = "?kprobe.multi/bpf_testmod_test_read"]
#[no_mangle]
extern "C" fn kprobe_multi(_ctx: *const c_void) -> i32 {
    0
}

bpf_object!("GPL");
