#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_attach_probe.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_copy_from_user, bpf_probe_read_user, bpf_strncmp};
use core::ffi::c_void;

const BPF_F_PAD_ZEROS: u64 = 1;

#[no_mangle]
static mut dynamic_sz: u32 = 1;
#[no_mangle]
static mut kprobe2_res: i32 = 0;
#[no_mangle]
static mut kretprobe2_res: i32 = 0;
#[no_mangle]
static mut uprobe_byname_res: i32 = 0;
#[no_mangle]
static mut uretprobe_byname_res: i32 = 0;
#[no_mangle]
static mut uprobe_byname2_res: i32 = 0;
#[no_mangle]
static mut uretprobe_byname2_res: i32 = 0;
#[no_mangle]
static mut uprobe_byname3_sleepable_res: i32 = 0;
#[no_mangle]
static mut uprobe_byname3_str_sleepable_res: i32 = 0;
#[no_mangle]
static mut uprobe_byname3_res: i32 = 0;
#[no_mangle]
static mut uretprobe_byname3_sleepable_res: i32 = 0;
#[no_mangle]
static mut uretprobe_byname3_str_sleepable_res: i32 = 0;
#[no_mangle]
static mut uretprobe_byname3_res: i32 = 0;
#[no_mangle]
static mut user_ptr: *mut c_void = core::ptr::null_mut();

extern "C" {
    fn bpf_copy_from_user_str(dst: *mut c_void, dst_sz: u32, src: *const c_void, flags: u64) -> i32;
}

/// UML x86-64: `struct pt_regs` wraps `struct uml_pt_regs`, whose `gp[]` is
/// indexed by the host `user_regs_struct` layout
/// (arch/x86/um/shared/sysdep/ptrace_64.h), so `ctx` here doubles as a
/// `*const u64` register-slot array — same mapping test_probe_user.rs uses:
/// PARM1 = gp[14] (di), PARM2 = gp[13] (si), RC = gp[10] (ax).
#[link_section = "ksyscall/nanosleep"]
#[no_mangle]
extern "C" fn handle_kprobe_auto(_ctx: *const u64) -> i32 {
    unsafe { kprobe2_res = 11 };
    0
}

#[link_section = "kretsyscall/nanosleep"]
#[no_mangle]
extern "C" fn handle_kretprobe_auto(ctx: *const u64) -> i32 {
    let ret = unsafe { *ctx.add(10) } as i32;
    unsafe { kretprobe2_res = 22 };
    ret
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn handle_uprobe_ref_ctr(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "uretprobe"]
#[no_mangle]
extern "C" fn handle_uretprobe_ref_ctr(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn handle_uprobe_byname(_ctx: *const c_void) -> i32 {
    unsafe { uprobe_byname_res = 5 };
    0
}

/* use auto-attach format for section definition. */
#[link_section = "uretprobe//proc/self/exe:trigger_func2"]
#[no_mangle]
extern "C" fn handle_uretprobe_byname(_ctx: *const c_void) -> i32 {
    unsafe { uretprobe_byname_res = 6 };
    0
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn handle_uprobe_byname2(ctx: *const u64) -> i32 {
    let mode = unsafe { *ctx.add(13) } as *const c_void;
    let mut mode_buf = [0u8; 2];

    /* verify fopen mode */
    unsafe {
        bpf_probe_read_user(mode_buf.as_mut_ptr() as *mut c_void, 2, mode);
    }
    if mode_buf[0] == b'r' && mode_buf[1] == 0 {
        unsafe { uprobe_byname2_res = 7 };
    }
    0
}

#[link_section = "uretprobe"]
#[no_mangle]
extern "C" fn handle_uretprobe_byname2(_ctx: *const c_void) -> i32 {
    unsafe { uretprobe_byname2_res = 8 };
    0
}

fn verify_sleepable_user_copy() -> bool {
    let mut data = [0u8; 9];
    let src = unsafe { user_ptr };

    unsafe {
        bpf_copy_from_user(data.as_mut_ptr() as *mut c_void, 9, src);
    }
    bpf_strncmp(
        data.as_ptr() as *const c_void,
        9,
        b"test_data".as_ptr() as *const c_void,
    ) == 0
}

fn verify_sleepable_user_copy_str() -> bool {
    let mut data_long = [0u8; 20];
    let mut data_long_pad = [0u8; 20];
    let mut data_long_err = [0u8; 20];
    let mut data_short = [0u8; 4];
    let mut data_short_pad = [0u8; 4];
    let src = unsafe { user_ptr };

    let ret =
        unsafe { bpf_copy_from_user_str(data_short.as_mut_ptr() as *mut c_void, 4, src, 0) };
    if bpf_strncmp(
        data_short.as_ptr() as *const c_void,
        4,
        b"tes\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 4
    {
        return false;
    }

    let ret = unsafe {
        bpf_copy_from_user_str(
            data_short_pad.as_mut_ptr() as *mut c_void,
            4,
            src,
            BPF_F_PAD_ZEROS,
        )
    };
    if bpf_strncmp(
        data_short.as_ptr() as *const c_void,
        4,
        b"tes\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 4
    {
        return false;
    }

    /* Make sure this passes the verifier */
    let sz = unsafe { dynamic_sz } & 20;
    let ret = unsafe { bpf_copy_from_user_str(data_long.as_mut_ptr() as *mut c_void, sz, src, 0) };
    if ret != 0 {
        return false;
    }

    let ret =
        unsafe { bpf_copy_from_user_str(data_long.as_mut_ptr() as *mut c_void, 20, src, 0) };
    if bpf_strncmp(
        data_long.as_ptr() as *const c_void,
        10,
        b"test_data\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 10
    {
        return false;
    }

    let ret = unsafe {
        bpf_copy_from_user_str(
            data_long_pad.as_mut_ptr() as *mut c_void,
            20,
            src,
            BPF_F_PAD_ZEROS,
        )
    };
    if bpf_strncmp(
        data_long_pad.as_ptr() as *const c_void,
        10,
        b"test_data\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 10
        || data_long_pad[19] != 0
    {
        return false;
    }

    let ret = unsafe {
        bpf_copy_from_user_str(
            data_long_err.as_mut_ptr() as *mut c_void,
            20,
            data_long.as_ptr() as *const c_void,
            BPF_F_PAD_ZEROS,
        )
    };
    if ret > 0 || data_long_err[19] != 0 {
        return false;
    }

    let ret = unsafe { bpf_copy_from_user_str(data_long.as_mut_ptr() as *mut c_void, 20, src, 2) };
    if ret != -22 {
        // -EINVAL
        return false;
    }

    true
}

#[link_section = "uprobe.s//proc/self/exe:trigger_func3"]
#[no_mangle]
extern "C" fn handle_uprobe_byname3_sleepable(_ctx: *const c_void) -> i32 {
    if verify_sleepable_user_copy() {
        unsafe { uprobe_byname3_sleepable_res = 9 };
    }
    if verify_sleepable_user_copy_str() {
        unsafe { uprobe_byname3_str_sleepable_res = 10 };
    }
    0
}

/**
 * same target as the uprobe.s above to force sleepable and non-sleepable
 * programs in the same bpf_prog_array
 */
#[link_section = "uprobe//proc/self/exe:trigger_func3"]
#[no_mangle]
extern "C" fn handle_uprobe_byname3(_ctx: *const c_void) -> i32 {
    unsafe { uprobe_byname3_res = 11 };
    0
}

#[link_section = "uretprobe.s//proc/self/exe:trigger_func3"]
#[no_mangle]
extern "C" fn handle_uretprobe_byname3_sleepable(_ctx: *const c_void) -> i32 {
    if verify_sleepable_user_copy() {
        unsafe { uretprobe_byname3_sleepable_res = 12 };
    }
    if verify_sleepable_user_copy_str() {
        unsafe { uretprobe_byname3_str_sleepable_res = 13 };
    }
    0
}

#[link_section = "uretprobe//proc/self/exe:trigger_func3"]
#[no_mangle]
extern "C" fn handle_uretprobe_byname3(_ctx: *const c_void) -> i32 {
    unsafe { uretprobe_byname3_res = 14 };
    0
}

bpf_object!("GPL");
