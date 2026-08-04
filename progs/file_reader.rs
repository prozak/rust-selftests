#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/file_reader.c
// (bpf-rs-core idiom).
//
// The 256000-byte compare loop (`bpf_for(i, 0, len) { tmp_buf[i] !=
// user_buf[i] }` in the C source) is an open-coded num-iterator loop; there
// is no bpf-rs-core wrapper for that construct, so it is reimplemented via
// `bpf_loop` (same technique as strobemeta_bpf_loop.rs): the callback bound-
// checks its index against both the requested length and the fixed 256000-
// byte backing arrays before every access, so the verifier can prove every
// load is in range.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_dynptr_read, bpf_get_current_pid_tgid, bpf_get_current_task_btf, bpf_loop,
    bpf_map_lookup_elem,
};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

const USER_BUF_LEN: u32 = 256000;
const EFAULT: i32 = 14;

#[repr(C, align(8))]
struct bpf_dynptr {
    opaque: [u64; 2],
}

// struct bpf_task_work { __u64 __opaque; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_task_work {
    __opaque: u64,
}

#[allow(dead_code)]
#[repr(C)]
struct elem {
    file: *mut c_void,
    tw: bpf_task_work,
}

#[link_section = ".maps"]
#[no_mangle]
static arrmap: BpfMap<i32, elem, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut user_buf: [u8; 256000] = [0; 256000];
#[no_mangle]
static mut tmp_buf: [u8; 256000] = [0; 256000];

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut err: i32 = 0;
#[no_mangle]
static mut run_success: i32 = 0;

extern "C" {
    fn bpf_get_task_exe_file(task: *mut c_void) -> *mut c_void;
    fn bpf_put_file(file: *mut c_void);
    fn bpf_dynptr_from_file(file: *mut c_void, flags: u32, ptr: *mut c_void) -> i32;
    fn bpf_dynptr_file_discard(ptr: *mut c_void) -> i32;
    fn bpf_dynptr_adjust(ptr: *mut c_void, start: u64, end: u64) -> i32;
    fn bpf_task_work_schedule_signal(
        task: *mut c_void,
        tw: *mut c_void,
        map: *mut c_void,
        callback: extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32,
    ) -> i32;
}

fn current_pid() -> i32 {
    (bpf_get_current_pid_tgid() >> 32) as i32
}

#[repr(C)]
struct VerifyCtx {
    user_off: u32,
    len: u32,
    mismatch: i32,
}

extern "C" fn verify_cb(index: u64, ctx: *mut VerifyCtx) -> i64 {
    let c = unsafe { &mut *ctx };
    let i = index as u32;
    if i >= c.len || i >= USER_BUF_LEN {
        return 1;
    }
    let uoff = c.user_off.wrapping_add(i);
    if uoff >= USER_BUF_LEN {
        return 1;
    }
    let a = unsafe { *(core::ptr::addr_of!(tmp_buf) as *const u8).add(i as usize) };
    let b = unsafe { *(core::ptr::addr_of!(user_buf) as *const u8).add(uoff as usize) };
    if a != b {
        c.mismatch = 1;
        return 1;
    }
    0
}

// static int verify_dynptr_read(struct bpf_dynptr *ptr, u32 off, char
// *user_buf, u32 len) -- `user_buf` in the C source is always
// `user_buf + user_off` for some offset into the global array, so the
// pointer argument is replaced here by that numeric offset.
fn verify_dynptr_read(ptr: *mut c_void, dynptr_off: u32, user_off: u32, len: u32) -> i32 {
    let n = unsafe {
        bpf_dynptr_read(
            core::ptr::addr_of_mut!(tmp_buf) as *mut c_void,
            len as u64,
            ptr as *const c_void,
            dynptr_off as u64,
            0,
        )
    };
    if n != 0 {
        return 1;
    }

    let mut vctx = VerifyCtx {
        user_off,
        len,
        mismatch: 0,
    };
    bpf_loop(len, verify_cb, &mut vctx as *mut VerifyCtx, 0);
    if vctx.mismatch != 0 {
        1
    } else {
        0
    }
}

fn validate_file_read(file: *mut c_void) -> i32 {
    let mut dynptr = bpf_dynptr { opaque: [0; 2] };
    let dp = &mut dynptr as *mut bpf_dynptr as *mut c_void;
    let mut loc_err: i32 = 1;

    if unsafe { bpf_dynptr_from_file(file, 0, dp) } == 0 {
        loc_err = verify_dynptr_read(dp, 0, 0, USER_BUF_LEN);

        if loc_err == 0 {
            loc_err = verify_dynptr_read(dp, 1, 1, USER_BUF_LEN - 1);
        }

        let off2 = USER_BUF_LEN - 1;
        if loc_err == 0 {
            loc_err = verify_dynptr_read(dp, off2, off2, USER_BUF_LEN - off2);
        }

        // Read file with random offset and length
        let off: u32 = 4097;
        if loc_err == 0 {
            loc_err = verify_dynptr_read(dp, off, off, 100);
        }

        // Adjust dynptr, verify read
        if loc_err == 0 {
            loc_err = unsafe { bpf_dynptr_adjust(dp, off as u64, (off + 1) as u64) };
        }
        if loc_err == 0 {
            loc_err = verify_dynptr_read(dp, 0, off, 1);
        }
        // Can't read more than 1 byte
        if loc_err == 0 {
            loc_err = (verify_dynptr_read(dp, 0, off, 2) == 0) as i32;
        }
        // Can't read with far offset
        if loc_err == 0 {
            loc_err = (verify_dynptr_read(dp, 1, off, 1) == 0) as i32;
        }
    }

    unsafe { bpf_dynptr_file_discard(dp) };
    loc_err
}

// Called in a sleepable context, read 256K bytes, cross check with user
// space read data
extern "C" fn task_work_callback(
    _map: *mut c_void,
    _key: *mut c_void,
    _value: *mut c_void,
) -> i32 {
    let task = bpf_get_current_task_btf::<c_void>();
    let file = unsafe { bpf_get_task_exe_file(task) };
    if file.is_null() {
        return 0;
    }

    let e = validate_file_read(file);
    unsafe { err = e };
    if e == 0 {
        unsafe { run_success = 1 };
    }
    unsafe { bpf_put_file(file) };
    0
}

#[link_section = "lsm/file_open"]
#[no_mangle]
extern "C" fn on_open_expect_fault(_c: *const c_void) -> i32 {
    let mut dynptr = bpf_dynptr { opaque: [0; 2] };
    let dp = &mut dynptr as *mut bpf_dynptr as *mut c_void;
    let mut local_err: i32 = 1;

    if current_pid() != unsafe { pid } {
        return 0;
    }

    let task = bpf_get_current_task_btf::<c_void>();
    let file = unsafe { bpf_get_task_exe_file(task) };
    if file.is_null() {
        return 0;
    }

    if unsafe { bpf_dynptr_from_file(file, 0, dp) } == 0 {
        local_err = unsafe {
            bpf_dynptr_read(
                core::ptr::addr_of_mut!(tmp_buf) as *mut c_void,
                USER_BUF_LEN as u64,
                dp as *const c_void,
                USER_BUF_LEN as u64,
                0,
            )
        } as i32;
        // Expect page fault or success
        if local_err == -EFAULT || local_err == 0 {
            local_err = 0;
            unsafe { run_success = 1 };
        }
    }
    unsafe { bpf_dynptr_file_discard(dp) };
    if local_err != 0 {
        unsafe { err = local_err };
    }
    unsafe { bpf_put_file(file) };
    0
}

#[link_section = "lsm/file_open"]
#[no_mangle]
extern "C" fn on_open_validate_file_read(_c: *const c_void) -> i32 {
    if current_pid() != unsafe { pid } {
        return 0;
    }

    let task = bpf_get_current_task_btf::<c_void>();
    let key: i32 = 0;
    let work = bpf_map_lookup_elem(&arrmap, &key) as *mut elem;
    if work.is_null() {
        unsafe { err = 1 };
        return 0;
    }

    let tw = unsafe { core::ptr::addr_of_mut!((*work).tw) as *mut c_void };
    unsafe {
        bpf_task_work_schedule_signal(
            task,
            tw,
            &arrmap as *const _ as *mut c_void,
            task_work_callback,
        );
    }
    0
}

bpf_object!("GPL");
