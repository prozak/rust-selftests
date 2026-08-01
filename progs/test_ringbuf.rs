#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_ringbuf.c.
//
// The globals total/discarded/dropped are updated with
// __sync_fetch_and_add in C; here they stay plain isize (BTF "long") statics (so the
// regenerated skeleton sees `long`, same as C) and the add goes through
// an AtomicIsize view of the same storage.

use core::ffi::c_void;
use core::sync::atomic::{AtomicIsize, Ordering};

#[allow(non_camel_case_types)]
#[repr(C)]
struct sample {
    pid: i32,
    seq: i32,
    value: i64,
    comm: [u8; 16],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct ringbuf_def {
    r#type: *const [i32; 27], // BPF_MAP_TYPE_RINGBUF = 27
}
unsafe impl Sync for ringbuf_def {}

#[link_section = ".maps"]
#[no_mangle]
static ringbuf: ringbuf_def = ringbuf_def {
    r#type: core::ptr::null(),
};

/* inputs */
#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut value: isize = 0;
#[no_mangle]
static mut flags: isize = 0;

/* outputs */
#[no_mangle]
static mut total: isize = 0;
#[no_mangle]
static mut discarded: isize = 0;
#[no_mangle]
static mut dropped: isize = 0;

#[no_mangle]
static mut avail_data: isize = 0;
#[no_mangle]
static mut ring_size: isize = 0;
#[no_mangle]
static mut cons_pos: isize = 0;
#[no_mangle]
static mut prod_pos: isize = 0;

/* inner state */
#[no_mangle]
static mut seq: isize = 0;

const BPF_RB_AVAIL_DATA: u64 = 0;
const BPF_RB_RING_SIZE: u64 = 1;
const BPF_RB_CONS_POS: u64 = 2;
const BPF_RB_PROD_POS: u64 = 3;

#[inline(always)]
fn bpf_get_current_pid_tgid() -> u64 {
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(14usize) };
    f()
}

#[inline(always)]
fn bpf_get_current_comm(buf: *mut c_void, size: u32) -> i64 {
    let f: extern "C" fn(*mut c_void, u32) -> i64 = unsafe { core::mem::transmute(16usize) };
    f(buf, size)
}

#[inline(always)]
fn bpf_ringbuf_output(map: *const ringbuf_def, data: *const c_void, size: u64, rb_flags: u64) -> i64 {
    let f: extern "C" fn(*const ringbuf_def, *const c_void, u64, u64) -> i64 =
        unsafe { core::mem::transmute(130usize) };
    f(map, data, size, rb_flags)
}

#[inline(always)]
fn bpf_ringbuf_reserve(map: *const ringbuf_def, size: u64, rb_flags: u64) -> *mut c_void {
    let f: extern "C" fn(*const ringbuf_def, u64, u64) -> *mut c_void =
        unsafe { core::mem::transmute(131usize) };
    f(map, size, rb_flags)
}

#[inline(always)]
fn bpf_ringbuf_submit(data: *mut c_void, rb_flags: u64) {
    let f: extern "C" fn(*mut c_void, u64) = unsafe { core::mem::transmute(132usize) };
    f(data, rb_flags)
}

#[inline(always)]
fn bpf_ringbuf_discard(data: *mut c_void, rb_flags: u64) {
    let f: extern "C" fn(*mut c_void, u64) = unsafe { core::mem::transmute(133usize) };
    f(data, rb_flags)
}

#[inline(always)]
fn bpf_ringbuf_query(map: *const ringbuf_def, rb_flags: u64) -> u64 {
    let f: extern "C" fn(*const ringbuf_def, u64) -> u64 =
        unsafe { core::mem::transmute(134usize) };
    f(map, rb_flags)
}

#[inline(always)]
fn sync_fetch_and_add(p: *mut isize, v: isize) {
    unsafe { (*(p as *mut AtomicIsize)).fetch_add(v, Ordering::SeqCst) };
}

#[link_section = "fentry/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn test_ringbuf(_ctx: *const c_void) -> i32 {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    if cur_pid != unsafe { pid } {
        return 0;
    }

    let sample = bpf_ringbuf_reserve(&ringbuf, core::mem::size_of::<sample>() as u64, 0)
        as *mut sample;
    if sample.is_null() {
        sync_fetch_and_add(core::ptr::addr_of_mut!(dropped), 1);
        return 0;
    }

    unsafe {
        (*sample).pid = pid;
        bpf_get_current_comm((*sample).comm.as_mut_ptr() as *mut c_void, 16);
        (*sample).value = value as i64;

        (*sample).seq = seq as i32;
        seq += 1;
        sync_fetch_and_add(core::ptr::addr_of_mut!(total), 1);

        if (*sample).seq & 1 != 0 {
            /* copy from reserved sample to a new one... */
            bpf_ringbuf_output(
                &ringbuf,
                sample as *const c_void,
                core::mem::size_of::<sample>() as u64,
                flags as u64,
            );
            /* ...and then discard reserved sample */
            bpf_ringbuf_discard(sample as *mut c_void, flags as u64);
            sync_fetch_and_add(core::ptr::addr_of_mut!(discarded), 1);
        } else {
            bpf_ringbuf_submit(sample as *mut c_void, flags as u64);
        }

        avail_data = bpf_ringbuf_query(&ringbuf, BPF_RB_AVAIL_DATA) as isize;
        ring_size = bpf_ringbuf_query(&ringbuf, BPF_RB_RING_SIZE) as isize;
        cons_pos = bpf_ringbuf_query(&ringbuf, BPF_RB_CONS_POS) as isize;
        prod_pos = bpf_ringbuf_query(&ringbuf, BPF_RB_PROD_POS) as isize;
    }

    0
}

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
