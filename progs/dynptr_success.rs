// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/dynptr_success.c
// (bpf-rs-core idiom). Thirty-one positive dynptr programs over ring
// buffer, map value, skb, skb metadata and xdp dynptrs, each attached or
// test-run by prog_tests/dynptr.c, which then checks the `err` global.
//
// C string locals (`char data[] = "..."`) are explicit u64 immediates: an
// array copy becomes an llvm.memcpy, which the pipeline turns into a
// bpf_arena_memcpy kfunc call. `bpf_for` is the open-coded num iterator
// with the header's bounds test, destroyed on every exit path as its
// cleanup attribute does. The kfuncs' bool results are tested on their
// low bit, as the C object does.
//
// BTF_C_CHAR: u8
// BTF_C_VOID: c_void

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{addr_of, addr_of_mut, write_bytes};

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_dynptr_data, bpf_dynptr_from_mem, bpf_dynptr_read, bpf_dynptr_write,
    bpf_get_current_pid_tgid, bpf_get_current_task_btf, bpf_loop, bpf_map_lookup_elem,
    bpf_map_update_elem, bpf_probe_read_kernel, bpf_ringbuf_discard_dynptr,
    bpf_ringbuf_reserve_dynptr, bpf_ringbuf_submit_dynptr, bpf_strncmp,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::{bpf_map, bpf_object};

const EINVAL: i32 = 22;
const E2BIG: i32 = 7;
const ERANGE: i32 = 34;
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
const PAGE_SIZE_64K: u32 = 65536;
/* sizeof(struct ethhdr) + sizeof(struct iphdr) */
const TEST_SKB_LINEAR_SIZE: u32 = 14 + 20;
const DYNPTR_MEMSET_VAL: u8 = 42;

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut err: i32 = 0;
#[no_mangle]
static mut val: i32 = 0;

#[allow(non_camel_case_types)]
#[repr(C)]
struct ringbuf_sample {
    pid: i32,
    seq: i32,
    value: i64,
    comm: [u8; 16],
}

bpf_map! {
    ringbuf {
        r#type: *const [i32; maps::RINGBUF],
        max_entries: *const [i32; 4096],
    }
}

#[link_section = ".maps"]
#[no_mangle]
static array_map: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct task_struct {
    _opaque: [u8; 0],
}

extern "C" {
    fn bpf_dynptr_from_skb(skb: *mut c_void, flags: u64, ptr__uninit: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_from_skb_meta(skb: *mut c_void, flags: u64, ptr__uninit: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_from_xdp(xdp: *mut xdp_md, flags: u64, ptr__uninit: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_slice(
        ptr: *const bpf_dynptr,
        offset: u32,
        buffer__opt: *mut c_void,
        buffer__szk: u32,
    ) -> *mut c_void;
    fn bpf_dynptr_adjust(ptr: *const bpf_dynptr, start: u32, end: u32) -> i32;
    fn bpf_dynptr_is_null(ptr: *const bpf_dynptr) -> u8;
    fn bpf_dynptr_is_rdonly(ptr: *const bpf_dynptr) -> u8;
    fn bpf_dynptr_size(ptr: *const bpf_dynptr) -> u32;
    fn bpf_dynptr_clone(ptr: *const bpf_dynptr, clone__uninit: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_memset(ptr: *const bpf_dynptr, offset: u32, size: u32, val: u8) -> i32;
    fn bpf_dynptr_copy(
        dst_ptr: *const bpf_dynptr,
        dst_off: u32,
        src_ptr: *const bpf_dynptr,
        src_off: u32,
        size: u32,
    ) -> i32;
    fn bpf_probe_read_user_dynptr(dptr: *const bpf_dynptr, off: u32, size: u32, unsafe_ptr: *const c_void) -> i32;
    fn bpf_probe_read_kernel_dynptr(dptr: *const bpf_dynptr, off: u32, size: u32, unsafe_ptr: *const c_void) -> i32;
    fn bpf_probe_read_user_str_dynptr(dptr: *const bpf_dynptr, off: u32, size: u32, unsafe_ptr: *const c_void) -> i32;
    fn bpf_probe_read_kernel_str_dynptr(dptr: *const bpf_dynptr, off: u32, size: u32, unsafe_ptr: *const c_void) -> i32;
    fn bpf_copy_from_user_dynptr(dptr: *const bpf_dynptr, off: u32, size: u32, unsafe_ptr: *const c_void) -> i32;
    fn bpf_copy_from_user_str_dynptr(dptr: *const bpf_dynptr, off: u32, size: u32, unsafe_ptr: *const c_void) -> i32;
    fn bpf_copy_from_user_task_dynptr(
        dptr: *const bpf_dynptr,
        off: u32,
        size: u32,
        unsafe_ptr: *const c_void,
        tsk: *mut task_struct,
    ) -> i32;
    fn bpf_copy_from_user_task_str_dynptr(
        dptr: *const bpf_dynptr,
        off: u32,
        size: u32,
        unsafe_ptr: *const c_void,
        tsk: *mut task_struct,
    ) -> i32;
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
}

#[inline(always)]
fn current_pid_matches() -> bool {
    (bpf_get_current_pid_tgid() >> 32) == unsafe { pid } as u64
}

#[inline(always)]
fn get_err() -> i32 {
    unsafe { err }
}

#[inline(always)]
fn set_err(v: i32) {
    unsafe {
        err = v;
    }
}

/// bpf_for(i, start, end): the iterator's `next` plus the header's
/// `(i) >= (start) && (i) < (end)` bounds test. A plain `break` falls
/// through to the destroy below, as the C cleanup attribute runs on leaving
/// the loop; a `return` or a labeled break out of the enclosing block must
/// destroy `$it` itself first.
macro_rules! bpf_for {
    ($it:ident, $i:ident, $start:expr, $end:expr, $body:block) => {
        let mut $it = MaybeUninit::<bpf_iter_num>::uninit();
        unsafe {
            bpf_iter_num_new($it.as_mut_ptr(), $start, ($end) as i32);
        }
        loop {
            let t = unsafe { bpf_iter_num_next($it.as_mut_ptr()) };
            if t.is_null() {
                break;
            }
            let $i: i32 = unsafe { *t };
            if !($i >= $start && ($i as u32) < ($end) as u32) {
                break;
            }
            $body
        }
        unsafe {
            bpf_iter_num_destroy($it.as_mut_ptr());
        }
    };
}

#[inline(always)]
fn dp(p: &MaybeUninit<bpf_dynptr>) -> *const bpf_dynptr {
    p.as_ptr()
}

#[inline(always)]
fn dpv(p: &MaybeUninit<bpf_dynptr>) -> *mut c_void {
    p.as_ptr() as *mut c_void
}

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_read_write(_ctx: *mut c_void) -> i32 {
    /* char write_data[64] = "hello there, world!!"; */
    let mut write_data = [0u64; 8];
    write_data[0] = 0x6874206f6c6c6568;
    write_data[1] = 0x726f77202c657265;
    write_data[2] = 0x2121646c;
    let mut read_data = [0u8; 64];
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    if !current_pid_matches() {
        return 0;
    }

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&ptr));

    /* Write data into the dynptr */
    set_err(bpf_dynptr_write(dp(&ptr), 0, write_data.as_mut_ptr() as *mut c_void, 64, 0) as i32);

    /* Read the data that was written into the dynptr */
    if get_err() == 0 {
        set_err(bpf_dynptr_read(read_data.as_mut_ptr() as *mut c_void, 64, dp(&ptr), 0, 0) as i32);
    }

    /* Ensure the data we read matches the data we wrote */
    let wd = write_data.as_ptr() as *const u8;
    let rd = read_data.as_ptr();
    let mut i: usize = 0;
    while i < 64 {
        if unsafe { *rd.add(i) != *wd.add(i) } {
            set_err(1);
            break;
        }
        i += 1;
    }

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);
    0
}

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_dynptr_data(_ctx: *mut c_void) -> i32 {
    let key: u32 = 0;
    /* the C local `val` shadows the global */
    let mut lval: u32 = 235;
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let map_val_size: u32 = 4;

    if !current_pid_matches() {
        return 0;
    }

    bpf_map_update_elem(&array_map, &key, &lval, 0);

    let map_val = bpf_map_lookup_elem(&array_map, &key) as *mut u32;
    if map_val.is_null() {
        set_err(1);
        return 0;
    }

    bpf_dynptr_from_mem(map_val as *mut c_void, map_val_size as u64, 0, dpv(&ptr));

    /* Try getting a data slice that is out of range */
    let data = bpf_dynptr_data(dp(&ptr) as *const c_void, (map_val_size + 1) as u64, 1);
    if !data.is_null() {
        set_err(2);
        return 0;
    }

    /* Try getting more bytes than available */
    let data = bpf_dynptr_data(dp(&ptr) as *const c_void, 0, (map_val_size + 1) as u64);
    if !data.is_null() {
        set_err(3);
        return 0;
    }

    let data = bpf_dynptr_data(dp(&ptr) as *const c_void, 0, 4);
    if data.is_null() {
        set_err(4);
        return 0;
    }

    unsafe {
        *(data as *mut u32) = 999;
    }

    set_err(bpf_probe_read_kernel(&mut lval, 4, data as *const c_void) as i32);
    if get_err() != 0 {
        return 0;
    }

    if lval as i32 != unsafe { *(data as *const i32) } {
        set_err(5);
    }

    0
}

#[export_name = "ringbuf_callback"]
extern "C" fn ringbuf_callback(index: u64, data: *mut bpf_dynptr) -> i64 {
    let ptr = data;

    let sample = bpf_dynptr_data(ptr as *const c_void, 0, 32) as *mut ringbuf_sample;
    if sample.is_null() {
        set_err(2);
    } else {
        unsafe {
            (*sample).pid = (*sample).pid.wrapping_add(index as u32 as i32);
        }
    }

    0
}

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_ringbuf(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    if !current_pid_matches() {
        return 0;
    }

    unsafe {
        val = 100;
    }

    /* check that you can reserve a dynamic size reservation */
    set_err(bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr)) as i32);

    let sample = if get_err() != 0 {
        core::ptr::null_mut()
    } else {
        bpf_dynptr_data(dp(&ptr) as *const c_void, 0, 32) as *mut ringbuf_sample
    };
    'done: {
        if sample.is_null() {
            set_err(1);
            break 'done;
        }

        unsafe {
            (*sample).pid = 10;
        }

        /* Can pass dynptr to callback functions */
        bpf_loop(10, ringbuf_callback, dp(&ptr) as *mut bpf_dynptr, 0);

        if unsafe { (*sample).pid } != 55 {
            set_err(2);
        }
    }

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);
    0
}

#[link_section = "?cgroup_skb/egress"]
#[no_mangle]
extern "C" fn test_skb_readonly(skb: *mut __sk_buff) -> i32 {
    /* the C's frame: write_data at fp-2, ptr at fp-0x18 (rustc places the
     * last local highest) */
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut write_data: [u8; 2] = [1, 2];

    if unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, dp(&ptr) as *mut bpf_dynptr) } != 0 {
        set_err(1);
        return 1;
    }

    /* since cgroup skbs are read only, writes should fail */
    let ret = bpf_dynptr_write(dp(&ptr), 0, write_data.as_mut_ptr() as *mut c_void, 2, 0) as i32;
    if ret != -EINVAL {
        set_err(2);
        return 1;
    }

    1
}

#[link_section = "?cgroup_skb/egress"]
#[no_mangle]
extern "C" fn test_dynptr_skb_data(skb: *mut __sk_buff) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    if unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, dp(&ptr) as *mut bpf_dynptr) } != 0 {
        set_err(1);
        return 1;
    }

    /* This should return NULL. Must use bpf_dynptr_slice API */
    let data = bpf_dynptr_data(dp(&ptr) as *const c_void, 0, 1);
    if !data.is_null() {
        set_err(2);
        return 1;
    }

    1
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn test_dynptr_skb_slice_non_linear(skb: *mut __sk_buff) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    if unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, dp(&ptr) as *mut bpf_dynptr) } != 0 {
        set_err(1);
        return 1;
    }

    /* Ensure we cannot read past the end of the buffer. */
    let data =
        unsafe { bpf_dynptr_slice(dp(&ptr), TEST_SKB_LINEAR_SIZE + 1, core::ptr::null_mut(), 1) };
    if !data.is_null() {
        set_err(2);
    }

    1
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn test_dynptr_skb_meta_data(skb: *mut __sk_buff) -> i32 {
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    set_err(1);
    let ret = unsafe { bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dp(&meta) as *mut bpf_dynptr) };
    if ret != 0 {
        return 1;
    }

    /* This should return NULL. Must use bpf_dynptr_slice API */
    set_err(2);
    let md = bpf_dynptr_data(dp(&meta) as *const c_void, 0, 1) as *mut u8;
    if !md.is_null() {
        return 1;
    }

    set_err(0);
    1
}

/* Check that skb metadata dynptr ops don't accept any flags. */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn test_dynptr_skb_meta_flags(skb: *mut __sk_buff) -> i32 {
    const INVALID_FLAGS: u64 = !0u64;
    let meta = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buf = MaybeUninit::<u8>::uninit();

    set_err(1);
    let ret =
        unsafe { bpf_dynptr_from_skb_meta(skb as *mut c_void, INVALID_FLAGS, dp(&meta) as *mut bpf_dynptr) };
    if ret != -EINVAL {
        return 1;
    }

    set_err(2);
    let ret = unsafe { bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dp(&meta) as *mut bpf_dynptr) };
    if ret != 0 {
        return 1;
    }

    set_err(3);
    let ret = bpf_dynptr_read(buf.as_mut_ptr() as *mut c_void, 0, dp(&meta), 0, INVALID_FLAGS) as i32;
    if ret != -EINVAL {
        return 1;
    }

    set_err(4);
    let ret = bpf_dynptr_write(dp(&meta), 0, buf.as_mut_ptr() as *mut c_void, 0, INVALID_FLAGS) as i32;
    if ret != -EINVAL {
        return 1;
    }

    set_err(0);
    1
}

#[link_section = "tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_adjust(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let bytes: u32 = 64;
    let off: u32 = 10;
    let trim: u32 = 15;

    if !current_pid_matches() {
        return 0;
    }

    'done: {
        set_err(bpf_ringbuf_reserve_dynptr(&ringbuf, bytes, 0, dpv(&ptr)) as i32);
        if get_err() != 0 {
            set_err(1);
            break 'done;
        }

        if unsafe { bpf_dynptr_size(dp(&ptr)) } != bytes {
            set_err(2);
            break 'done;
        }

        /* Advance the dynptr by off */
        let size = unsafe { bpf_dynptr_size(dp(&ptr)) };
        set_err(unsafe { bpf_dynptr_adjust(dp(&ptr), off, size) });
        if get_err() != 0 {
            set_err(3);
            break 'done;
        }

        if unsafe { bpf_dynptr_size(dp(&ptr)) } != bytes - off {
            set_err(4);
            break 'done;
        }

        /* Trim the dynptr */
        set_err(unsafe { bpf_dynptr_adjust(dp(&ptr), off, 15) });
        if get_err() != 0 {
            set_err(5);
            break 'done;
        }

        /* Check that the size was adjusted correctly */
        if unsafe { bpf_dynptr_size(dp(&ptr)) } != trim - off {
            set_err(6);
            break 'done;
        }
    }

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);
    0
}

#[link_section = "tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_adjust_err(_ctx: *mut c_void) -> i32 {
    /* char write_data[45] = "hello there, world!!"; */
    let mut write_data = [0u64; 6];
    write_data[0] = 0x6874206f6c6c6568;
    write_data[1] = 0x726f77202c657265;
    write_data[2] = 0x2121646c;
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let size: u32 = 64;
    let off: u32 = 20;

    if !current_pid_matches() {
        return 0;
    }

    'done: {
        if bpf_ringbuf_reserve_dynptr(&ringbuf, size, 0, dpv(&ptr)) != 0 {
            set_err(1);
            break 'done;
        }

        /* Check that start can't be greater than end */
        if unsafe { bpf_dynptr_adjust(dp(&ptr), 5, 1) } != -EINVAL {
            set_err(2);
            break 'done;
        }

        /* Check that start can't be greater than size */
        if unsafe { bpf_dynptr_adjust(dp(&ptr), size + 1, size + 1) } != -ERANGE {
            set_err(3);
            break 'done;
        }

        /* Check that end can't be greater than size */
        if unsafe { bpf_dynptr_adjust(dp(&ptr), 0, size + 1) } != -ERANGE {
            set_err(4);
            break 'done;
        }

        if unsafe { bpf_dynptr_adjust(dp(&ptr), off, size) } != 0 {
            set_err(5);
            break 'done;
        }

        /* Check that you can't write more bytes than available into the dynptr
         * after you've adjusted it
         */
        if bpf_dynptr_write(dp(&ptr), 0, write_data.as_mut_ptr() as *mut c_void, 45, 0) as i32 != -E2BIG {
            set_err(6);
            break 'done;
        }

        /* Check that even after adjusting, submitting/discarding
         * a ringbuf dynptr works
         */
        bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);
        return 0;
    }

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);
    0
}

#[link_section = "tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_zero_size_dynptr(_ctx: *mut c_void) -> i32 {
    let mut write_data: u8 = b'x';
    let mut read_data = MaybeUninit::<u8>::uninit();
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let size: u32 = 64;

    if !current_pid_matches() {
        return 0;
    }

    'done: {
        if bpf_ringbuf_reserve_dynptr(&ringbuf, size, 0, dpv(&ptr)) != 0 {
            set_err(1);
            break 'done;
        }

        /* After this, the dynptr has a size of 0 */
        if unsafe { bpf_dynptr_adjust(dp(&ptr), size, size) } != 0 {
            set_err(2);
            break 'done;
        }

        /* Test that reading + writing non-zero bytes is not ok */
        if bpf_dynptr_read(read_data.as_mut_ptr() as *mut c_void, 1, dp(&ptr), 0, 0) as i32 != -E2BIG {
            set_err(3);
            break 'done;
        }

        if bpf_dynptr_write(dp(&ptr), 0, &mut write_data as *mut u8 as *mut c_void, 1, 0) as i32 != -E2BIG {
            set_err(4);
            break 'done;
        }

        /* Test that reading + writing 0 bytes from a 0-size dynptr is ok */
        if bpf_dynptr_read(read_data.as_mut_ptr() as *mut c_void, 0, dp(&ptr), 0, 0) != 0 {
            set_err(5);
            break 'done;
        }

        if bpf_dynptr_write(dp(&ptr), 0, &mut write_data as *mut u8 as *mut c_void, 0, 0) != 0 {
            set_err(6);
            break 'done;
        }

        set_err(0);
    }

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);
    0
}

#[link_section = "tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_dynptr_is_null(_ctx: *mut c_void) -> i32 {
    let ptr1 = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr2 = MaybeUninit::<bpf_dynptr>::uninit();
    let size: u64 = 4;

    if !current_pid_matches() {
        return 0;
    }

    'exit_early: {
        /* Pass in invalid flags, get back an invalid dynptr */
        if bpf_ringbuf_reserve_dynptr(&ringbuf, size as u32, 123, dpv(&ptr1)) != -(EINVAL as i64) {
            set_err(1);
            break 'exit_early;
        }

        /* Test that the invalid dynptr is null */
        if unsafe { bpf_dynptr_is_null(dp(&ptr1)) } & 1 == 0 {
            set_err(2);
            break 'exit_early;
        }

        'exit: {
            /* Get a valid dynptr */
            if bpf_ringbuf_reserve_dynptr(&ringbuf, size as u32, 0, dpv(&ptr2)) != 0 {
                set_err(3);
                break 'exit;
            }

            /* Test that the valid dynptr is not null */
            if unsafe { bpf_dynptr_is_null(dp(&ptr2)) } & 1 != 0 {
                set_err(4);
                break 'exit;
            }
        }
        bpf_ringbuf_discard_dynptr(dpv(&ptr2), 0);
    }
    bpf_ringbuf_discard_dynptr(dpv(&ptr1), 0);
    0
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn test_dynptr_is_rdonly(skb: *mut __sk_buff) -> i32 {
    let ptr1 = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr2 = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr3 = MaybeUninit::<bpf_dynptr>::uninit();

    /* Pass in invalid flags, get back an invalid dynptr */
    if unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 123, dp(&ptr1) as *mut bpf_dynptr) } != -EINVAL {
        set_err(1);
        return 0;
    }

    /* Test that an invalid dynptr is_rdonly returns false */
    if unsafe { bpf_dynptr_is_rdonly(dp(&ptr1)) } & 1 != 0 {
        set_err(2);
        return 0;
    }

    /* Get a read-only dynptr */
    if unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, dp(&ptr2) as *mut bpf_dynptr) } != 0 {
        set_err(3);
        return 0;
    }

    /* Test that the dynptr is read-only */
    if unsafe { bpf_dynptr_is_rdonly(dp(&ptr2)) } & 1 == 0 {
        set_err(4);
        return 0;
    }

    'done: {
        /* Get a read-writeable dynptr */
        if bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&ptr3)) != 0 {
            set_err(5);
            break 'done;
        }

        /* Test that the dynptr is read-only */
        if unsafe { bpf_dynptr_is_rdonly(dp(&ptr3)) } & 1 != 0 {
            set_err(6);
            break 'done;
        }
    }

    bpf_ringbuf_discard_dynptr(dpv(&ptr3), 0);
    0
}

#[link_section = "cgroup_skb/egress"]
#[no_mangle]
extern "C" fn test_dynptr_clone(skb: *mut __sk_buff) -> i32 {
    let ptr1 = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr2 = MaybeUninit::<bpf_dynptr>::uninit();
    let off: u32 = 2;

    /* Get a dynptr */
    if unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, dp(&ptr1) as *mut bpf_dynptr) } != 0 {
        set_err(1);
        return 0;
    }

    let size = unsafe { bpf_dynptr_size(dp(&ptr1)) };
    if unsafe { bpf_dynptr_adjust(dp(&ptr1), off, size) } != 0 {
        set_err(2);
        return 0;
    }

    /* Clone the dynptr */
    if unsafe { bpf_dynptr_clone(dp(&ptr1), dp(&ptr2) as *mut bpf_dynptr) } != 0 {
        set_err(3);
        return 0;
    }

    let size = unsafe { bpf_dynptr_size(dp(&ptr1)) };

    /* Check that the clone has the same size and rd-only */
    if unsafe { bpf_dynptr_size(dp(&ptr2)) } != size {
        set_err(4);
        return 0;
    }

    if unsafe { bpf_dynptr_is_rdonly(dp(&ptr2)) & 1 != bpf_dynptr_is_rdonly(dp(&ptr1)) & 1 } {
        set_err(5);
        return 0;
    }

    /* Advance and trim the original dynptr */
    unsafe {
        bpf_dynptr_adjust(dp(&ptr1), 5, 5);
    }

    /* Check that only original dynptr was affected, and the clone wasn't */
    if unsafe { bpf_dynptr_size(dp(&ptr2)) } != size {
        set_err(6);
        return 0;
    }

    0
}

#[link_section = "?cgroup_skb/egress"]
#[no_mangle]
extern "C" fn test_dynptr_skb_no_buff(skb: *mut __sk_buff) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    if unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, dp(&ptr) as *mut bpf_dynptr) } != 0 {
        set_err(1);
        return 1;
    }

    /* This may return NULL. SKB may require a buffer */
    let data = unsafe { bpf_dynptr_slice(dp(&ptr), 0, core::ptr::null_mut(), 1) };

    (!data.is_null()) as i32
}

#[link_section = ".rodata.str1.1"]
static STR_FOO: [u8; 4] = *b"foo\0";

#[link_section = "?cgroup_skb/egress"]
#[no_mangle]
extern "C" fn test_dynptr_skb_strcmp(skb: *mut __sk_buff) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    if unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, dp(&ptr) as *mut bpf_dynptr) } != 0 {
        set_err(1);
        return 1;
    }

    /* This may return NULL. SKB may require a buffer */
    let data = unsafe { bpf_dynptr_slice(dp(&ptr), 0, core::ptr::null_mut(), 10) };
    if !data.is_null() {
        bpf_strncmp(data as *const c_void, 10, STR_FOO.as_ptr() as *const c_void);
        return 1;
    }

    1
}

#[link_section = "tp_btf/kfree_skb"]
#[no_mangle]
extern "C" fn test_dynptr_skb_tp_btf(ctx: *const u64) -> i32 {
    let skb = fentry_arg(ctx, 0) as *mut c_void;
    let mut write_data: [u8; 2] = [1, 2];
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    if unsafe { bpf_dynptr_from_skb(skb, 0, dp(&ptr) as *mut bpf_dynptr) } != 0 {
        set_err(1);
        return 1;
    }

    /* since tp_btf skbs are read only, writes should fail */
    let ret = bpf_dynptr_write(dp(&ptr), 0, write_data.as_mut_ptr() as *mut c_void, 2, 0) as i32;
    if ret != -EINVAL {
        set_err(2);
        return 1;
    }

    1
}

/* static inline int bpf_memcmp(const char *a, const char *b, u32 size):
 * BPF char is signed. */
#[inline(always)]
fn bpf_memcmp(a: *const u8, b: *const u8, size: u32) -> i32 {
    bpf_for!(it, i, 0, size, {
        let x = unsafe { *a.add(i as usize) };
        let y = unsafe { *b.add(i as usize) };
        if x != y {
            unsafe {
                bpf_iter_num_destroy(it.as_mut_ptr());
            }
            return if (x as i8) < (y as i8) { -1 } else { 1 };
        }
    });
    0
}

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_dynptr_copy(_ctx: *mut c_void) -> i32 {
    /* char data[] = "hello there, world!!"; (21 bytes) */
    let mut data = [0u64; 3];
    data[0] = 0x6874206f6c6c6568;
    data[1] = 0x726f77202c657265;
    data[2] = 0x2121646c;
    let mut buf = [0u8; 32];
    let sz: u32 = 21;
    let src = MaybeUninit::<bpf_dynptr>::uninit();
    let dst = MaybeUninit::<bpf_dynptr>::uninit();
    let datap = data.as_mut_ptr() as *mut u8;

    bpf_ringbuf_reserve_dynptr(&ringbuf, sz, 0, dpv(&src));
    bpf_ringbuf_reserve_dynptr(&ringbuf, sz, 0, dpv(&dst));

    /* Test basic case of copying contiguous memory backed dynptrs */
    set_err(bpf_dynptr_write(dp(&src), 0, datap as *mut c_void, sz as u64, 0) as i32);
    if get_err() == 0 {
        set_err(unsafe { bpf_dynptr_copy(dp(&dst), 0, dp(&src), 0, sz) });
    }
    if get_err() == 0 {
        set_err(bpf_dynptr_read(buf.as_mut_ptr() as *mut c_void, sz as u64, dp(&dst), 0, 0) as i32);
    }
    if get_err() == 0 {
        set_err(bpf_memcmp(datap, buf.as_ptr(), sz));
    }

    /* Test that offsets are handled correctly */
    if get_err() == 0 {
        set_err(unsafe { bpf_dynptr_copy(dp(&dst), 3, dp(&src), 5, sz - 5) });
    }
    if get_err() == 0 {
        set_err(bpf_dynptr_read(buf.as_mut_ptr() as *mut c_void, (sz - 5) as u64, dp(&dst), 3, 0) as i32);
    }
    if get_err() == 0 {
        set_err(bpf_memcmp(unsafe { datap.add(5) }, buf.as_ptr(), sz - 5));
    }

    bpf_ringbuf_discard_dynptr(dpv(&src), 0);
    bpf_ringbuf_discard_dynptr(dpv(&dst), 0);
    0
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn test_dynptr_copy_xdp(xdp: *mut xdp_md) -> i32 {
    let ptr_buf = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr_xdp = MaybeUninit::<bpf_dynptr>::uninit();
    /* char data[] = "qwertyuiopasdfghjkl"; (20 bytes) */
    let mut data = [0u64; 3];
    data[0] = 0x6975797472657771;
    data[1] = 0x686766647361706f;
    data[2] = 0x6c6b6a;
    let mut buf = [0u8; 32];
    let len: u32 = 20;
    let chunks: i32 = 200;
    let datap = data.as_mut_ptr() as *mut u8;

    /* ptr_xdp is backed by non-contiguous memory */
    unsafe {
        bpf_dynptr_from_xdp(xdp, 0, dp(&ptr_xdp) as *mut bpf_dynptr);
    }
    let xdp_data_size = unsafe { bpf_dynptr_size(dp(&ptr_xdp)) };
    bpf_ringbuf_reserve_dynptr(&ringbuf, len * chunks as u32, 0, dpv(&ptr_buf));

    'out: {
        /* Destination dynptr is backed by non-contiguous memory */
        bpf_for!(it, i, 0, chunks, {
            set_err(bpf_dynptr_write(dp(&ptr_buf), (i as u32 * len) as u64, datap as *mut c_void, len as u64, 0) as i32);
            if get_err() != 0 {
                unsafe { bpf_iter_num_destroy(it.as_mut_ptr()) };
                break 'out;
            }
        });

        set_err(unsafe { bpf_dynptr_copy(dp(&ptr_xdp), 0, dp(&ptr_buf), 0, len * chunks as u32) });
        if get_err() != 0 {
            break 'out;
        }

        bpf_for!(it, i, 0, chunks, {
            unsafe { write_bytes(buf.as_mut_ptr(), 0, 32) };
            set_err(bpf_dynptr_read(buf.as_mut_ptr() as *mut c_void, len as u64, dp(&ptr_xdp), (i as u32 * len) as u64, 0) as i32);
            if get_err() != 0 {
                unsafe { bpf_iter_num_destroy(it.as_mut_ptr()) };
                break 'out;
            }
            if bpf_memcmp(datap, buf.as_ptr(), len) != 0 {
                unsafe { bpf_iter_num_destroy(it.as_mut_ptr()) };
                break 'out;
            }
        });

        /* Source dynptr is backed by non-contiguous memory */
        unsafe { write_bytes(buf.as_mut_ptr(), 0, 32) };
        bpf_for!(it, i, 0, chunks, {
            set_err(bpf_dynptr_write(dp(&ptr_buf), (i as u32 * len) as u64, buf.as_mut_ptr() as *mut c_void, len as u64, 0) as i32);
            if get_err() != 0 {
                unsafe { bpf_iter_num_destroy(it.as_mut_ptr()) };
                break 'out;
            }
        });

        set_err(unsafe { bpf_dynptr_copy(dp(&ptr_buf), 0, dp(&ptr_xdp), 0, len * chunks as u32) });
        if get_err() != 0 {
            break 'out;
        }

        bpf_for!(it, i, 0, chunks, {
            unsafe { write_bytes(buf.as_mut_ptr(), 0, 32) };
            set_err(bpf_dynptr_read(buf.as_mut_ptr() as *mut c_void, len as u64, dp(&ptr_buf), (i as u32 * len) as u64, 0) as i32);
            if get_err() != 0 {
                unsafe { bpf_iter_num_destroy(it.as_mut_ptr()) };
                break 'out;
            }
            if bpf_memcmp(datap, buf.as_ptr(), len) != 0 {
                unsafe { bpf_iter_num_destroy(it.as_mut_ptr()) };
                break 'out;
            }
        });

        /* Both source and destination dynptrs are backed by non-contiguous memory */
        set_err(unsafe { bpf_dynptr_copy(dp(&ptr_xdp), 2, dp(&ptr_xdp), len, len * (chunks - 1) as u32) });
        if get_err() != 0 {
            break 'out;
        }

        bpf_for!(it, i, 0, chunks - 1, {
            unsafe { write_bytes(buf.as_mut_ptr(), 0, 32) };
            set_err(bpf_dynptr_read(buf.as_mut_ptr() as *mut c_void, len as u64, dp(&ptr_xdp), (2 + i as u32 * len) as u64, 0) as i32);
            if get_err() != 0 {
                unsafe { bpf_iter_num_destroy(it.as_mut_ptr()) };
                break 'out;
            }
            if bpf_memcmp(datap, buf.as_ptr(), len) != 0 {
                unsafe { bpf_iter_num_destroy(it.as_mut_ptr()) };
                break 'out;
            }
        });

        if unsafe { bpf_dynptr_copy(dp(&ptr_xdp), xdp_data_size.wrapping_sub(3000), dp(&ptr_xdp), 0, len * chunks as u32) } != -E2BIG {
            set_err(1);
        }
    }

    bpf_ringbuf_discard_dynptr(dpv(&ptr_buf), 0);
    XDP_DROP
}

#[no_mangle]
static mut memset_zero_data: [u8; 18] = *b"data to be zeroed\0";

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_dynptr_memset_zero(_ctx: *mut c_void) -> i32 {
    let data_sz: u32 = 18;
    let zeroes = [0u8; 32];
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    set_err(bpf_dynptr_from_mem(addr_of_mut!(memset_zero_data) as *mut c_void, data_sz as u64, 0, dpv(&ptr)) as i32);
    if get_err() == 0 {
        set_err(unsafe { bpf_dynptr_memset(dp(&ptr), 0, data_sz, 0) });
    }
    if get_err() == 0 {
        set_err(bpf_memcmp(zeroes.as_ptr(), addr_of!(memset_zero_data) as *const u8, data_sz));
    }

    0
}

#[no_mangle]
static mut memset_notzero_data: [u8; 23] = *b"data to be overwritten\0";

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_dynptr_memset_notzero(_ctx: *mut c_void) -> i32 {
    let data_sz: u32 = 23;
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut expected = MaybeUninit::<[u8; 32]>::uninit();

    unsafe { write_bytes(expected.as_mut_ptr() as *mut u8, DYNPTR_MEMSET_VAL, data_sz as usize) };

    set_err(bpf_dynptr_from_mem(addr_of_mut!(memset_notzero_data) as *mut c_void, data_sz as u64, 0, dpv(&ptr)) as i32);
    if get_err() == 0 {
        set_err(unsafe { bpf_dynptr_memset(dp(&ptr), 0, data_sz, DYNPTR_MEMSET_VAL) });
    }
    if get_err() == 0 {
        set_err(bpf_memcmp(expected.as_ptr() as *const u8, addr_of!(memset_notzero_data) as *const u8, data_sz));
    }

    0
}

#[no_mangle]
static mut memset_zero_offset_data: [u8; 28] = *b"data to be zeroed partially\0";

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_dynptr_memset_zero_offset(_ctx: *mut c_void) -> i32 {
    /* char expected[] = "data to \0\0\0\0eroed partially"; (28 bytes) */
    let mut expected = [0u64; 4];
    expected[0] = 0x206f742061746164;
    expected[1] = 0x656f726500000000;
    expected[2] = 0x6169747261702064;
    expected[3] = 0x796c6c;
    let data_sz: u32 = 28;
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    set_err(bpf_dynptr_from_mem(addr_of_mut!(memset_zero_offset_data) as *mut c_void, data_sz as u64, 0, dpv(&ptr)) as i32);
    if get_err() == 0 {
        set_err(unsafe { bpf_dynptr_memset(dp(&ptr), 8, 4, 0) });
    }
    if get_err() == 0 {
        set_err(bpf_memcmp(expected.as_ptr() as *const u8, addr_of!(memset_zero_offset_data) as *const u8, data_sz));
    }

    0
}

#[no_mangle]
static mut memset_zero_adjusted_data: [u8; 28] = *b"data to be zeroed partially\0";

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_dynptr_memset_zero_adjusted(_ctx: *mut c_void) -> i32 {
    /* char expected[] = "data\0\0\0\0be zeroed partially"; (28 bytes) */
    let mut expected = [0u64; 4];
    expected[0] = 0x61746164;
    expected[1] = 0x656f72657a206562;
    expected[2] = 0x6169747261702064;
    expected[3] = 0x796c6c;
    let data_sz: u32 = 28;
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    set_err(bpf_dynptr_from_mem(addr_of_mut!(memset_zero_adjusted_data) as *mut c_void, data_sz as u64, 0, dpv(&ptr)) as i32);
    if get_err() == 0 {
        set_err(unsafe { bpf_dynptr_adjust(dp(&ptr), 4, 8) });
    }
    if get_err() == 0 {
        let size = unsafe { bpf_dynptr_size(dp(&ptr)) };
        set_err(unsafe { bpf_dynptr_memset(dp(&ptr), 0, size, 0) });
    }
    if get_err() == 0 {
        set_err(bpf_memcmp(expected.as_ptr() as *const u8, addr_of!(memset_zero_adjusted_data) as *const u8, data_sz));
    }

    0
}

#[no_mangle]
static mut memset_overflow_data: [u8; 21] = *b"memset overflow data\0";

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_dynptr_memset_overflow(_ctx: *mut c_void) -> i32 {
    let data_sz: u32 = 21;
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    set_err(bpf_dynptr_from_mem(addr_of_mut!(memset_overflow_data) as *mut c_void, data_sz as u64, 0, dpv(&ptr)) as i32);
    let ret = unsafe { bpf_dynptr_memset(dp(&ptr), 0, data_sz + 1, 0) };
    if ret != -E2BIG {
        set_err(1);
    }

    0
}

#[link_section = "?tp/syscalls/sys_enter_nanosleep"]
#[no_mangle]
extern "C" fn test_dynptr_memset_overflow_offset(_ctx: *mut c_void) -> i32 {
    let data_sz: u32 = 21;
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    set_err(bpf_dynptr_from_mem(addr_of_mut!(memset_overflow_data) as *mut c_void, data_sz as u64, 0, dpv(&ptr)) as i32);
    let ret = unsafe { bpf_dynptr_memset(dp(&ptr), 1, data_sz, 0) };
    if ret != -E2BIG {
        set_err(1);
    }

    0
}

#[link_section = "?cgroup_skb/egress"]
#[no_mangle]
extern "C" fn test_dynptr_memset_readonly(skb: *mut __sk_buff) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    set_err(unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, dp(&ptr) as *mut bpf_dynptr) });

    /* cgroup skbs are read only, memset should fail */
    let size = unsafe { bpf_dynptr_size(dp(&ptr)) };
    let ret = unsafe { bpf_dynptr_memset(dp(&ptr), 0, size, 0) };
    if ret != -EINVAL {
        set_err(1);
    }

    0
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn test_dynptr_memset_xdp_chunks(xdp: *mut xdp_md) -> i32 {
    let max_chunks: i32 = 200;
    let ptr_xdp = MaybeUninit::<bpf_dynptr>::uninit();
    let mut expected_buf = MaybeUninit::<[u8; 32]>::uninit();
    let mut buf = MaybeUninit::<[u8; 32]>::uninit();

    unsafe { write_bytes(expected_buf.as_mut_ptr() as *mut u8, DYNPTR_MEMSET_VAL, 32) };

    /* ptr_xdp is backed by non-contiguous memory */
    unsafe {
        bpf_dynptr_from_xdp(xdp, 0, dp(&ptr_xdp) as *mut bpf_dynptr);
    }
    let data_sz = unsafe { bpf_dynptr_size(dp(&ptr_xdp)) };

    'out: {
        set_err(unsafe { bpf_dynptr_memset(dp(&ptr_xdp), 0, data_sz, DYNPTR_MEMSET_VAL) });
        if get_err() != 0 {
            /* bpf_dynptr_memset() eventually called bpf_xdp_pointer()
             * where if data_sz is greater than 0xffff, -EFAULT will be
             * returned. For 64K page size, data_sz is greater than
             * 64K, so error is expected and let us zero out error and
             * return success.
             */
            if data_sz >= PAGE_SIZE_64K {
                set_err(0);
            }
            break 'out;
        }

        bpf_for!(it, i, 0, max_chunks, {
            let offset: u32 = i as u32 * 32;
            if offset >= data_sz {
                unsafe { bpf_iter_num_destroy(it.as_mut_ptr()) };
                break 'out;
            }
            let chunk_sz: u32 = if 32 < data_sz - offset { 32 } else { data_sz - offset };
            set_err(bpf_dynptr_read(buf.as_mut_ptr() as *mut c_void, chunk_sz as u64, dp(&ptr_xdp), offset as u64, 0) as i32);
            if get_err() != 0 {
                unsafe { bpf_iter_num_destroy(it.as_mut_ptr()) };
                break 'out;
            }
            set_err(bpf_memcmp(buf.as_ptr() as *const u8, expected_buf.as_ptr() as *const u8, 32));
            if get_err() != 0 {
                unsafe { bpf_iter_num_destroy(it.as_mut_ptr()) };
                break 'out;
            }
        });
    }
    XDP_DROP
}

#[no_mangle]
static mut user_ptr: *mut c_void = core::ptr::null_mut();
/* Contains the copy of the data pointed by user_ptr.
 * Size 384 to make it not fit into a single kernel chunk when copying
 * but less than the maximum bpf stack size (512).
 */
#[no_mangle]
static mut expected_str: [u8; 384] = [0; 384];
#[no_mangle]
static mut test_len: [u32; 7] = [0 /* placeholder */, 0, 1, 2, 255, 256, 257];

/* Returns the offset just before the end of the maximum sized xdp fragment.
 * Any write larger than 32 bytes will be split between 2 fragments.
 */
#[no_mangle]
extern "C" fn xdp_near_frag_end_offset() -> u32 {
    let headroom: u32 = 256;
    /* __PAGE_SIZE - headroom - sizeof(struct skb_shared_info) */
    let max_frag_size: u32 = 4096 - headroom - 320;

    /* 32 bytes before the approximate end of the fragment */
    max_frag_size - 32
}

#[inline(always)]
fn test_len_at(i: i32) -> u32 {
    unsafe { *(addr_of!(test_len) as *const u32).add(i as usize) }
}

#[inline(always)]
fn expected_str_ptr() -> *const u8 {
    addr_of!(expected_str) as *const u8
}

/* Use __always_inline on test_dynptr_probe[_str][_xdp]() and callbacks
 * of type bpf_read_dynptr_fn_t to prevent compiler from generating
 * indirect calls that make program fail to load with "unknown opcode" error.
 */
#[inline(always)]
fn test_dynptr_probe(ptr: *const c_void, read_fn: impl Fn(*const bpf_dynptr, u64, u64, *const c_void) -> i32) {
    let mut buf = MaybeUninit::<[u8; 384]>::uninit();
    let ptr_buf = MaybeUninit::<bpf_dynptr>::uninit();

    if !current_pid_matches() {
        return;
    }

    set_err(bpf_ringbuf_reserve_dynptr(&ringbuf, 384, 0, dpv(&ptr_buf)) as i32);

    bpf_for!(it, i, 0, 7, {
        let len = test_len_at(i);

        if get_err() == 0 {
            set_err(read_fn(dp(&ptr_buf), 0, test_len_at(i) as u64, ptr));
        }
        if len > 384 {
            break;
        }
        if get_err() == 0 {
            set_err(bpf_dynptr_read(buf.as_mut_ptr() as *mut c_void, len as u64, dp(&ptr_buf), 0, 0) as i32);
        }

        if get_err() != 0 || bpf_memcmp(expected_str_ptr(), buf.as_ptr() as *const u8, len) != 0 {
            set_err(1);
        }

        /* Reset buffer and dynptr */
        unsafe { write_bytes(buf.as_mut_ptr() as *mut u8, 0, 384) };
        if get_err() == 0 {
            set_err(bpf_dynptr_write(dp(&ptr_buf), 0, buf.as_mut_ptr() as *mut c_void, len as u64, 0) as i32);
        }
    });
    bpf_ringbuf_discard_dynptr(dpv(&ptr_buf), 0);
}

#[inline(always)]
fn test_dynptr_probe_str(ptr: *const c_void, read_fn: impl Fn(*const bpf_dynptr, u64, u64, *const c_void) -> i32) {
    let mut buf = MaybeUninit::<[u8; 384]>::uninit();
    let ptr_buf = MaybeUninit::<bpf_dynptr>::uninit();

    if !current_pid_matches() {
        return;
    }

    bpf_ringbuf_reserve_dynptr(&ringbuf, 384, 0, dpv(&ptr_buf));

    bpf_for!(it, i, 0, 7, {
        let len = test_len_at(i);

        let cnt = read_fn(dp(&ptr_buf), 0, len as u64, ptr) as u32;
        if cnt != len {
            set_err(1);
        }

        if len > 384 {
            continue;
        }
        if get_err() == 0 {
            set_err(bpf_dynptr_read(buf.as_mut_ptr() as *mut c_void, len as u64, dp(&ptr_buf), 0, 0) as i32);
        }
        if len == 0 {
            continue;
        }
        if get_err() != 0
            || bpf_memcmp(expected_str_ptr(), buf.as_ptr() as *const u8, len - 1) != 0
            || unsafe { *(buf.as_ptr() as *const u8).add((len - 1) as usize) } != 0
        {
            set_err(1);
        }
    });
    bpf_ringbuf_discard_dynptr(dpv(&ptr_buf), 0);
}

#[inline(always)]
fn test_dynptr_probe_xdp(
    xdp: *mut xdp_md,
    ptr: *const c_void,
    read_fn: impl Fn(*const bpf_dynptr, u64, u64, *const c_void) -> i32,
) {
    let ptr_xdp = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buf = MaybeUninit::<[u8; 384]>::uninit();

    if !current_pid_matches() {
        return;
    }

    let off = xdp_near_frag_end_offset();
    set_err(unsafe { bpf_dynptr_from_xdp(xdp, 0, dp(&ptr_xdp) as *mut bpf_dynptr) });

    bpf_for!(it, i, 0, 7, {
        let len = test_len_at(i);

        if get_err() == 0 {
            set_err(read_fn(dp(&ptr_xdp), off as u64, len as u64, ptr));
        }
        if len > 384 {
            continue;
        }
        if get_err() == 0 {
            set_err(bpf_dynptr_read(buf.as_mut_ptr() as *mut c_void, len as u64, dp(&ptr_xdp), off as u64, 0) as i32);
        }
        if get_err() != 0 || bpf_memcmp(expected_str_ptr(), buf.as_ptr() as *const u8, len) != 0 {
            set_err(1);
        }
        /* Reset buffer and dynptr */
        unsafe { write_bytes(buf.as_mut_ptr() as *mut u8, 0, 384) };
        if get_err() == 0 {
            set_err(bpf_dynptr_write(dp(&ptr_xdp), off as u64, buf.as_mut_ptr() as *mut c_void, len as u64, 0) as i32);
        }
    });
}

#[inline(always)]
fn test_dynptr_probe_str_xdp(
    xdp: *mut xdp_md,
    ptr: *const c_void,
    read_fn: impl Fn(*const bpf_dynptr, u64, u64, *const c_void) -> i32,
) {
    let ptr_xdp = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buf = MaybeUninit::<[u8; 384]>::uninit();

    if !current_pid_matches() {
        return;
    }

    let off = xdp_near_frag_end_offset();
    set_err(unsafe { bpf_dynptr_from_xdp(xdp, 0, dp(&ptr_xdp) as *mut bpf_dynptr) });
    if get_err() != 0 {
        return;
    }

    bpf_for!(it, i, 0, 7, {
        let len = test_len_at(i);

        let cnt = read_fn(dp(&ptr_xdp), off as u64, len as u64, ptr) as u32;
        if cnt != len {
            set_err(1);
        }

        if len > 384 {
            continue;
        }
        if get_err() == 0 {
            set_err(bpf_dynptr_read(buf.as_mut_ptr() as *mut c_void, len as u64, dp(&ptr_xdp), off as u64, 0) as i32);
        }

        if len == 0 {
            continue;
        }
        if get_err() != 0
            || bpf_memcmp(expected_str_ptr(), buf.as_ptr() as *const u8, len - 1) != 0
            || unsafe { *(buf.as_ptr() as *const u8).add((len - 1) as usize) } != 0
        {
            set_err(1);
        }

        unsafe { write_bytes(buf.as_mut_ptr() as *mut u8, 0, 384) };
        if get_err() == 0 {
            set_err(bpf_dynptr_write(dp(&ptr_xdp), off as u64, buf.as_mut_ptr() as *mut c_void, len as u64, 0) as i32);
        }
    });
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn test_probe_read_user_dynptr(xdp: *mut xdp_md) -> i32 {
    let f = |d: *const bpf_dynptr, off: u64, size: u64, p: *const c_void| unsafe {
        bpf_probe_read_user_dynptr(d, off as u32, size as u32, p)
    };
    test_dynptr_probe(unsafe { user_ptr }, f);
    if get_err() == 0 {
        test_dynptr_probe_xdp(xdp, unsafe { user_ptr }, f);
    }
    XDP_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn test_probe_read_kernel_dynptr(xdp: *mut xdp_md) -> i32 {
    let f = |d: *const bpf_dynptr, off: u64, size: u64, p: *const c_void| unsafe {
        bpf_probe_read_kernel_dynptr(d, off as u32, size as u32, p)
    };
    test_dynptr_probe(expected_str_ptr() as *const c_void, f);
    if get_err() == 0 {
        test_dynptr_probe_xdp(xdp, expected_str_ptr() as *const c_void, f);
    }
    XDP_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn test_probe_read_user_str_dynptr(xdp: *mut xdp_md) -> i32 {
    let f = |d: *const bpf_dynptr, off: u64, size: u64, p: *const c_void| unsafe {
        bpf_probe_read_user_str_dynptr(d, off as u32, size as u32, p)
    };
    test_dynptr_probe_str(unsafe { user_ptr }, f);
    if get_err() == 0 {
        test_dynptr_probe_str_xdp(xdp, unsafe { user_ptr }, f);
    }
    XDP_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn test_probe_read_kernel_str_dynptr(xdp: *mut xdp_md) -> i32 {
    let f = |d: *const bpf_dynptr, off: u64, size: u64, p: *const c_void| unsafe {
        bpf_probe_read_kernel_str_dynptr(d, off as u32, size as u32, p)
    };
    test_dynptr_probe_str(expected_str_ptr() as *const c_void, f);
    if get_err() == 0 {
        test_dynptr_probe_str_xdp(xdp, expected_str_ptr() as *const c_void, f);
    }
    XDP_PASS
}

#[link_section = "fentry.s/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn test_copy_from_user_dynptr(_ctx: *mut c_void) -> i32 {
    test_dynptr_probe(unsafe { user_ptr }, |d, off, size, p| unsafe {
        bpf_copy_from_user_dynptr(d, off as u32, size as u32, p)
    });
    0
}

#[link_section = "fentry.s/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn test_copy_from_user_str_dynptr(_ctx: *mut c_void) -> i32 {
    test_dynptr_probe_str(unsafe { user_ptr }, |d, off, size, p| unsafe {
        bpf_copy_from_user_str_dynptr(d, off as u32, size as u32, p)
    });
    0
}

#[inline(always)]
fn bpf_copy_data_from_user_task(dptr: *const bpf_dynptr, off: u64, size: u64, unsafe_ptr: *const c_void) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();

    unsafe { bpf_copy_from_user_task_dynptr(dptr, off as u32, size as u32, unsafe_ptr, task) }
}

#[inline(always)]
fn bpf_copy_data_from_user_task_str(dptr: *const bpf_dynptr, off: u64, size: u64, unsafe_ptr: *const c_void) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();

    unsafe { bpf_copy_from_user_task_str_dynptr(dptr, off as u32, size as u32, unsafe_ptr, task) }
}

#[link_section = "fentry.s/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn test_copy_from_user_task_dynptr(_ctx: *mut c_void) -> i32 {
    test_dynptr_probe(unsafe { user_ptr }, bpf_copy_data_from_user_task);
    0
}

#[link_section = "fentry.s/__x64_sys_nanosleep"]
#[no_mangle]
extern "C" fn test_copy_from_user_task_str_dynptr(_ctx: *mut c_void) -> i32 {
    test_dynptr_probe_str(unsafe { user_ptr }, bpf_copy_data_from_user_task_str);
    0
}

bpf_object!("GPL");
