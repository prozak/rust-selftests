// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/dynptr_fail.c
// (bpf-rs-core idiom): the verifier's rejections of misused dynptrs --
// unreleased ring-buffer reservations, use after release or
// invalidation, dynptrs in maps, out-of-bounds or unchecked data slices,
// raw reads and writes of the dynptr stack slots, dynptrs at an offset,
// double release, from_mem on the wrong memory, slice writes to read-only
// packet data, slices invalidated by packet-changing helpers, cloning
// rules and subprogram boundaries -- plus the seven programs the
// verifier must accept (prog_tests/dynptr.c runs every program through
// test_loader). The types, kfunc externs and MaybeUninit accessors are
// those of dynptr_success.rs; raw reads of a dynptr slot are
// read_volatile and raw writes write_volatile so LLVM cannot fold them
// (the expected message depends on the access existing). The five
// hand-written asm programs of the C are BPF_NAKED copies of the C
// object's instruction sequence (scripts/naked_verbatim.py checks them).
// The test_loader decl tags are declared with test_tags!
// (scripts/btf_test_tags.py).

// BTF_C_CHAR: u8
// BTF_C_VOID: c_void

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{addr_of_mut, read_volatile, write_volatile};

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_dynptr_data, bpf_dynptr_from_mem, bpf_dynptr_read, bpf_loop, bpf_map_lookup_elem,
    bpf_map_update_elem, bpf_ringbuf_discard_dynptr, bpf_ringbuf_reserve_dynptr,
    bpf_ringbuf_submit, bpf_ringbuf_submit_dynptr, bpf_strncmp, sink,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::test_tags;
use bpf_rs_core::{bpf_map, bpf_object};

const ENOENT: i32 = 2;
const SK_DROP: i32 = 0;
const SK_PASS: i32 = 1;

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct test_info {
    x: i32,
    ptr: bpf_dynptr,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct sample {
    pid: i32,
    _pad: [u8; 4],
    value: i64,
    comm: [u8; 16],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[link_section = ".maps"]
#[no_mangle]
static array_map1: BpfMap<u32, bpf_dynptr, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static array_map2: BpfMap<u32, test_info, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static array_map3: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static array_map4: BpfMap<u32, u64, { maps::ARRAY }, 1> = BpfMap::new();

bpf_map! {
    ringbuf {
        r#type: *const [i32; maps::RINGBUF],
        max_entries: *const [i32; 4096],
    }
}

#[no_mangle]
static mut err: i32 = 0;
#[no_mangle]
static mut val: i32 = 0;

extern "C" {
    fn bpf_dynptr_from_skb(skb: *mut c_void, flags: u64, ptr__uninit: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_from_skb_meta(skb: *mut c_void, flags: u64, ptr__uninit: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_slice_rdwr(
        ptr: *const bpf_dynptr,
        offset: u32,
        buffer__opt: *mut c_void,
        buffer__szk: u32,
    ) -> *mut c_void;
}

#[inline(always)]
fn dp(p: &MaybeUninit<bpf_dynptr>) -> *const bpf_dynptr {
    p.as_ptr()
}

#[inline(always)]
fn dpv(p: &MaybeUninit<bpf_dynptr>) -> *mut c_void {
    p.as_ptr() as *mut c_void
}

#[inline(always)]
fn dpm(p: &MaybeUninit<bpf_dynptr>) -> *mut bpf_dynptr {
    p.as_ptr() as *mut bpf_dynptr
}

#[inline(always)]
fn set_val(v: i32) {
    unsafe {
        val = v;
    }
}

#[inline(always)]
fn get_map_val_dynptr(ptr: *mut bpf_dynptr) -> i32 {
    let key: u32 = 0;

    bpf_map_update_elem(&array_map3, &key, unsafe { &*addr_of_mut!(val) }, 0);

    let map_val = bpf_map_lookup_elem(&array_map3, &key) as *mut u32;
    if map_val.is_null() {
        return -ENOENT;
    }

    bpf_dynptr_from_mem(map_val as *mut c_void, 4, 0, ptr as *mut c_void);

    0
}

test_tags! {
    ringbuf_missing_release1: __failure, __msg("Unreleased reference id=1");
    ringbuf_missing_release2: __failure, __msg("Unreleased reference id=3");
    ringbuf_missing_release_callback: __failure, __msg("cannot overwrite referenced dynptr");
    ringbuf_release_uninit_dynptr: __failure, __msg("Expected an initialized dynptr as R1");
    use_after_invalid: __failure, __msg("Expected an initialized dynptr as R3");
    ringbuf_invalid_api: __failure, __msg("type=mem expected=ringbuf_mem");
    add_dynptr_to_map1: __failure, __msg("invalid read from stack");
    add_dynptr_to_map2: __failure, __msg("invalid read from stack");
    data_slice_out_of_bounds_ringbuf: __failure, __msg("value is outside of the allowed memory range");
    data_slice_out_of_bounds_skb: __failure, __msg("value is outside of the allowed memory range");
    data_slice_out_of_bounds_skb_meta: __failure, __msg("value is outside of the allowed memory range");
    data_slice_out_of_bounds_map_value: __failure, __msg("value is outside of the allowed memory range");
    data_slice_use_after_release1: __failure, __msg("invalid mem access 'scalar'");
    data_slice_use_after_release2: __failure, __msg("invalid mem access 'scalar'");
    data_slice_missing_null_check1: __failure, __msg("invalid mem access 'mem_or_null'");
    data_slice_missing_null_check2: __failure, __msg("invalid mem access 'mem_or_null'");
    invalid_helper1: __failure, __msg("invalid read from stack");
    invalid_helper2: __failure, __msg("cannot pass in dynptr at an offset=-8");
    invalid_write1: __failure, __msg("Expected an initialized dynptr as R1");
    invalid_write2: __failure, __msg("cannot overwrite referenced dynptr");
    invalid_write3: __failure, __msg("cannot overwrite referenced dynptr");
    invalid_write4: __failure, __msg("cannot overwrite referenced dynptr");
    global: __failure, __msg("type=map_value expected=fp");
    invalid_read1: __failure, __msg("invalid read from stack"), __msg("Verification failed: Memory Safety: Direct read of dynptr stack state"), __msg("verifier-managed dynptr state"), __msg("Use dynptr helpers or kfuncs");
    invalid_read2: __failure, __msg("cannot pass in dynptr at an offset");
    invalid_read3: __failure, __msg("invalid read from stack");
    invalid_read4: __failure, __msg("invalid read from stack");
    invalid_offset: __failure, __msg("cannot pass in dynptr at an offset=0");
    release_twice: __failure, __msg("Expected an initialized dynptr as R1");
    release_twice_callback: __failure, __msg("Expected an initialized dynptr as R1");
    dynptr_from_mem_invalid_api: __failure, __msg("Unsupported reg type fp for bpf_dynptr_from_mem data");
    dynptr_from_dynptr_data: __failure, __msg("Unsupported reg type mem for bpf_dynptr_from_mem data");
    dynptr_from_dynptr_slice: __failure, __msg("Unsupported reg type mem for bpf_dynptr_from_mem data");
}

/* Every bpf_ringbuf_reserve_dynptr call must have a corresponding
 * bpf_ringbuf_submit/discard_dynptr call
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn ringbuf_missing_release1(_ctx: *mut c_void) -> i32 {
    let mut ptr = bpf_dynptr { __opaque: [0, 0] };

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, addr_of_mut!(ptr) as *mut c_void);

    /* missing a call to bpf_ringbuf_discard/submit_dynptr */

    0
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn ringbuf_missing_release2(_ctx: *mut c_void) -> i32 {
    let ptr1 = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr2 = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 32, 0, dpv(&ptr1));
    bpf_ringbuf_reserve_dynptr(&ringbuf, 32, 0, dpv(&ptr2));

    let sample = bpf_dynptr_data(dpv(&ptr1), 0, 32) as *mut sample;
    if sample.is_null() {
        bpf_ringbuf_discard_dynptr(dpv(&ptr1), 0);
        bpf_ringbuf_discard_dynptr(dpv(&ptr2), 0);
        return 0;
    }

    bpf_ringbuf_submit_dynptr(dpv(&ptr1), 0);

    /* missing a call to bpf_ringbuf_discard/submit_dynptr on ptr2 */

    0
}

#[export_name = "missing_release_callback_fn"]
extern "C" fn missing_release_callback_fn(_index: u64, _data: *mut c_void) -> i64 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));

    /* missing a call to bpf_ringbuf_discard/submit_dynptr */

    0
}

/* A callback cannot return with the last dynptr for a referenced resource. */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn ringbuf_missing_release_callback(_ctx: *mut c_void) -> i32 {
    bpf_loop(10, missing_release_callback_fn, core::ptr::null_mut::<c_void>(), 0);
    0
}

/* Can't call bpf_ringbuf_submit/discard_dynptr on a non-initialized dynptr */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn ringbuf_release_uninit_dynptr(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    /* this should fail */
    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);

    0
}

/* A dynptr can't be used after it has been invalidated */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn use_after_invalid(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut read_data = MaybeUninit::<[u8; 64]>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&ptr));

    bpf_dynptr_read(read_data.as_mut_ptr() as *mut c_void, 64, dp(&ptr), 0, 0);

    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);

    /* this should fail */
    bpf_dynptr_read(read_data.as_mut_ptr() as *mut c_void, 64, dp(&ptr), 0, 0);

    0
}

/* Can't call non-dynptr ringbuf APIs on a dynptr ringbuf sample */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn ringbuf_invalid_api(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 32, 0, dpv(&ptr));
    let sample = bpf_dynptr_data(dpv(&ptr), 0, 32) as *mut sample;
    'done: {
        if sample.is_null() {
            break 'done;
        }

        unsafe {
            (*sample).pid = 123;
        }

        /* invalid API use. need to use dynptr API to submit/discard */
        bpf_ringbuf_submit(sample as *mut c_void, 0);
    }

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);
    0
}

/* Can't add a dynptr to a map */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn add_dynptr_to_map1(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let key: i32 = 0;

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));

    /* this should fail */
    bpf_map_update_elem(&array_map1, &key, &ptr, 0);

    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);

    0
}

/* Can't add a struct with an embedded dynptr to a map */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn add_dynptr_to_map2(_ctx: *mut c_void) -> i32 {
    let mut x = MaybeUninit::<test_info>::uninit();
    let key: i32 = 0;
    let xptr = unsafe { addr_of_mut!((*x.as_mut_ptr()).ptr) } as *mut c_void;

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, xptr);

    /* this should fail */
    bpf_map_update_elem(&array_map2, &key, &x, 0);

    bpf_ringbuf_submit_dynptr(xptr, 0);

    0
}

/* A data slice can't be accessed out of bounds */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn data_slice_out_of_bounds_ringbuf(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 8, 0, dpv(&ptr));

    let data = bpf_dynptr_data(dpv(&ptr), 0, 8);
    if !data.is_null() {
        /* can't index out of bounds of the data slice */
        set_val(unsafe { *((data as *const u8).add(8)) } as i32);
    }

    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);
    0
}

/* A data slice can't be accessed out of bounds */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn data_slice_out_of_bounds_skb(skb: *mut __sk_buff) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buffer: [u8; 14] = [0; 14];

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&ptr));
    }

    let hdr = unsafe { bpf_dynptr_slice_rdwr(dp(&ptr), 0, buffer.as_mut_ptr() as *mut c_void, 14) }
        as *mut ethhdr;
    if hdr.is_null() {
        return SK_DROP;
    }

    /* this should fail */
    unsafe {
        *((hdr as *mut u8).add(14)) = 1;
    }

    SK_PASS
}

/* A metadata slice can't be accessed out of bounds */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn data_slice_out_of_bounds_skb_meta(skb: *mut __sk_buff) -> i32 {
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dpm(&meta));
    }

    let md = unsafe { bpf_dynptr_slice_rdwr(dp(&meta), 0, core::ptr::null_mut(), 1) } as *mut u8;
    if md.is_null() {
        return SK_DROP;
    }

    /* this should fail */
    unsafe {
        *(md.add(1)) = 42;
    }

    SK_PASS
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn data_slice_out_of_bounds_map_value(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    get_map_val_dynptr(dpm(&ptr));

    let data = bpf_dynptr_data(dpv(&ptr), 0, 4);
    if data.is_null() {
        return 0;
    }

    /* can't index out of bounds of the data slice */
    set_val(unsafe { *((data as *const u8).add(4 + 1)) } as i32);

    0
}

/* A data slice can't be used after it has been released */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn data_slice_use_after_release1(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 32, 0, dpv(&ptr));
    let sample = bpf_dynptr_data(dpv(&ptr), 0, 32) as *mut sample;
    if sample.is_null() {
        bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);
        return 0;
    }

    unsafe {
        (*sample).pid = 123;
    }

    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);

    /* this should fail */
    set_val(unsafe { (*sample).pid });

    0
}

/* A data slice can't be used after it has been released.
 *
 * This tests the case where the data slice tracks a dynptr (ptr2)
 * that is at a non-zero offset from the frame pointer (ptr1 is at fp,
 * ptr2 is at fp - 16).
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn data_slice_use_after_release2(_ctx: *mut c_void) -> i32 {
    let ptr1 = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr2 = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&ptr1));
    bpf_ringbuf_reserve_dynptr(&ringbuf, 32, 0, dpv(&ptr2));

    let sample = bpf_dynptr_data(dpv(&ptr2), 0, 32) as *mut sample;
    if sample.is_null() {
        bpf_ringbuf_discard_dynptr(dpv(&ptr2), 0);
        bpf_ringbuf_discard_dynptr(dpv(&ptr1), 0);
        return 0;
    }

    unsafe {
        (*sample).pid = 23;
    }

    bpf_ringbuf_submit_dynptr(dpv(&ptr2), 0);

    /* this should fail */
    unsafe {
        (*sample).pid = 23;
    }

    bpf_ringbuf_submit_dynptr(dpv(&ptr1), 0);

    0
}

/* A data slice must be first checked for NULL */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn data_slice_missing_null_check1(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 8, 0, dpv(&ptr));

    let data = bpf_dynptr_data(dpv(&ptr), 0, 8);

    /* missing if (!data) check */

    /* this should fail */
    unsafe {
        *(data as *mut u8) = 3;
    }

    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);
    0
}

/* A data slice can't be dereferenced if it wasn't checked for null */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn data_slice_missing_null_check2(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 16, 0, dpv(&ptr));

    let data1 = bpf_dynptr_data(dpv(&ptr), 0, 8) as *mut u64;
    let data2 = bpf_dynptr_data(dpv(&ptr), 0, 8) as *mut u64;
    if !data1.is_null() {
        /* this should fail */
        unsafe {
            *data2 = 3;
        }
    }

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);
    0
}

#[link_section = ".rodata.str1.1"]
static STR_HELLO: [u8; 7] = *b"hello!\0";

/* Can't pass in a dynptr as an arg to a helper function that doesn't take in a
 * dynptr argument
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn invalid_helper1(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    get_map_val_dynptr(dpm(&ptr));

    /* this should fail */
    bpf_strncmp(dpv(&ptr) as *const c_void, 16, STR_HELLO.as_ptr() as *const c_void);

    0
}

/* A dynptr can't be passed into a helper function at a non-zero offset */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn invalid_helper2(_ctx: *mut c_void) -> i32 {
    /* the C's frame: ptr at fp-16 (topmost), read_data below it; rustc
     * places the last-declared local highest, so read_data comes first:
     * the `offset=-8` of the message is &ptr + 8 = fp-8 */
    let mut read_data = MaybeUninit::<[u8; 64]>::uninit();
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    get_map_val_dynptr(dpm(&ptr));

    /* this should fail */
    bpf_dynptr_read(
        read_data.as_mut_ptr() as *mut c_void,
        64,
        unsafe { (dpv(&ptr) as *const u8).add(8) },
        0,
        0,
    );
    0
}

/* A bpf_dynptr is invalidated if it's been written into */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn invalid_write1(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let x: u8 = 0;

    get_map_val_dynptr(dpm(&ptr));

    /* C: memcpy(&ptr, &x, sizeof(x)); */
    unsafe {
        write_volatile(dpv(&ptr) as *mut u8, x);
    }

    /* this should fail */
    let mut data = bpf_dynptr_data(dpv(&ptr), 0, 1);
    sink(&mut data);

    0
}

/*
 * A bpf_dynptr can't be used as a dynptr if it has been written into at a fixed
 * offset
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn invalid_write2(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut read_data = MaybeUninit::<[u8; 64]>::uninit();
    let x: u8 = 0;

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&ptr));

    /* C: memcpy((void *)&ptr + 8, &x, sizeof(x)); */
    unsafe {
        write_volatile((dpv(&ptr) as *mut u8).add(8), x);
    }

    /* this should fail */
    bpf_dynptr_read(read_data.as_mut_ptr() as *mut c_void, 64, dp(&ptr), 0, 0);

    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);

    0
}

/*
 * A bpf_dynptr can't be used as a dynptr if it has been written into at a
 * non-const offset
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn invalid_write3(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let x: u8 = 0;

    bpf_ringbuf_reserve_dynptr(&ringbuf, 8, 0, dpv(&ptr));

    /* C: memcpy(stack_buf, &val, sizeof(val)); len = stack_buf[0] & 0xf; */
    let len = (unsafe { val } as u8 & 0xf) as usize;

    /* C: memcpy((void *)&ptr + len, &x, sizeof(x)); */
    unsafe {
        write_volatile((dpv(&ptr) as *mut u8).add(len), x);
    }

    /* this should fail */
    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);

    0
}

#[export_name = "invalid_write4_callback"]
extern "C" fn invalid_write4_callback(_index: u64, data: *mut u32) -> i64 {
    unsafe {
        *data = 123;
    }

    0
}

/* If the dynptr is written into in a callback function, it should
 * be invalidated as a dynptr
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn invalid_write4(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&ptr));

    bpf_loop(10, invalid_write4_callback, dpv(&ptr) as *mut u32, 0);

    /* this should fail */
    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);

    0
}

/* A globally-defined bpf_dynptr can't be used (it must reside as a stack frame) */
#[no_mangle]
static mut global_dynptr: bpf_dynptr = bpf_dynptr { __opaque: [0, 0] };

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn global(_ctx: *mut c_void) -> i32 {
    /* this should fail */
    bpf_ringbuf_reserve_dynptr(&ringbuf, 16, 0, addr_of_mut!(global_dynptr) as *mut c_void);

    bpf_ringbuf_discard_dynptr(addr_of_mut!(global_dynptr) as *mut c_void, 0);

    0
}

/* A direct read should fail */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn invalid_read1(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&ptr));

    /* this should fail */
    set_val(unsafe { read_volatile(dpv(&ptr) as *const i32) });

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);

    0
}

/* A direct read at an offset should fail */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn invalid_read2(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut read_data = MaybeUninit::<[u8; 64]>::uninit();

    get_map_val_dynptr(dpm(&ptr));

    /* this should fail */
    bpf_dynptr_read(
        read_data.as_mut_ptr() as *mut c_void,
        64,
        unsafe { (dpv(&ptr) as *const u8).add(1) },
        0,
        0,
    );

    0
}

/* A direct read at an offset into the lower stack slot should fail */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn invalid_read3(_ctx: *mut c_void) -> i32 {
    let ptr1 = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr2 = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 16, 0, dpv(&ptr1));
    bpf_ringbuf_reserve_dynptr(&ringbuf, 16, 0, dpv(&ptr2));

    /* this should fail */
    /* C: memcpy(&val, (void *)&ptr1 + 8, sizeof(val)); */
    set_val(unsafe { read_volatile((dpv(&ptr1) as *const u8).add(8) as *const i32) });

    bpf_ringbuf_discard_dynptr(dpv(&ptr1), 0);
    bpf_ringbuf_discard_dynptr(dpv(&ptr2), 0);

    0
}

#[export_name = "invalid_read4_callback"]
extern "C" fn invalid_read4_callback(_index: u64, data: *mut u32) -> i64 {
    /* this should fail */
    set_val(unsafe { *data } as i32);

    0
}

/* A direct read within a callback function should fail */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn invalid_read4(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&ptr));

    bpf_loop(10, invalid_read4_callback, dpv(&ptr) as *mut u32, 0);

    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);

    0
}

/* Initializing a dynptr on an offset should fail */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn invalid_offset(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    /* this should fail */
    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, unsafe { dpm(&ptr).add(1) } as *mut c_void);

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);

    0
}

/* Can't release a dynptr twice */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn release_twice(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 16, 0, dpv(&ptr));

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);

    /* this second release should fail */
    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);

    0
}

#[export_name = "release_twice_callback_fn"]
extern "C" fn release_twice_callback_fn(_index: u64, data: *mut bpf_dynptr) -> i64 {
    /* this should fail */
    bpf_ringbuf_discard_dynptr(data as *mut c_void, 0);

    0
}

/* Test that releasing a dynptr twice, where one of the releases happens
 * within a callback function, fails
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn release_twice_callback(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 32, 0, dpv(&ptr));

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);

    bpf_loop(10, release_twice_callback_fn, dpm(&ptr), 0);

    0
}

/* Reject unsupported local mem types for dynptr_from_mem API */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_from_mem_invalid_api(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut x: i32 = 0;

    /* this should fail */
    bpf_dynptr_from_mem(addr_of_mut!(x) as *mut c_void, 4, 0, dpv(&ptr));

    0
}

/* Cannot create dynptr from dynptr data */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_from_dynptr_data(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr2 = MaybeUninit::<bpf_dynptr>::uninit();

    if get_map_val_dynptr(dpm(&ptr)) != 0 {
        return 0;
    }

    let data = bpf_dynptr_data(dpv(&ptr), 0, 4);
    if data.is_null() {
        return 0;
    }

    /* this should fail */
    bpf_dynptr_from_mem(data, 4, 0, dpv(&ptr2));

    0
}

/* Cannot create dynptr from dynptr slice */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn dynptr_from_dynptr_slice(skb: *mut __sk_buff) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr2 = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buffer: [u8; 14] = [0; 14];

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&ptr));
    }

    let hdr = unsafe { bpf_dynptr_slice_rdwr(dp(&ptr), 0, buffer.as_mut_ptr() as *mut c_void, 14) }
        as *mut ethhdr;
    if hdr.is_null() {
        return SK_DROP;
    }

    /* this should fail */
    bpf_dynptr_from_mem(hdr as *mut c_void, 14, 0, dpv(&ptr2));

    SK_PASS
}

bpf_object!("GPL");
