// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

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

use core::arch::asm;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{addr_of_mut, read_volatile, write_volatile};

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_dynptr_data, bpf_dynptr_from_mem, bpf_dynptr_read, bpf_dynptr_write, bpf_get_current_comm,
    bpf_loop, bpf_map_lookup_elem, bpf_map_update_elem, bpf_ringbuf_discard_dynptr,
    bpf_get_current_task_btf, bpf_ringbuf_reserve_dynptr, bpf_ringbuf_submit,
    bpf_ringbuf_submit_dynptr, bpf_skb_pull_data, bpf_strncmp, bpf_this_cpu_ptr,
    bpf_xdp_adjust_head, sink,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg;
use bpf_rs_core::test_tags;
use bpf_rs_core::{bpf_map, bpf_object};

const ENOENT: i32 = 2;
const SK_DROP: i32 = 0;
const SK_PASS: i32 = 1;
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

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
    fn bpf_dynptr_from_xdp(xdp: *mut xdp_md, flags: u64, ptr__uninit: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_slice(
        ptr: *const bpf_dynptr,
        offset: u32,
        buffer__opt: *mut c_void,
        buffer__szk: u32,
    ) -> *mut c_void;
    fn bpf_dynptr_slice_rdwr(
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
    dynptr_pruning_overwrite: __failure, __msg("cannot overwrite referenced dynptr"), __log_level(2);
    dynptr_pruning_stacksafe: __success, __msg("12: safe"), __log_level(2);
    dynptr_pruning_type_confusion: __failure, __msg("cannot overwrite referenced dynptr"), __log_level(2);
    dynptr_var_off_overwrite: __failure, __msg("dynptr has to be at a constant offset"), __log_level(2);
    dynptr_partial_slot_invalidate: __failure, __msg("cannot overwrite referenced dynptr"), __log_level(2);
    dynptr_overwrite_unref: __success;
    dynptr_invalidate_slice_reinit: __failure, __msg("invalid mem access 'scalar'");
    dynptr_invalidate_slice_or_null: __failure, __msg("R{{[0-9]+}} type=scalar expected=percpu_ptr_");
    dynptr_invalidate_slice_failure: __failure, __msg("R{{[0-9]+}} invalid mem access 'scalar'");
    dynptr_invalidate_slice_success: __success;
    dynptr_overwrite_ref: __failure, __msg("cannot overwrite referenced dynptr");
    dynptr_read_into_slot: __failure, __msg("cannot overwrite referenced dynptr");
    skb_invalid_slice_write: __failure, __msg("R{{[0-9]+}} cannot write into rdonly_mem");
    skb_meta_invalid_slice_write: __failure, __msg("R{{[0-9]+}} cannot write into rdonly_mem");
    skb_invalid_data_slice1: __failure, __msg("invalid mem access 'scalar'");
    skb_invalid_data_slice2: __failure, __msg("invalid mem access 'scalar'");
    skb_invalid_data_slice3: __failure, __msg("invalid mem access 'scalar'");
    skb_invalid_data_slice4: __failure, __msg("invalid mem access 'scalar'");
    ro_skb_slice_invalid_after_metadata_write: __failure, __msg("invalid mem access 'scalar'");
    rw_skb_slice_invalid_after_metadata_write: __failure, __msg("invalid mem access 'scalar'");
    ro_skb_meta_slice_invalid_after_payload_write: __failure, __msg("invalid mem access 'scalar'");
    rw_skb_meta_slice_invalid_after_payload_write: __failure, __msg("invalid mem access 'scalar'");
    ro_skb_meta_slice_invalid_after_payload_helper: __failure, __msg("invalid mem access 'scalar'");
    rw_skb_meta_slice_invalid_after_payload_helper: __failure, __msg("invalid mem access 'scalar'");
    ro_skb_meta_slice_invalid_after_metadata_write: __failure, __msg("invalid mem access 'scalar'");
    rw_skb_meta_slice_invalid_after_metadata_write: __failure, __msg("invalid mem access 'scalar'");
    xdp_invalid_data_slice1: __failure, __msg("invalid mem access 'scalar'");
    xdp_invalid_data_slice2: __failure, __msg("invalid mem access 'scalar'");
    skb_invalid_ctx: __failure, __msg("calling kernel function bpf_dynptr_from_skb is not allowed");
    skb_meta_invalid_ctx: __failure, __msg("calling kernel function bpf_dynptr_from_skb_meta is not allowed");
    skb_invalid_ctx_fentry: __failure, __msg("must be referenced or trusted");
    skb_invalid_ctx_fexit: __failure, __msg("must be referenced or trusted");
    uninit_write_into_slot: __failure, __msg("cannot overwrite referenced dynptr");
    xdp_invalid_ctx: __failure, __msg("calling kernel function bpf_dynptr_from_xdp is not allowed");
    dynptr_slice_var_len1: __failure, __msg("must be a known constant"), __msg("requires this memory size to be a verifier-known constant");
    dynptr_slice_var_len2: __failure, __msg("must be a known constant"), __msg("requires this memory size to be a verifier-known constant");
    dynptr_slice_commuted_invalidate: __failure, __msg("invalid mem access 'scalar'");
    invalid_data_slices: __failure, __msg("invalid mem access 'scalar'");
    invalid_slice_rdwr_rdonly: __failure, __msg("the prog does not allow writes to packet data");
    dynptr_adjust_invalid: __failure, __msg("Expected an initialized dynptr as R1");
    dynptr_is_null_invalid: __failure, __msg("Expected an initialized dynptr as R1");
    dynptr_is_rdonly_invalid: __failure, __msg("Expected an initialized dynptr as R1");
    dynptr_size_invalid: __failure, __msg("Expected an initialized dynptr as R1");
    clone_invalid1: __failure, __msg("Expected an initialized dynptr as R1");
    clone_invalid2: __failure, __msg("cannot overwrite referenced dynptr");
    clone_invalidate1: __failure, __msg("Expected an initialized dynptr as R3");
    clone_invalidate2: __failure, __msg("Expected an initialized dynptr as R3");
    clone_invalidate3: __failure, __msg("Expected an initialized dynptr as R3");
    clone_invalidate4: __failure, __msg("invalid mem access 'scalar'");
    referenced_dynptr_lost_on_subprog_return: __failure, __msg("cannot overwrite referenced dynptr");
    caller_dynptr_slice_across_subprog_valid: __success;
    callee_dynptr_slice_invalid_after_return: __failure, __msg("invalid mem access 'scalar'");
    caller_dynptr_slice_release_after_subprog_invalid: __failure, __msg("invalid mem access 'scalar'");
    clone_invalidate5: __failure, __msg("invalid mem access 'scalar'");
    clone_invalidate6: __failure, __msg("invalid mem access 'scalar'");
    clone_skb_packet_data: __failure, __msg("invalid mem access 'scalar'");
    clone_skb_packet_meta: __failure, __msg("invalid mem access 'scalar'");
    clone_xdp_packet_data: __failure, __msg("invalid mem access 'scalar'");
    test_dynptr_skb_small_buff: __failure, __msg("memory, len pair leads to invalid memory access");
    test_dynptr_reg_type: __failure, __msg("R1 type=trusted_ptr_ expected=fp, dynptr_ptr");
    dynptr_overwrite_ref_with_clone: __success;
    dynptr_overwrite_ref_last_clone: __failure, __msg("cannot overwrite referenced dynptr");
    dynptr_overwrite_clone_with_original: __success;
    dynptr_overwrite_ref_invalidate_slice: __failure, __msg("invalid mem access 'scalar'");
    dynptr_overwrite_ref_clone_slice_valid: __success;
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

/* The five hand-written asm programs of the C: BPF_NAKED copies of the C
 * object's instruction sequence (maps by `sym`, helpers by number, the
 * C's labels, `w0 = 0; exit` for its `return 0`). */
#[link_section = "?tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dynptr_pruning_overwrite
extern "C" fn dynptr_pruning_overwrite(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        asm!(
            "r9 = 0xeB9F;",
            "r6 = {ringbuf} ll;",
            "r1 = r6;",
            "r2 = 8;",
            "r3 = 0;",
            "r4 = r10;",
            "r4 += -16;",
            "call 198;",
            "if r0 == 0 goto pjmp1;",
            "goto pjmp2;",
            "pjmp1:",
            "*(u64 *)(r10 - 16) = r9;",
            "pjmp2:",
            "r1 = r10;",
            "r1 += -16;",
            "r2 = 0;",
            "call 200;",
            "w0 = 0;",
            "exit;",
            ringbuf = sym ringbuf,
            options(noreturn)
        );
    }
}

#[link_section = "?tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dynptr_pruning_stacksafe
extern "C" fn dynptr_pruning_stacksafe(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        asm!(
            "r9 = 0xeB9F;",
            "r6 = {ringbuf} ll;",
            "r1 = r6;",
            "r2 = 8;",
            "r3 = 0;",
            "r4 = r10;",
            "r4 += -16;",
            "call 198;",
            "if r0 == 0 goto stjmp1;",
            "goto stjmp2;",
            "stjmp1:",
            "r9 = r9;",
            "stjmp2:",
            "r1 = r10;",
            "r1 += -16;",
            "r2 = 0;",
            "call 200;",
            "w0 = 0;",
            "exit;",
            ringbuf = sym ringbuf,
            options(noreturn)
        );
    }
}

#[link_section = "?tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dynptr_pruning_type_confusion
extern "C" fn dynptr_pruning_type_confusion(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        asm!(
            "r6 = {array_map4} ll;",
            "r7 = {ringbuf} ll;",
            "r1 = r6;",
            "r2 = r10;",
            "r2 += -8;",
            "r9 = 0;",
            "*(u64 *)(r2 + 0) = r9;",
            "r3 = r10;",
            "r3 += -24;",
            "r9 = 0xeB9FeB9F;",
            "*(u64 *)(r10 - 16) = r9;",
            "*(u64 *)(r10 - 24) = r9;",
            "r9 = 0;",
            "r4 = 0;",
            "r8 = r2;",
            "call 2;",
            "r1 = r6;",
            "r2 = r8;",
            "call 1;",
            "if r0 != 0 goto tjmp1;",
            "exit;",
            "tjmp1:",
            "r8 = r0;",
            "r1 = r7;",
            "r2 = 8;",
            "r3 = 0;",
            "r4 = r10;",
            "r4 += -16;",
            "r0 = *(u64 *)(r0 + 0);",
            "call 198;",
            "if r0 == 0 goto tjmp2;",
            "r8 = r8;",
            "r8 = r8;",
            "r8 = r8;",
            "r8 = r8;",
            "r8 = r8;",
            "r8 = r8;",
            "r8 = r8;",
            "goto tjmp3;",
            "tjmp2:",
            "*(u64 *)(r10 - 8) = r9;",
            "*(u64 *)(r10 - 16) = r9;",
            "r1 = r8;",
            "r1 += 8;",
            "r2 = 0;",
            "r3 = 0;",
            "r4 = r10;",
            "r4 += -16;",
            "call 197;",
            "tjmp3:",
            "r1 = r10;",
            "r1 += -16;",
            "r2 = 0;",
            "call 200;",
            "w0 = 0;",
            "exit;",
            array_map4 = sym array_map4,
            ringbuf = sym ringbuf,
            options(noreturn)
        );
    }
}

#[link_section = "?tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dynptr_var_off_overwrite
extern "C" fn dynptr_var_off_overwrite(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        asm!(
            "r9 = 16;",
            "*(u32 *)(r10 - 4) = r9;",
            "r8 = *(u32 *)(r10 - 4);",
            "if r8 >= 0 goto vjmp1;",
            "r0 = 1;",
            "exit;",
            "vjmp1:",
            "if r8 <= 16 goto vjmp2;",
            "r0 = 1;",
            "exit;",
            "vjmp2:",
            "r8 &= 16;",
            "r1 = {ringbuf} ll;",
            "r2 = 8;",
            "r3 = 0;",
            "r4 = r10;",
            "r4 += -32;",
            "r4 += r8;",
            "call 198;",
            "r9 = 0xeB9F;",
            "*(u64 *)(r10 - 16) = r9;",
            "r1 = r10;",
            "r1 += -32;",
            "r1 += r8;",
            "r2 = 0;",
            "call 200;",
            "w0 = 0;",
            "exit;",
            ringbuf = sym ringbuf,
            options(noreturn)
        );
    }
}

#[link_section = "?tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dynptr_partial_slot_invalidate
extern "C" fn dynptr_partial_slot_invalidate(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        asm!(
            "r6 = {ringbuf} ll;",
            "r7 = {array_map4} ll;",
            "r1 = r7;",
            "r2 = r10;",
            "r2 += -8;",
            "r9 = 0;",
            "*(u64 *)(r2 + 0) = r9;",
            "r3 = r2;",
            "r4 = 0;",
            "r8 = r2;",
            "call 2;",
            "r1 = r7;",
            "r2 = r8;",
            "call 1;",
            "if r0 != 0 goto sjmp1;",
            "exit;",
            "sjmp1:",
            "r7 = r0;",
            "r1 = r6;",
            "r2 = 8;",
            "r3 = 0;",
            "r4 = r10;",
            "r4 += -24;",
            "call 198;",
            "*(u64 *)(r10 - 16) = r9;",
            "r1 = r7;",
            "r2 = 8;",
            "r3 = 0;",
            "r4 = r10;",
            "r4 += -16;",
            "call 197;",
            "r1 = r10;",
            "r1 += -512;",
            "r2 = 488;",
            "r3 = r10;",
            "r3 += -24;",
            "r4 = 0;",
            "r5 = 0;",
            "call 201;",
            "r8 = 1;",
            "if r0 != 0 goto sjmp2;",
            "r8 = 0;",
            "sjmp2:",
            "r1 = r10;",
            "r1 += -24;",
            "r2 = 0;",
            "call 200;",
            "w0 = 0;",
            "exit;",
            ringbuf = sym ringbuf,
            array_map4 = sym array_map4,
            options(noreturn)
        );
    }
}

/* Test that it is allowed to overwrite unreferenced dynptr. */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_overwrite_unref(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    if get_map_val_dynptr(dpm(&ptr)) != 0 {
        return 0;
    }
    if get_map_val_dynptr(dpm(&ptr)) != 0 {
        return 0;
    }
    if get_map_val_dynptr(dpm(&ptr)) != 0 {
        return 0;
    }

    0
}

/* Test that slices are invalidated on reinitializing a dynptr. */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_invalidate_slice_reinit(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    if get_map_val_dynptr(dpm(&ptr)) != 0 {
        return 0;
    }
    let p = bpf_dynptr_data(dpv(&ptr), 0, 1) as *mut u8;
    if p.is_null() {
        return 0;
    }
    if get_map_val_dynptr(dpm(&ptr)) != 0 {
        return 0;
    }
    /* this should fail */
    (unsafe { *p }) as i32
}

/* Invalidation of dynptr slices on destruction of dynptr should not miss
 * mem_or_null pointers.
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_invalidate_slice_or_null(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    if get_map_val_dynptr(dpm(&ptr)) != 0 {
        return 0;
    }

    let p = bpf_dynptr_data(dpv(&ptr), 0, 1) as *mut u8;
    /* C: *(__u8 *)&ptr = 0; */
    unsafe {
        write_volatile(dpv(&ptr) as *mut u8, 0);
    }
    /* this should fail */
    bpf_this_cpu_ptr(p as *const c_void);
    0
}

/* Destruction of dynptr should also any slices obtained from it */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_invalidate_slice_failure(_ctx: *mut c_void) -> i32 {
    let ptr1 = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr2 = MaybeUninit::<bpf_dynptr>::uninit();

    if get_map_val_dynptr(dpm(&ptr1)) != 0 {
        return 0;
    }
    if get_map_val_dynptr(dpm(&ptr2)) != 0 {
        return 0;
    }

    let p1 = bpf_dynptr_data(dpv(&ptr1), 0, 1) as *mut u8;
    if p1.is_null() {
        return 0;
    }
    let p2 = bpf_dynptr_data(dpv(&ptr2), 0, 1) as *mut u8;
    if p2.is_null() {
        return 0;
    }

    /* C: *(__u8 *)&ptr1 = 0; */
    unsafe {
        write_volatile(dpv(&ptr1) as *mut u8, 0);
    }
    /* this should fail */
    (unsafe { *p1 }) as i32
}

/* Invalidation of slices should be scoped and should not prevent dereferencing
 * slices of another dynptr after destroying unrelated dynptr
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_invalidate_slice_success(_ctx: *mut c_void) -> i32 {
    let ptr1 = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr2 = MaybeUninit::<bpf_dynptr>::uninit();

    if get_map_val_dynptr(dpm(&ptr1)) != 0 {
        return 1;
    }
    if get_map_val_dynptr(dpm(&ptr2)) != 0 {
        return 1;
    }

    let p1 = bpf_dynptr_data(dpv(&ptr1), 0, 1) as *mut u8;
    if p1.is_null() {
        return 1;
    }
    let p2 = bpf_dynptr_data(dpv(&ptr2), 0, 1) as *mut u8;
    if p2.is_null() {
        return 1;
    }

    /* C: *(__u8 *)&ptr1 = 0; */
    unsafe {
        write_volatile(dpv(&ptr1) as *mut u8, 0);
    }
    (unsafe { *p2 }) as i32
}

/* Overwriting referenced dynptr should be rejected */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_overwrite_ref(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&ptr));
    /* this should fail */
    if get_map_val_dynptr(dpm(&ptr)) != 0 {
        bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);
    }
    0
}

/* C: union { struct { char _pad[48]; struct bpf_dynptr ptr; }; char buf[64]; } */
#[allow(non_camel_case_types)]
#[repr(C)]
struct pad_then_dynptr {
    _pad: [u8; 48],
    ptr: bpf_dynptr,
}

/* Reject writes to dynptr slot from bpf_dynptr_read */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_read_into_slot(_ctx: *mut c_void) -> i32 {
    let mut data = MaybeUninit::<pad_then_dynptr>::uninit();
    let dptr = unsafe { addr_of_mut!((*data.as_mut_ptr()).ptr) };

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dptr as *mut c_void);
    /* this should fail */
    bpf_dynptr_read(data.as_mut_ptr() as *mut c_void, 64, dptr as *const bpf_dynptr, 0, 0);

    0
}

/* bpf_dynptr_slice()s are read-only and cannot be written to */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn skb_invalid_slice_write(skb: *mut __sk_buff) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buffer: [u8; 14] = [0; 14];

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&ptr));
    }

    let hdr = unsafe { bpf_dynptr_slice(dp(&ptr), 0, buffer.as_mut_ptr() as *mut c_void, 14) }
        as *mut ethhdr;
    if hdr.is_null() {
        return SK_DROP;
    }

    /* this should fail */
    unsafe {
        (*hdr).h_proto = 1;
    }

    SK_PASS
}

/* bpf_dynptr_slice()s are read-only and cannot be written to */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn skb_meta_invalid_slice_write(skb: *mut __sk_buff) -> i32 {
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dpm(&meta));
    }

    let md = unsafe { bpf_dynptr_slice(dp(&meta), 0, core::ptr::null_mut(), 1) } as *mut u8;
    if md.is_null() {
        return SK_DROP;
    }

    /* this should fail */
    unsafe {
        *md = 42;
    }

    SK_PASS
}

/* The read-only data slice is invalidated whenever a helper changes packet data */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn skb_invalid_data_slice1(skb: *mut __sk_buff) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buffer: [u8; 14] = [0; 14];

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&ptr));
    }

    let hdr = unsafe { bpf_dynptr_slice(dp(&ptr), 0, buffer.as_mut_ptr() as *mut c_void, 14) }
        as *mut ethhdr;
    if hdr.is_null() {
        return SK_DROP;
    }

    set_val(unsafe { (*hdr).h_proto } as i32);

    if bpf_skb_pull_data(skb as *const c_void, unsafe { (*skb).len }) != 0 {
        return SK_DROP;
    }

    /* this should fail */
    set_val(unsafe { (*hdr).h_proto } as i32);

    SK_PASS
}

/* The read-write data slice is invalidated whenever a helper changes packet data */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn skb_invalid_data_slice2(skb: *mut __sk_buff) -> i32 {
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

    unsafe {
        (*hdr).h_proto = 123;
    }

    if bpf_skb_pull_data(skb as *const c_void, unsafe { (*skb).len }) != 0 {
        return SK_DROP;
    }

    /* this should fail */
    unsafe {
        (*hdr).h_proto = 1;
    }

    SK_PASS
}

/* The read-only data slice is invalidated whenever bpf_dynptr_write() is called */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn skb_invalid_data_slice3(skb: *mut __sk_buff) -> i32 {
    /* char write_data[64] = "hello there, world!!"; */
    let mut write_data = [0u64; 8];
    write_data[0] = 0x6874206f6c6c6568;
    write_data[1] = 0x726f77202c657265;
    write_data[2] = 0x2121646c;
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buffer: [u8; 14] = [0; 14];

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&ptr));
    }

    let hdr = unsafe { bpf_dynptr_slice(dp(&ptr), 0, buffer.as_mut_ptr() as *mut c_void, 14) }
        as *mut ethhdr;
    if hdr.is_null() {
        return SK_DROP;
    }

    set_val(unsafe { (*hdr).h_proto } as i32);

    bpf_dynptr_write(dp(&ptr), 0, write_data.as_mut_ptr() as *mut c_void, 64, 0);

    /* this should fail */
    set_val(unsafe { (*hdr).h_proto } as i32);

    SK_PASS
}

/* The read-write data slice is invalidated whenever bpf_dynptr_write() is called */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn skb_invalid_data_slice4(skb: *mut __sk_buff) -> i32 {
    /* char write_data[64] = "hello there, world!!"; */
    let mut write_data = [0u64; 8];
    write_data[0] = 0x6874206f6c6c6568;
    write_data[1] = 0x726f77202c657265;
    write_data[2] = 0x2121646c;
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

    unsafe {
        (*hdr).h_proto = 123;
    }

    bpf_dynptr_write(dp(&ptr), 0, write_data.as_mut_ptr() as *mut c_void, 64, 0);

    /* this should fail */
    unsafe {
        (*hdr).h_proto = 1;
    }

    SK_PASS
}

#[link_section = ".rodata.str1.1"]
static STR_X: [u8; 2] = *b"x\0";

/* Read-only skb data slice is invalidated on write to skb metadata */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn ro_skb_slice_invalid_after_metadata_write(skb: *mut __sk_buff) -> i32 {
    let data = MaybeUninit::<bpf_dynptr>::uninit();
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&data));
        bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dpm(&meta));
    }

    let d = unsafe { bpf_dynptr_slice(dp(&data), 0, core::ptr::null_mut(), 1) } as *mut u8;
    if d.is_null() {
        return SK_DROP;
    }

    bpf_dynptr_write(dp(&meta), 0, STR_X.as_ptr() as *mut c_void, 1, 0);

    /* this should fail */
    set_val(unsafe { *d } as i32);

    SK_PASS
}

/* Read-write skb data slice is invalidated on write to skb metadata */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rw_skb_slice_invalid_after_metadata_write(skb: *mut __sk_buff) -> i32 {
    let data = MaybeUninit::<bpf_dynptr>::uninit();
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&data));
        bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dpm(&meta));
    }

    let d = unsafe { bpf_dynptr_slice_rdwr(dp(&data), 0, core::ptr::null_mut(), 1) } as *mut u8;
    if d.is_null() {
        return SK_DROP;
    }

    bpf_dynptr_write(dp(&meta), 0, STR_X.as_ptr() as *mut c_void, 1, 0);

    /* this should fail */
    unsafe {
        *d = 42;
    }

    SK_PASS
}

/* Read-only skb metadata slice is invalidated on write to skb data */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn ro_skb_meta_slice_invalid_after_payload_write(skb: *mut __sk_buff) -> i32 {
    let data = MaybeUninit::<bpf_dynptr>::uninit();
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&data));
        bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dpm(&meta));
    }

    let md = unsafe { bpf_dynptr_slice(dp(&meta), 0, core::ptr::null_mut(), 1) } as *mut u8;
    if md.is_null() {
        return SK_DROP;
    }

    bpf_dynptr_write(dp(&data), 0, STR_X.as_ptr() as *mut c_void, 1, 0);

    /* this should fail */
    set_val(unsafe { *md } as i32);

    SK_PASS
}

/* Read-write skb metadata slice is invalidated on write to skb data slice */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rw_skb_meta_slice_invalid_after_payload_write(skb: *mut __sk_buff) -> i32 {
    let data = MaybeUninit::<bpf_dynptr>::uninit();
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&data));
        bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dpm(&meta));
    }

    let md = unsafe { bpf_dynptr_slice_rdwr(dp(&meta), 0, core::ptr::null_mut(), 1) } as *mut u8;
    if md.is_null() {
        return SK_DROP;
    }

    bpf_dynptr_write(dp(&data), 0, STR_X.as_ptr() as *mut c_void, 1, 0);

    /* this should fail */
    unsafe {
        *md = 42;
    }

    SK_PASS
}

/* Read-only skb metadata slice is invalidated whenever a helper changes packet data */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn ro_skb_meta_slice_invalid_after_payload_helper(skb: *mut __sk_buff) -> i32 {
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dpm(&meta));
    }

    let md = unsafe { bpf_dynptr_slice(dp(&meta), 0, core::ptr::null_mut(), 1) } as *mut u8;
    if md.is_null() {
        return SK_DROP;
    }

    if bpf_skb_pull_data(skb as *const c_void, unsafe { (*skb).len }) != 0 {
        return SK_DROP;
    }

    /* this should fail */
    set_val(unsafe { *md } as i32);

    SK_PASS
}

/* Read-write skb metadata slice is invalidated whenever a helper changes packet data */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rw_skb_meta_slice_invalid_after_payload_helper(skb: *mut __sk_buff) -> i32 {
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dpm(&meta));
    }

    let md = unsafe { bpf_dynptr_slice_rdwr(dp(&meta), 0, core::ptr::null_mut(), 1) } as *mut u8;
    if md.is_null() {
        return SK_DROP;
    }

    if bpf_skb_pull_data(skb as *const c_void, unsafe { (*skb).len }) != 0 {
        return SK_DROP;
    }

    /* this should fail */
    unsafe {
        *md = 42;
    }

    SK_PASS
}

/* Read-only skb metadata slice is invalidated on write to skb metadata */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn ro_skb_meta_slice_invalid_after_metadata_write(skb: *mut __sk_buff) -> i32 {
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dpm(&meta));
    }

    let md = unsafe { bpf_dynptr_slice(dp(&meta), 0, core::ptr::null_mut(), 1) } as *mut u8;
    if md.is_null() {
        return SK_DROP;
    }

    bpf_dynptr_write(dp(&meta), 0, STR_X.as_ptr() as *mut c_void, 1, 0);

    /* this should fail */
    set_val(unsafe { *md } as i32);

    SK_PASS
}

/* Read-write skb metadata slice is invalidated on write to skb metadata */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn rw_skb_meta_slice_invalid_after_metadata_write(skb: *mut __sk_buff) -> i32 {
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dpm(&meta));
    }

    let md = unsafe { bpf_dynptr_slice_rdwr(dp(&meta), 0, core::ptr::null_mut(), 1) } as *mut u8;
    if md.is_null() {
        return SK_DROP;
    }

    bpf_dynptr_write(dp(&meta), 0, STR_X.as_ptr() as *mut c_void, 1, 0);

    /* this should fail */
    unsafe {
        *md = 42;
    }

    SK_PASS
}

/* The read-only data slice is invalidated whenever a helper changes packet data */
#[link_section = "?xdp"]
#[no_mangle]
extern "C" fn xdp_invalid_data_slice1(xdp: *mut xdp_md) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buffer: [u8; 14] = [0; 14];

    unsafe {
        bpf_dynptr_from_xdp(xdp, 0, dpm(&ptr));
    }
    let hdr = unsafe { bpf_dynptr_slice(dp(&ptr), 0, buffer.as_mut_ptr() as *mut c_void, 14) }
        as *mut ethhdr;
    if hdr.is_null() {
        return SK_DROP;
    }

    set_val(unsafe { (*hdr).h_proto } as i32);

    if bpf_xdp_adjust_head(xdp, 0 - 14) != 0 {
        return XDP_DROP;
    }

    /* this should fail */
    set_val(unsafe { (*hdr).h_proto } as i32);

    XDP_PASS
}

/* The read-write data slice is invalidated whenever a helper changes packet data */
#[link_section = "?xdp"]
#[no_mangle]
extern "C" fn xdp_invalid_data_slice2(xdp: *mut xdp_md) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buffer: [u8; 14] = [0; 14];

    unsafe {
        bpf_dynptr_from_xdp(xdp, 0, dpm(&ptr));
    }
    let hdr = unsafe { bpf_dynptr_slice_rdwr(dp(&ptr), 0, buffer.as_mut_ptr() as *mut c_void, 14) }
        as *mut ethhdr;
    if hdr.is_null() {
        return SK_DROP;
    }

    unsafe {
        (*hdr).h_proto = 9;
    }

    if bpf_xdp_adjust_head(xdp, 0 - 14) != 0 {
        return XDP_DROP;
    }

    /* this should fail */
    unsafe {
        (*hdr).h_proto = 1;
    }

    XDP_PASS
}

/* Only supported prog type can create skb-type dynptrs */
#[link_section = "?xdp"]
#[no_mangle]
extern "C" fn skb_invalid_ctx(ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    /* this should fail */
    unsafe {
        bpf_dynptr_from_skb(ctx, 0, dpm(&ptr));
    }

    0
}

/* Only supported prog type can create skb_meta-type dynptrs */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn skb_meta_invalid_ctx(ctx: *mut c_void) -> i32 {
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    /* this should fail */
    unsafe {
        bpf_dynptr_from_skb_meta(ctx, 0, dpm(&meta));
    }

    0
}

#[link_section = "fentry/skb_tx_error"]
#[no_mangle]
extern "C" fn skb_invalid_ctx_fentry(ctx: *const u64) -> i32 {
    let skb = fentry_arg(ctx, 0) as *mut c_void;
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    /* this should fail */
    unsafe {
        bpf_dynptr_from_skb(skb, 0, dpm(&ptr));
    }

    0
}

#[link_section = "fexit/skb_tx_error"]
#[no_mangle]
extern "C" fn skb_invalid_ctx_fexit(ctx: *const u64) -> i32 {
    let skb = fentry_arg(ctx, 0) as *mut c_void;
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    /* this should fail */
    unsafe {
        bpf_dynptr_from_skb(skb, 0, dpm(&ptr));
    }

    0
}

/* C: struct { char buf[64]; struct bpf_dynptr ptr; } data; */
#[allow(non_camel_case_types)]
#[repr(C)]
struct buf_then_dynptr {
    buf: [u8; 64],
    ptr: bpf_dynptr,
}

/* Reject writes to dynptr slot for uninit arg */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn uninit_write_into_slot(_ctx: *mut c_void) -> i32 {
    let mut data = MaybeUninit::<buf_then_dynptr>::uninit();
    let dptr = unsafe { addr_of_mut!((*data.as_mut_ptr()).ptr) };

    bpf_ringbuf_reserve_dynptr(&ringbuf, 80, 0, dptr as *mut c_void);
    /* this should fail */
    bpf_get_current_comm(data.as_mut_ptr() as *mut c_void, 80);

    0
}

/* Only supported prog type can create xdp-type dynptrs */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn xdp_invalid_ctx(ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    /* this should fail */
    unsafe {
        bpf_dynptr_from_xdp(ctx as *mut xdp_md, 0, dpm(&ptr));
    }

    0
}

/* C: __u32 hdr_size = sizeof(struct ethhdr); */
#[no_mangle]
static mut hdr_size: u32 = 14;

/* Can't pass in variable-sized len to bpf_dynptr_slice */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn dynptr_slice_var_len1(skb: *mut __sk_buff) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buffer: [u8; 14] = [0; 14];

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&ptr));
    }

    /* this should fail */
    let hdr = unsafe {
        bpf_dynptr_slice(dp(&ptr), 0, buffer.as_mut_ptr() as *mut c_void, hdr_size)
    } as *mut ethhdr;
    if hdr.is_null() {
        return SK_DROP;
    }

    SK_PASS
}

/* Can't pass in variable-sized len to bpf_dynptr_slice */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn dynptr_slice_var_len2(skb: *mut __sk_buff) -> i32 {
    let mut buffer: [u8; 14] = [0; 14];
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&ptr));
    }

    if unsafe { hdr_size } <= 14 {
        /* this should fail */
        let hdr = unsafe {
            bpf_dynptr_slice_rdwr(dp(&ptr), 0, buffer.as_mut_ptr() as *mut c_void, hdr_size)
        } as *mut ethhdr;
        if hdr.is_null() {
            return SK_DROP;
        }
        unsafe {
            (*hdr).h_proto = 12;
        }
    }

    SK_PASS
}

#[export_name = "callback"]
extern "C" fn callback(_index: u64, data: *mut u32) -> i64 {
    unsafe {
        *data = 123;
    }

    0
}

/* A commuted add should preserve the parent id of a dynptr data slice. */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_slice_commuted_invalidate(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 4, 0, dpv(&ptr));

    let mut slice = bpf_dynptr_data(dpv(&ptr), 0, 4) as *mut u32;
    if slice.is_null() {
        bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);
        return 0;
    }

    let derived: *mut u32;
    unsafe {
        asm!(
            "{dst} = 0;",
            "{dst} += {src};",
            "{src} = 0;",
            dst = out(reg) derived,
            src = inout(reg) slice,
        );
    }
    let _ = slice;

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);
    set_val(unsafe { *derived } as i32);
    0
}

/* If the dynptr is written into in a callback function, its data
 * slices should be invalidated as well.
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn invalid_data_slices(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    if get_map_val_dynptr(dpm(&ptr)) != 0 {
        return 0;
    }

    let slice = bpf_dynptr_data(dpv(&ptr), 0, 4) as *mut u32;
    if slice.is_null() {
        return 0;
    }

    bpf_loop(10, callback, dpv(&ptr) as *mut u32, 0);

    /* this should fail */
    unsafe {
        *slice = 1;
    }

    0
}

/* Program types that don't allow writes to packet data should fail if
 * bpf_dynptr_slice_rdwr is called
 */
#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
extern "C" fn invalid_slice_rdwr_rdonly(skb: *mut __sk_buff) -> i32 {
    let mut buffer: [u8; 14] = [0; 14];
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&ptr));
    }

    /* this should fail since cgroup_skb doesn't allow
     * changing packet data
     */
    let mut hdr = unsafe { bpf_dynptr_slice_rdwr(dp(&ptr), 0, buffer.as_mut_ptr() as *mut c_void, 14) }
        as *mut ethhdr;
    sink(&mut hdr);

    0
}

/* bpf_dynptr_adjust can only be called on initialized dynptrs */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_adjust_invalid(_ctx: *mut c_void) -> i32 {
    let mut ptr = bpf_dynptr { __opaque: [0, 0] };

    /* this should fail */
    unsafe {
        bpf_dynptr_adjust(addr_of_mut!(ptr), 1, 2);
    }

    0
}

/* bpf_dynptr_is_null can only be called on initialized dynptrs */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_is_null_invalid(_ctx: *mut c_void) -> i32 {
    let mut ptr = bpf_dynptr { __opaque: [0, 0] };

    /* this should fail */
    unsafe {
        bpf_dynptr_is_null(addr_of_mut!(ptr));
    }

    0
}

/* bpf_dynptr_is_rdonly can only be called on initialized dynptrs */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_is_rdonly_invalid(_ctx: *mut c_void) -> i32 {
    let mut ptr = bpf_dynptr { __opaque: [0, 0] };

    /* this should fail */
    unsafe {
        bpf_dynptr_is_rdonly(addr_of_mut!(ptr));
    }

    0
}

/* bpf_dynptr_size can only be called on initialized dynptrs */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_size_invalid(_ctx: *mut c_void) -> i32 {
    let mut ptr = bpf_dynptr { __opaque: [0, 0] };

    /* this should fail */
    unsafe {
        bpf_dynptr_size(addr_of_mut!(ptr));
    }

    0
}

/* Only initialized dynptrs can be cloned */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn clone_invalid1(_ctx: *mut c_void) -> i32 {
    /* reverse-declared: clang's frame has ptr1 at fp-16 and ptr2 at fp-32,
     * rustc gives the last-declared local the higher slot, and the prover
     * pins the clone kfunc's pointer arguments by frame offset */
    let ptr2 = MaybeUninit::<bpf_dynptr>::uninit();
    let mut ptr1 = bpf_dynptr { __opaque: [0, 0] };

    /* this should fail */
    unsafe {
        bpf_dynptr_clone(addr_of_mut!(ptr1), dpm(&ptr2));
    }

    0
}

/* Can't overwrite an existing dynptr when cloning */
#[link_section = "?xdp"]
#[no_mangle]
extern "C" fn clone_invalid2(xdp: *mut xdp_md) -> i32 {
    /* reverse-declared (clone_invalid1) */
    let clone = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr1 = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_xdp(xdp, 0, dpm(&ptr1));
    }

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&clone));

    /* this should fail */
    unsafe {
        bpf_dynptr_clone(dp(&ptr1), dpm(&clone));
    }

    bpf_ringbuf_submit_dynptr(dpv(&clone), 0);

    0
}

/* Invalidating a dynptr should invalidate its clones */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn clone_invalidate1(_ctx: *mut c_void) -> i32 {
    let clone = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut read_data = MaybeUninit::<[u8; 64]>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));

    unsafe {
        bpf_dynptr_clone(dp(&ptr), dpm(&clone));
    }

    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);

    /* this should fail */
    bpf_dynptr_read(read_data.as_mut_ptr() as *mut c_void, 64, dp(&clone), 0, 0);

    0
}

/* Invalidating a dynptr should invalidate its parent */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn clone_invalidate2(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let clone = MaybeUninit::<bpf_dynptr>::uninit();
    let mut read_data = MaybeUninit::<[u8; 64]>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));

    unsafe {
        bpf_dynptr_clone(dp(&ptr), dpm(&clone));
    }

    bpf_ringbuf_submit_dynptr(dpv(&clone), 0);

    /* this should fail */
    bpf_dynptr_read(read_data.as_mut_ptr() as *mut c_void, 64, dp(&ptr), 0, 0);

    0
}

/* Invalidating a dynptr should invalidate its siblings */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn clone_invalidate3(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let clone1 = MaybeUninit::<bpf_dynptr>::uninit();
    let clone2 = MaybeUninit::<bpf_dynptr>::uninit();
    let mut read_data = MaybeUninit::<[u8; 64]>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));

    unsafe {
        bpf_dynptr_clone(dp(&ptr), dpm(&clone1));

        bpf_dynptr_clone(dp(&ptr), dpm(&clone2));
    }

    bpf_ringbuf_submit_dynptr(dpv(&clone2), 0);

    /* this should fail */
    bpf_dynptr_read(read_data.as_mut_ptr() as *mut c_void, 64, dp(&clone1), 0, 0);

    0
}

/* Invalidating a dynptr should invalidate any data slices
 * of its clones
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn clone_invalidate4(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let clone = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));

    unsafe {
        bpf_dynptr_clone(dp(&ptr), dpm(&clone));
    }
    let data = bpf_dynptr_data(dpv(&clone), 0, 4) as *mut i32;
    if data.is_null() {
        return 0;
    }

    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);

    /* this should fail */
    unsafe {
        *data = 123;
    }

    0
}

#[inline(never)]
fn clone_slice_in_subprog(ptr: *mut bpf_dynptr, data: *mut *mut i32) {
    let clone = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_clone(ptr, dpm(&clone));
        *data = bpf_dynptr_data(dpv(&clone), 0, 4) as *mut i32;
    }
}

#[inline(never)]
fn caller_slice_in_subprog(ptr: *mut bpf_dynptr, data: *mut *mut i32) {
    let clone = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        *data = bpf_dynptr_data(ptr as *mut c_void, 0, 4) as *mut i32;
        bpf_dynptr_clone(ptr, dpm(&clone));
    }
}

#[inline(never)]
fn reserve_dynptr_in_subprog() {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));
}

/* A subprogram cannot lose the last dynptr that can release a resource. */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn referenced_dynptr_lost_on_subprog_return(_ctx: *mut c_void) -> i32 {
    reserve_dynptr_in_subprog();

    0
}

/*
 * Destroying a callee-local clone on return must not invalidate a slice whose
 * source dynptr belongs to the caller.
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn caller_dynptr_slice_across_subprog_valid(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut data: *mut i32 = core::ptr::null_mut();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));
    caller_slice_in_subprog(dpm(&ptr), &mut data);
    if !data.is_null() {
        unsafe {
            *data = 123;
        }
    }
    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);

    0
}

/*
 * A slice derived from a callee-local clone is invalid after the subprogram
 * returns.
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn callee_dynptr_slice_invalid_after_return(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut data: *mut i32 = core::ptr::null_mut();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));
    clone_slice_in_subprog(dpm(&ptr), &mut data);
    if !data.is_null() {
        /* this should fail */
        unsafe {
            *data = 123;
        }
    }
    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);

    0
}

/*
 * A slice from a caller-owned dynptr survives the subprogram return, but
 * releasing the shared reservation must invalidate it.
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn caller_dynptr_slice_release_after_subprog_invalid(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut data: *mut i32 = core::ptr::null_mut();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));
    caller_slice_in_subprog(dpm(&ptr), &mut data);
    bpf_ringbuf_submit_dynptr(dpv(&ptr), 0);
    if !data.is_null() {
        /* this should fail */
        unsafe {
            *data = 123;
        }
    }

    0
}

/* Invalidating a dynptr should invalidate any data slices
 * of its parent
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn clone_invalidate5(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let clone = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));
    let data = bpf_dynptr_data(dpv(&ptr), 0, 4) as *mut i32;
    if data.is_null() {
        return 0;
    }

    unsafe {
        bpf_dynptr_clone(dp(&ptr), dpm(&clone));
    }

    bpf_ringbuf_submit_dynptr(dpv(&clone), 0);

    /* this should fail */
    unsafe {
        *data = 123;
    }

    0
}

/* Invalidating a dynptr should invalidate any data slices
 * of its sibling
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn clone_invalidate6(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let clone1 = MaybeUninit::<bpf_dynptr>::uninit();
    let clone2 = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));

    unsafe {
        bpf_dynptr_clone(dp(&ptr), dpm(&clone1));

        bpf_dynptr_clone(dp(&ptr), dpm(&clone2));
    }

    let data = bpf_dynptr_data(dpv(&clone1), 0, 4) as *mut i32;
    if data.is_null() {
        return 0;
    }

    bpf_ringbuf_submit_dynptr(dpv(&clone2), 0);

    /* this should fail */
    unsafe {
        *data = 123;
    }

    0
}

/* A skb clone's data slices should be invalid anytime packet data changes */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn clone_skb_packet_data(skb: *mut __sk_buff) -> i32 {
    let mut buffer: [u8; 4] = [0; 4];
    let clone = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&ptr));

        bpf_dynptr_clone(dp(&ptr), dpm(&clone));
    }
    let data = unsafe { bpf_dynptr_slice_rdwr(dp(&clone), 0, buffer.as_mut_ptr() as *mut c_void, 4) }
        as *mut u32;
    if data.is_null() {
        return XDP_DROP;
    }

    if bpf_skb_pull_data(skb as *const c_void, unsafe { (*skb).len }) != 0 {
        return SK_DROP;
    }

    /* this should fail */
    unsafe {
        *data = 123;
    }

    0
}

/* A skb clone's metadata slice becomes invalid anytime packet data changes */
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn clone_skb_packet_meta(skb: *mut __sk_buff) -> i32 {
    let clone = MaybeUninit::<bpf_dynptr>::uninit();
    let meta = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_skb_meta(skb as *mut c_void, 0, dpm(&meta));
        bpf_dynptr_clone(dp(&meta), dpm(&clone));
    }
    let md = unsafe { bpf_dynptr_slice_rdwr(dp(&clone), 0, core::ptr::null_mut(), 1) } as *mut u8;
    if md.is_null() {
        return SK_DROP;
    }

    if bpf_skb_pull_data(skb as *const c_void, unsafe { (*skb).len }) != 0 {
        return SK_DROP;
    }

    /* this should fail */
    unsafe {
        *md = 42;
    }

    0
}

/* A xdp clone's data slices should be invalid anytime packet data changes */
#[link_section = "?xdp"]
#[no_mangle]
extern "C" fn clone_xdp_packet_data(xdp: *mut xdp_md) -> i32 {
    let mut buffer: [u8; 4] = [0; 4];
    let clone = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    unsafe {
        bpf_dynptr_from_xdp(xdp, 0, dpm(&ptr));

        bpf_dynptr_clone(dp(&ptr), dpm(&clone));
    }
    let data = unsafe { bpf_dynptr_slice_rdwr(dp(&clone), 0, buffer.as_mut_ptr() as *mut c_void, 4) }
        as *mut u32;
    if data.is_null() {
        return XDP_DROP;
    }

    /* C: bpf_xdp_adjust_head(xdp, 0 - (int)sizeof(*hdr)) with struct ethhdr *hdr */
    if bpf_xdp_adjust_head(xdp, 0 - 14) != 0 {
        return XDP_DROP;
    }

    /* this should fail */
    unsafe {
        *data = 123;
    }

    0
}

/* Buffers that are provided must be sufficiently long */
#[link_section = "?cgroup_skb/egress"]
#[no_mangle]
extern "C" fn test_dynptr_skb_small_buff(skb: *mut __sk_buff) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let mut buffer: [u8; 8] = [0; 8];

    if unsafe { bpf_dynptr_from_skb(skb as *mut c_void, 0, dpm(&ptr)) } != 0 {
        unsafe {
            err = 1;
        }
        return 1;
    }

    /* This may return NULL. SKB may require a buffer */
    let data = unsafe { bpf_dynptr_slice(dp(&ptr), 0, buffer.as_mut_ptr() as *mut c_void, 9) }
        as *mut u64;

    (!data.is_null()) as i32
}

#[no_mangle]
#[inline(never)]
extern "C" fn global_call_bpf_dynptr(dynptr: *const bpf_dynptr) -> i64 {
    let mut ret: *mut u8 = core::ptr::null_mut();
    /* Avoid leaving this global function empty to avoid having the compiler
     * optimize away the call to this global function.
     */
    let mut d = dynptr as *mut bpf_dynptr;
    sink(&mut d);
    sink(&mut ret);
    ret as i64
}

#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn test_dynptr_reg_type(_ctx: *mut c_void) -> i32 {
    let current = bpf_get_current_task_btf::<task_struct>();
    /* R1 holds a PTR_TO_BTF_ID, which cannot be passed to a function
     * accepting ARG_PTR_TO_DYNPTR | MEM_RDONLY.
     */
    global_call_bpf_dynptr(current as *const bpf_dynptr);
    0
}

/* Overwriting a referenced dynptr is allowed if a clone still holds the ref */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_overwrite_ref_with_clone(_ctx: *mut c_void) -> i32 {
    /* reverse-declared (clone_invalid1) */
    let clone = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&ptr));

    unsafe {
        bpf_dynptr_clone(dp(&ptr), dpm(&clone));
    }

    /* Overwrite the original - clone still holds the ref */
    unsafe {
        write_volatile(dpv(&ptr) as *mut u8, 0);
    }

    bpf_ringbuf_discard_dynptr(dpv(&clone), 0);

    0
}

/* Overwriting the last referenced dynptr should still be rejected */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_overwrite_ref_last_clone(_ctx: *mut c_void) -> i32 {
    /* reverse-declared (clone_invalid1) */
    let clone = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&ptr));

    unsafe {
        bpf_dynptr_clone(dp(&ptr), dpm(&clone));
    }

    /* Overwrite the original - clone still holds the ref, OK */
    unsafe {
        write_volatile(dpv(&ptr) as *mut u8, 0);
    }

    /* Overwrite the last holder - this should fail */
    unsafe {
        write_volatile(dpv(&clone) as *mut u8, 0);
    }

    0
}

/* Overwriting a clone should be allowed if the original still holds the ref */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_overwrite_clone_with_original(_ctx: *mut c_void) -> i32 {
    /* reverse-declared (clone_invalid1) */
    let clone = MaybeUninit::<bpf_dynptr>::uninit();
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, 64, 0, dpv(&ptr));

    unsafe {
        bpf_dynptr_clone(dp(&ptr), dpm(&clone));
    }

    /* Overwrite the clone - original still holds the ref */
    unsafe {
        write_volatile(dpv(&clone) as *mut u8, 0);
    }

    bpf_ringbuf_discard_dynptr(dpv(&ptr), 0);

    0
}

/* Data slices from the destroyed dynptr should be invalidated */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_overwrite_ref_invalidate_slice(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let clone = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));

    let data = bpf_dynptr_data(dpv(&ptr), 0, 4) as *mut i32;
    if data.is_null() {
        return 0;
    }

    unsafe {
        bpf_dynptr_clone(dp(&ptr), dpm(&clone));
    }

    /* Overwrite the original - clone holds the ref */
    unsafe {
        write_volatile(dpv(&ptr) as *mut u8, 0);
    }

    /* data was from the original dynptr, should be invalid now */
    unsafe {
        *data = 123;
    }

    0
}

/*
 * Data slices from a dynptr clone should remain valid after
 * overwriting the original dynptr
 */
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn dynptr_overwrite_ref_clone_slice_valid(_ctx: *mut c_void) -> i32 {
    let ptr = MaybeUninit::<bpf_dynptr>::uninit();
    let clone = MaybeUninit::<bpf_dynptr>::uninit();

    bpf_ringbuf_reserve_dynptr(&ringbuf, unsafe { val } as u32, 0, dpv(&ptr));

    unsafe {
        bpf_dynptr_clone(dp(&ptr), dpm(&clone));
    }

    let data = bpf_dynptr_data(dpv(&clone), 0, 4) as *mut i32;
    if data.is_null() {
        bpf_ringbuf_discard_dynptr(dpv(&clone), 0);
        return 0;
    }

    /* Overwrite the original - clone holds the ref */
    unsafe {
        write_volatile(dpv(&ptr) as *mut u8, 0);
    }

    /* data is from the clone, should still be valid */
    unsafe {
        *data = 123;
    }

    bpf_ringbuf_discard_dynptr(dpv(&clone), 0);

    0
}

bpf_object!("GPL");
