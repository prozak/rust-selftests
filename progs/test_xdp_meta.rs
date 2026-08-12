#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp_meta.c
// (bpf-rs-core idiom). Exercises skb/xdp metadata (data_meta) through the
// classic ctx->data_meta/data pointer idiom and through the newer
// bpf_dynptr_from_skb_meta()/bpf_dynptr_from_skb() kfunc + dynptr
// read/write/slice/adjust helper set. Consumed by
// prog_tests/xdp_context_test_run.c's test_xdp_context_veth,
// test_xdp_context_tuntap and test_xdp_context_lwt_encap.
//
// bpf_dynptr_from_skb(_meta)/bpf_dynptr_slice(_rdwr)/bpf_dynptr_adjust/
// bpf_dynptr_size/bpf_dynptr_is_rdonly are __bpf_kfunc (kernel/bpf/helpers.c,
// net/core/filter.c) so they are declared `extern "C"` here, resolved by the
// pipeline's add_ksyms ksym relocation, same as
// [[xdp-dynptr-kfunc-first-translation]]. bpf_dynptr_read/write are ordinary
// numbered helpers (201/202) and go through bpf-rs-core's thunk! mechanism.
//
// bpf_stream_vprintk (the kfunc behind C's bpf_stream_printk() macro) is
// KF_IMPLICIT_ARGS: no C prototype exists anywhere (the verifier appends a
// trailing `struct bpf_prog_aux *aux` the caller never supplies), and per
// [[stream]] a null/zero-length varargs pointer is rejected outright, so the
// no-varargs call routes through a real local's address instead of
// `core::ptr::null()`. Only the diagnostic message text differs from the C
// source (no %pI6 dump) — check_metadata's return-value contract, which is
// all the userspace tests observe, is unchanged.
//
// Multi-byte copies (memcpy/memset-shaped in the C source) go through
// volatile per-byte loops per
// [[copy-nonoverlapping-becomes-arena-memcpy-kfunc]], not
// core::ptr::copy_nonoverlapping/write_bytes.
//
// skb/xdp data(_meta) bounds checks (`have + META_SIZE > data`) use real
// pointer arithmetic (`.add(META_SIZE)` then a pointer compare), not usize
// arithmetic, per [[pkt-bounds-check-needs-raw-pointer-add-not-integer]].

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK, TC_ACT_SHOT};
use bpf_rs_core::helpers::{
    bpf_dynptr_read, bpf_dynptr_write, bpf_skb_adjust_room, bpf_skb_change_head,
    bpf_skb_change_proto, bpf_skb_change_tail, bpf_skb_load_bytes, bpf_skb_vlan_pop,
    bpf_skb_vlan_push, bpf_xdp_adjust_meta, bpf_xdp_get_buff_len, bpf_xdp_load_bytes,
};
use bpf_rs_core::vload;

const TC_ACT_UNSPEC: i32 = -1;
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;

const BPF_OK: i32 = 0;
const BPF_DROP: i32 = 2;

const BPF_ADJ_ROOM_MAC: u32 = 1;

const E2BIG: i64 = 7;
const ERANGE: i32 = 34;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

const META_SIZE: usize = 32;
const IPV6HDR_SZ: u32 = 40;

static META_WANT: [u8; META_SIZE] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x38,
];

#[no_mangle]
static mut test_pass: bool = false;

/// UAPI struct xdp_md (linux/bpf.h).
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

// linux/if_ether.h: only h_proto is ever read/written here.
#[repr(C, packed)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

const ETHHDR_SZ: u64 = core::mem::size_of::<ethhdr>() as u64;
const ETHHDR_H_PROTO_OFFSET: u64 = 12; // offsetof(struct ethhdr, h_proto): h_dest[6] + h_source[6]

// UAPI struct bpf_dynptr (linux/bpf.h): opaque, two anonymous __u64
// bitfields, aligned(8).
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

extern "C" {
    fn bpf_dynptr_from_skb(skb: *const __sk_buff, flags: u64, ptr: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_from_skb_meta(skb: *const __sk_buff, flags: u64, ptr: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_slice(
        ptr: *const bpf_dynptr,
        offset: u64,
        buffer: *mut c_void,
        buffer_sz: u64,
    ) -> *mut c_void;
    fn bpf_dynptr_slice_rdwr(
        ptr: *const bpf_dynptr,
        offset: u64,
        buffer: *mut c_void,
        buffer_sz: u64,
    ) -> *mut c_void;
    fn bpf_dynptr_adjust(ptr: *mut bpf_dynptr, start: u64, end: u64) -> i32;
    fn bpf_dynptr_size(ptr: *const bpf_dynptr) -> u64;
    fn bpf_dynptr_is_rdonly(ptr: *const bpf_dynptr) -> bool;

    fn bpf_stream_vprintk(stream_id: i32, fmt: *const u8, args: *const c_void, len: u32) -> i32;
}

const BPF_STDERR: i32 = 2;

#[inline(always)]
fn stream_report_mismatch() {
    static FMT: &[u8] = b"FAIL: metadata mismatch\n\0";
    let no_args: u64 = 0;
    unsafe {
        bpf_stream_vprintk(
            BPF_STDERR,
            FMT.as_ptr(),
            core::ptr::addr_of!(no_args) as *const c_void,
            0,
        );
    }
}

#[inline(always)]
unsafe fn vcopy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
}

#[inline(always)]
unsafe fn vzero(dst: *mut u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        core::ptr::write_volatile(dst.add(i), 0u8);
        i += 1;
    }
}

#[inline(always)]
fn bytes_eq(a: *const u8, b: &[u8; META_SIZE]) -> bool {
    let mut i = 0usize;
    while i < META_SIZE {
        if unsafe { *a.add(i) } != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[inline(always)]
fn check_metadata(meta_have: *const u8) -> bool {
    if bytes_eq(meta_have, &META_WANT) {
        return true;
    }
    stream_report_mismatch();
    false
}

#[inline(always)]
fn check_skb_metadata(skb: *const __sk_buff) -> bool {
    let data_meta = vload!((*skb).data_meta) as usize as *const u8;
    let data = vload!((*skb).data) as usize as *const u8;
    (unsafe { data_meta.add(META_SIZE) } as *const u8) <= data && check_metadata(data_meta)
}

#[inline(always)]
fn is_test_packet_xdp(ctx: *const xdp_md) -> bool {
    // C: `__u32 len = bpf_xdp_get_buff_len(ctx);` — the helper returns u64
    // and the assignment narrows it, which the comparison below then sees.
    let len = bpf_xdp_get_buff_len(ctx as *mut xdp_md) as u32;
    if len < META_SIZE as u32 {
        return false;
    }
    let mut meta_have = [0u8; META_SIZE];
    if bpf_xdp_load_bytes(
        ctx as *mut xdp_md,
        len - META_SIZE as u32,
        meta_have.as_mut_ptr() as *mut c_void,
        META_SIZE as u32,
    ) != 0
    {
        return false;
    }
    bytes_eq(meta_have.as_ptr(), &META_WANT)
}

#[inline(always)]
fn is_test_packet_tc(ctx: *const __sk_buff) -> bool {
    let len = vload!((*ctx).len);
    if len < META_SIZE as u32 {
        return false;
    }
    let mut meta_have = [0u8; META_SIZE];
    if bpf_skb_load_bytes(
        ctx as *const c_void,
        len - META_SIZE as u32,
        meta_have.as_mut_ptr() as *mut c_void,
        META_SIZE as u32,
    ) != 0
    {
        return false;
    }
    bytes_eq(meta_have.as_ptr(), &META_WANT)
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ing_cls(ctx: *const __sk_buff) -> i32 {
    let meta_have = vload!((*ctx).data_meta) as usize as *const u8;
    let data = vload!((*ctx).data) as usize as *const u8;
    if (unsafe { meta_have.add(META_SIZE) } as *const u8) <= data {
        if check_metadata(meta_have) {
            unsafe {
                test_pass = true;
            }
        }
    }
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ing_cls_dynptr_read(ctx: *const __sk_buff) -> i32 {
    let mut meta_have = [0u8; META_SIZE];
    let mut meta = bpf_dynptr { __opaque: [0, 0] };
    unsafe {
        bpf_dynptr_from_skb_meta(ctx, 0, &mut meta);
    }
    bpf_dynptr_read(
        meta_have.as_mut_ptr() as *mut c_void,
        META_SIZE as u64,
        &meta,
        0,
        0,
    );
    if check_metadata(meta_have.as_ptr()) {
        unsafe {
            test_pass = true;
        }
    }
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ing_cls_dynptr_write(ctx: *const __sk_buff) -> i32 {
    let mut data = bpf_dynptr { __opaque: [0, 0] };
    let mut meta = bpf_dynptr { __opaque: [0, 0] };

    unsafe {
        bpf_dynptr_from_skb(ctx, 0, &mut data);
    }
    let src = unsafe {
        bpf_dynptr_slice(&data, ETHHDR_SZ, core::ptr::null_mut(), META_SIZE as u64) as *mut u8
    };
    if src.is_null() {
        return TC_ACT_SHOT;
    }

    unsafe {
        bpf_dynptr_from_skb_meta(ctx, 0, &mut meta);
    }
    bpf_dynptr_write(&meta, 0, src as *mut c_void, META_SIZE as u64, 0);

    TC_ACT_UNSPEC
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ing_cls_dynptr_slice(ctx: *const __sk_buff) -> i32 {
    let mut meta = bpf_dynptr { __opaque: [0, 0] };
    unsafe {
        bpf_dynptr_from_skb_meta(ctx, 0, &mut meta);
    }
    let meta_have =
        unsafe { bpf_dynptr_slice(&meta, 0, core::ptr::null_mut(), META_SIZE as u64) as *const u8 };
    if !meta_have.is_null() && check_metadata(meta_have) {
        unsafe {
            test_pass = true;
        }
    }
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ing_cls_dynptr_slice_rdwr(ctx: *const __sk_buff) -> i32 {
    let mut data = bpf_dynptr { __opaque: [0, 0] };
    let mut meta = bpf_dynptr { __opaque: [0, 0] };

    unsafe {
        bpf_dynptr_from_skb(ctx, 0, &mut data);
    }
    let src = unsafe {
        bpf_dynptr_slice(&data, ETHHDR_SZ, core::ptr::null_mut(), META_SIZE as u64) as *const u8
    };
    if src.is_null() {
        return TC_ACT_SHOT;
    }

    unsafe {
        bpf_dynptr_from_skb_meta(ctx, 0, &mut meta);
    }
    let dst = unsafe {
        bpf_dynptr_slice_rdwr(&meta, 0, core::ptr::null_mut(), META_SIZE as u64) as *mut u8
    };
    if dst.is_null() {
        return TC_ACT_SHOT;
    }

    unsafe {
        vcopy(dst, src, META_SIZE);
    }

    TC_ACT_UNSPEC
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ing_cls_dynptr_offset_rd(ctx: *const __sk_buff) -> i32 {
    const CHUNK_LEN: usize = META_SIZE / 4;

    let mut meta_have = [0u8; META_SIZE];
    let mut meta = bpf_dynptr { __opaque: [0, 0] };
    let mut dst = meta_have.as_mut_ptr();

    // 1. Regular read
    unsafe {
        bpf_dynptr_from_skb_meta(ctx, 0, &mut meta);
    }
    bpf_dynptr_read(dst as *mut c_void, CHUNK_LEN as u64, &meta, 0, 0);
    dst = unsafe { dst.add(CHUNK_LEN) };

    // 2. Read from an offset-adjusted dynptr
    let size = unsafe { bpf_dynptr_size(&meta) };
    unsafe {
        bpf_dynptr_adjust(&mut meta, CHUNK_LEN as u64, size);
    }
    bpf_dynptr_read(dst as *mut c_void, CHUNK_LEN as u64, &meta, 0, 0);
    dst = unsafe { dst.add(CHUNK_LEN) };

    // 3. Read at an offset
    bpf_dynptr_read(dst as *mut c_void, CHUNK_LEN as u64, &meta, CHUNK_LEN as u64, 0);
    dst = unsafe { dst.add(CHUNK_LEN) };

    // 4. Read from a slice starting at an offset
    let src = unsafe {
        bpf_dynptr_slice(
            &meta,
            (2 * CHUNK_LEN) as u64,
            core::ptr::null_mut(),
            CHUNK_LEN as u64,
        ) as *const u8
    };
    if src.is_null() {
        return TC_ACT_SHOT;
    }
    unsafe {
        vcopy(dst, src, CHUNK_LEN);
    }

    if check_metadata(meta_have.as_ptr()) {
        unsafe {
            test_pass = true;
        }
    }
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ing_cls_dynptr_offset_wr(ctx: *const __sk_buff) -> i32 {
    const CHUNK_LEN: usize = META_SIZE / 4;

    let mut payload = [0u8; META_SIZE];
    let mut meta = bpf_dynptr { __opaque: [0, 0] };

    bpf_skb_load_bytes(
        ctx as *const c_void,
        ETHHDR_SZ as u32,
        payload.as_mut_ptr() as *mut c_void,
        payload.len() as u32,
    );
    let mut src = payload.as_ptr();

    // 1. Regular write
    unsafe {
        bpf_dynptr_from_skb_meta(ctx, 0, &mut meta);
    }
    bpf_dynptr_write(&meta, 0, src as *mut c_void, CHUNK_LEN as u64, 0);
    src = unsafe { src.add(CHUNK_LEN) };

    // 2. Write to an offset-adjusted dynptr
    let size = unsafe { bpf_dynptr_size(&meta) };
    unsafe {
        bpf_dynptr_adjust(&mut meta, CHUNK_LEN as u64, size);
    }
    bpf_dynptr_write(&meta, 0, src as *mut c_void, CHUNK_LEN as u64, 0);
    src = unsafe { src.add(CHUNK_LEN) };

    // 3. Write at an offset
    bpf_dynptr_write(&meta, CHUNK_LEN as u64, src as *mut c_void, CHUNK_LEN as u64, 0);
    src = unsafe { src.add(CHUNK_LEN) };

    // 4. Write to a slice starting at an offset
    let dst = unsafe {
        bpf_dynptr_slice_rdwr(
            &meta,
            (2 * CHUNK_LEN) as u64,
            core::ptr::null_mut(),
            CHUNK_LEN as u64,
        ) as *mut u8
    };
    if dst.is_null() {
        return TC_ACT_SHOT;
    }
    unsafe {
        vcopy(dst, src, CHUNK_LEN);
    }

    TC_ACT_UNSPEC
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn ing_cls_dynptr_offset_oob(ctx: *const __sk_buff) -> i32 {
    let mut meta = bpf_dynptr { __opaque: [0, 0] };
    let mut md: u8 = 0;

    let err = unsafe { bpf_dynptr_from_skb_meta(ctx, 0, &mut meta) };
    if err != 0 {
        return TC_ACT_SHOT;
    }

    // read offset OOB
    let err = bpf_dynptr_read(
        &mut md as *mut u8 as *mut c_void,
        core::mem::size_of::<u8>() as u64,
        &meta,
        META_SIZE as u64,
        0,
    );
    if err != -E2BIG {
        return TC_ACT_SHOT;
    }

    // write offset OOB
    let err = bpf_dynptr_write(
        &meta,
        META_SIZE as u64,
        &mut md as *mut u8 as *mut c_void,
        core::mem::size_of::<u8>() as u64,
        0,
    );
    if err != -E2BIG {
        return TC_ACT_SHOT;
    }

    // adjust end offset OOB
    let err = unsafe { bpf_dynptr_adjust(&mut meta, 0, (META_SIZE + 1) as u64) };
    if err != -ERANGE {
        return TC_ACT_SHOT;
    }

    // adjust start offset OOB
    let err =
        unsafe { bpf_dynptr_adjust(&mut meta, (META_SIZE + 1) as u64, (META_SIZE + 1) as u64) };
    if err != -ERANGE {
        return TC_ACT_SHOT;
    }

    // slice offset OOB
    let p = unsafe {
        bpf_dynptr_slice(
            &meta,
            META_SIZE as u64,
            core::ptr::null_mut(),
            core::mem::size_of::<u8>() as u64,
        )
    };
    if !p.is_null() {
        return TC_ACT_SHOT;
    }

    // slice rdwr offset OOB
    let p = unsafe {
        bpf_dynptr_slice_rdwr(
            &meta,
            META_SIZE as u64,
            core::ptr::null_mut(),
            core::mem::size_of::<u8>() as u64,
        )
    };
    if !p.is_null() {
        return TC_ACT_SHOT;
    }

    TC_ACT_UNSPEC
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn ing_xdp_zalloc_meta(ctx: *const xdp_md) -> i32 {
    if !is_test_packet_xdp(ctx) {
        return XDP_DROP;
    }

    let ret = unsafe { bpf_xdp_adjust_meta(ctx as *mut xdp_md, -(META_SIZE as i32)) };
    if ret < 0 {
        return XDP_DROP;
    }

    let meta = vload!((*ctx).data_meta) as usize as *mut u8;
    let data = vload!((*ctx).data) as usize as *const u8;
    if (unsafe { meta.add(META_SIZE) } as *const u8) > data {
        return XDP_DROP;
    }

    unsafe {
        vzero(meta, META_SIZE);
    }

    XDP_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn ing_xdp(ctx: *const xdp_md) -> i32 {
    if !is_test_packet_xdp(ctx) {
        return XDP_DROP;
    }

    let ret = unsafe { bpf_xdp_adjust_meta(ctx as *mut xdp_md, -(META_SIZE as i32)) };
    if ret < 0 {
        return XDP_DROP;
    }

    let data_meta = vload!((*ctx).data_meta) as usize as *mut u8;
    let data = vload!((*ctx).data) as usize as *const u8;

    if (unsafe { data_meta.add(META_SIZE) } as *const u8) > data {
        return XDP_DROP;
    }

    unsafe {
        vcopy(data_meta, META_WANT.as_ptr(), META_SIZE);
    }
    XDP_PASS
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn clone_data_meta_survives_data_write(ctx: *const __sk_buff) -> i32 {
    let meta_have = vload!((*ctx).data_meta) as usize as *const u8;
    let eth = vload!((*ctx).data) as usize as *mut ethhdr;
    let data_end = vload!((*ctx).data_end) as usize as *const u8;

    if (unsafe { eth.add(1) } as *const u8) <= data_end
        && is_test_packet_tc(ctx)
        && (unsafe { meta_have.add(META_SIZE) } as *const u8) <= (eth as *const u8)
        && check_metadata(meta_have)
    {
        unsafe {
            core::ptr::write_unaligned(core::ptr::addr_of_mut!((*eth).h_proto), 42u16);
            test_pass = true;
        }
    }
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn clone_data_meta_survives_meta_write(ctx: *const __sk_buff) -> i32 {
    let meta_have = vload!((*ctx).data_meta) as usize as *mut u8;
    let eth = vload!((*ctx).data) as usize as *const ethhdr;
    let data_end = vload!((*ctx).data_end) as usize as *const u8;

    if (unsafe { eth.add(1) } as *const u8) <= data_end
        && is_test_packet_tc(ctx)
        && (unsafe { meta_have.add(META_SIZE) } as *const u8) <= (eth as *const u8)
        && check_metadata(meta_have)
    {
        unsafe {
            core::ptr::write_volatile(meta_have, 42u8);
            test_pass = true;
        }
    }
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn clone_meta_dynptr_survives_data_slice_write(ctx: *const __sk_buff) -> i32 {
    let mut data = bpf_dynptr { __opaque: [0, 0] };
    let mut meta = bpf_dynptr { __opaque: [0, 0] };
    let mut meta_have = [0u8; META_SIZE];

    unsafe {
        bpf_dynptr_from_skb(ctx, 0, &mut data);
    }
    let eth = unsafe {
        bpf_dynptr_slice_rdwr(&data, 0, core::ptr::null_mut(), core::mem::size_of::<ethhdr>() as u64)
    };
    if eth.is_null() {
        return TC_ACT_SHOT;
    }
    if !is_test_packet_tc(ctx) {
        return TC_ACT_SHOT;
    }

    unsafe {
        bpf_dynptr_from_skb_meta(ctx, 0, &mut meta);
    }
    bpf_dynptr_read(
        meta_have.as_mut_ptr() as *mut c_void,
        META_SIZE as u64,
        &meta,
        0,
        0,
    );
    if check_metadata(meta_have.as_ptr()) {
        unsafe {
            test_pass = true;
        }
    }
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn clone_meta_dynptr_survives_meta_slice_write(ctx: *const __sk_buff) -> i32 {
    if !is_test_packet_tc(ctx) {
        return TC_ACT_SHOT;
    }

    let mut meta = bpf_dynptr { __opaque: [0, 0] };
    unsafe {
        bpf_dynptr_from_skb_meta(ctx, 0, &mut meta);
    }
    let meta_have = unsafe {
        bpf_dynptr_slice_rdwr(&meta, 0, core::ptr::null_mut(), META_SIZE as u64) as *const u8
    };
    if meta_have.is_null() {
        return TC_ACT_SHOT;
    }

    if check_metadata(meta_have) {
        unsafe {
            test_pass = true;
        }
    }
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn clone_meta_dynptr_rw_before_data_dynptr_write(ctx: *const __sk_buff) -> i32 {
    if !is_test_packet_tc(ctx) {
        return TC_ACT_SHOT;
    }

    let mut meta = bpf_dynptr { __opaque: [0, 0] };
    let mut data = bpf_dynptr { __opaque: [0, 0] };
    let mut meta_have = [0u8; META_SIZE];

    unsafe {
        bpf_dynptr_from_skb_meta(ctx, 0, &mut meta);
    }
    if unsafe { bpf_dynptr_is_rdonly(&meta) } {
        return TC_ACT_SHOT;
    }

    let err = bpf_dynptr_read(
        meta_have.as_mut_ptr() as *mut c_void,
        META_SIZE as u64,
        &meta,
        0,
        0,
    );
    if err != 0 || !check_metadata(meta_have.as_ptr()) {
        return TC_ACT_SHOT;
    }

    unsafe {
        bpf_dynptr_from_skb(ctx, 0, &mut data);
    }
    let x_byte: u8 = b'x';
    bpf_dynptr_write(
        &data,
        ETHHDR_H_PROTO_OFFSET,
        &x_byte as *const u8 as *mut c_void,
        1,
        0,
    );

    let err = bpf_dynptr_read(
        meta_have.as_mut_ptr() as *mut c_void,
        META_SIZE as u64,
        &meta,
        0,
        0,
    );
    if err != 0 || !check_metadata(meta_have.as_ptr()) {
        return TC_ACT_SHOT;
    }

    unsafe {
        test_pass = true;
    }
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn clone_meta_dynptr_rw_before_meta_dynptr_write(ctx: *const __sk_buff) -> i32 {
    if !is_test_packet_tc(ctx) {
        return TC_ACT_SHOT;
    }

    let mut meta = bpf_dynptr { __opaque: [0, 0] };
    let mut meta_have = [0u8; META_SIZE];

    unsafe {
        bpf_dynptr_from_skb_meta(ctx, 0, &mut meta);
    }
    if unsafe { bpf_dynptr_is_rdonly(&meta) } {
        return TC_ACT_SHOT;
    }

    let err = bpf_dynptr_read(
        meta_have.as_mut_ptr() as *mut c_void,
        META_SIZE as u64,
        &meta,
        0,
        0,
    );
    if err != 0 || !check_metadata(meta_have.as_ptr()) {
        return TC_ACT_SHOT;
    }

    bpf_dynptr_write(
        &meta,
        0,
        meta_have.as_mut_ptr() as *mut c_void,
        1,
        0,
    );

    let err = bpf_dynptr_read(
        meta_have.as_mut_ptr() as *mut c_void,
        META_SIZE as u64,
        &meta,
        0,
        0,
    );
    if err != 0 || !check_metadata(meta_have.as_ptr()) {
        return TC_ACT_SHOT;
    }

    unsafe {
        test_pass = true;
    }
    TC_ACT_SHOT
}

#[link_section = "lwt_xmit"]
#[no_mangle]
extern "C" fn dummy_lwt_xmit(ctx: *const __sk_buff) -> i32 {
    if bpf_skb_change_head(ctx as *const c_void, IPV6HDR_SZ, 0) != 0 {
        return BPF_DROP;
    }
    BPF_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tc_is_meta_empty(ctx: *const __sk_buff) -> i32 {
    if !is_test_packet_tc(ctx) {
        return TC_ACT_OK;
    }

    let data_meta = vload!((*ctx).data_meta);
    let data = vload!((*ctx).data);
    if data_meta != data {
        return TC_ACT_OK;
    }

    unsafe {
        test_pass = true;
    }
    TC_ACT_OK
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn helper_skb_vlan_push_pop(ctx: *const __sk_buff) -> i32 {
    if bpf_skb_vlan_push(ctx as *mut c_void, 0, 42) != 0 {
        return TC_ACT_SHOT;
    }
    if bpf_skb_vlan_push(ctx as *mut c_void, 0, 207) != 0 {
        return TC_ACT_SHOT;
    }
    if !check_skb_metadata(ctx) {
        return TC_ACT_SHOT;
    }

    if bpf_skb_vlan_pop(ctx as *const c_void) != 0 {
        return TC_ACT_SHOT;
    }
    if bpf_skb_vlan_pop(ctx as *const c_void) != 0 {
        return TC_ACT_SHOT;
    }
    if !check_skb_metadata(ctx) {
        return TC_ACT_SHOT;
    }

    unsafe {
        test_pass = true;
    }
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn helper_skb_adjust_room(ctx: *const __sk_buff) -> i32 {
    // Grow a 1 byte hole after the MAC header
    if bpf_skb_adjust_room(ctx as *const c_void, 1, BPF_ADJ_ROOM_MAC, 0) != 0 {
        return TC_ACT_SHOT;
    }
    if !check_skb_metadata(ctx) {
        return TC_ACT_SHOT;
    }

    // Shrink a 1 byte hole after the MAC header
    if bpf_skb_adjust_room(ctx as *const c_void, -1, BPF_ADJ_ROOM_MAC, 0) != 0 {
        return TC_ACT_SHOT;
    }
    if !check_skb_metadata(ctx) {
        return TC_ACT_SHOT;
    }

    // Grow a 256 byte hole to trigger head reallocation
    if bpf_skb_adjust_room(ctx as *const c_void, 256, BPF_ADJ_ROOM_MAC, 0) != 0 {
        return TC_ACT_SHOT;
    }
    if !check_skb_metadata(ctx) {
        return TC_ACT_SHOT;
    }

    unsafe {
        test_pass = true;
    }
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn helper_skb_change_head_tail(ctx: *const __sk_buff) -> i32 {
    // Reserve 1 extra in the front for packet data
    if bpf_skb_change_head(ctx as *const c_void, 1, 0) != 0 {
        return TC_ACT_SHOT;
    }
    if !check_skb_metadata(ctx) {
        return TC_ACT_SHOT;
    }

    // Reserve 256 extra bytes in the front to trigger head reallocation
    if bpf_skb_change_head(ctx as *const c_void, 256, 0) != 0 {
        return TC_ACT_SHOT;
    }
    if !check_skb_metadata(ctx) {
        return TC_ACT_SHOT;
    }

    // Reserve 4k extra bytes in the back to trigger head reallocation
    let len = vload!((*ctx).len);
    if bpf_skb_change_tail(ctx as *const c_void, len + 4096, 0) != 0 {
        return TC_ACT_SHOT;
    }
    if !check_skb_metadata(ctx) {
        return TC_ACT_SHOT;
    }

    unsafe {
        test_pass = true;
    }
    TC_ACT_SHOT
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn helper_skb_change_proto(ctx: *const __sk_buff) -> i32 {
    if bpf_skb_change_proto(ctx as *const c_void, ETH_P_IPV6.to_be(), 0) != 0 {
        return TC_ACT_SHOT;
    }
    if !check_skb_metadata(ctx) {
        return TC_ACT_SHOT;
    }

    if bpf_skb_change_proto(ctx as *const c_void, ETH_P_IP.to_be(), 0) != 0 {
        return TC_ACT_SHOT;
    }
    if !check_skb_metadata(ctx) {
        return TC_ACT_SHOT;
    }

    unsafe {
        test_pass = true;
    }
    TC_ACT_SHOT
}

bpf_object!("GPL");
