#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/bpf_qdisc_dynptr_use_after_invalidate_clone.c,
// bpf-rs-core idiom.
//
// __success struct_ops program: prog_tests/bpf_qdisc.c's
// RUN_TESTS(bpf_qdisc_dynptr_use_after_invalidate_clone) only asserts the
// object loads (test_loader.c's expect-success path) — the qdisc is never
// attached/exercised. The three bpf_qdisc_test_* members are __auxiliary
// (present only so the Qdisc_ops struct_ops map is complete enough to
// load), matching bpf_tcp_nogpl.rs's convention of ctx: *const u64 args.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg;
use core::ffi::c_void;

#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

#[repr(C)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

const NET_XMIT_DROP: i32 = 0x01;

extern "C" {
    fn bpf_dynptr_from_skb(skb: *mut c_void, flags: u64, ptr: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_clone(ptr: *const bpf_dynptr, clone: *mut bpf_dynptr) -> i32;
    fn bpf_dynptr_slice(
        ptr: *const bpf_dynptr,
        offset: u64,
        buffer: *mut c_void,
        buffer_sz: u64,
    ) -> *mut c_void;
    fn bpf_qdisc_skb_drop(skb: *mut c_void, to_free: *mut c_void);
}

#[no_mangle]
static mut proto: i32 = 0;

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn dynptr_use_after_invalidate_clone(ctx: *const u64) -> i32 {
    let skb = fentry_arg(ctx, 0) as *mut c_void;
    let to_free = fentry_arg(ctx, 2) as *mut c_void;

    let mut ptr = bpf_dynptr { __opaque: [0, 0] };
    let mut ptr_clone = bpf_dynptr { __opaque: [0, 0] };

    unsafe {
        bpf_dynptr_from_skb(skb, 0, &mut ptr as *mut bpf_dynptr);

        bpf_dynptr_clone(&ptr as *const bpf_dynptr, &mut ptr_clone as *mut bpf_dynptr);

        let hdr = bpf_dynptr_slice(
            &ptr_clone as *const bpf_dynptr,
            0,
            core::ptr::null_mut(),
            core::mem::size_of::<ethhdr>() as u64,
        ) as *mut ethhdr;
        if hdr.is_null() {
            bpf_qdisc_skb_drop(skb, to_free);
            return NET_XMIT_DROP;
        }

        *(&mut ptr as *mut bpf_dynptr as *mut i32) = 0;

        proto = (*hdr).h_proto as i32;

        bpf_qdisc_skb_drop(skb, to_free);
    }

    NET_XMIT_DROP
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_qdisc_test_dequeue(_ctx: *const u64) -> *mut c_void {
    core::ptr::null_mut()
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_qdisc_test_init(_ctx: *const u64) -> i32 {
    0
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_qdisc_test_reset(_ctx: *const u64) {}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_qdisc_test_destroy(_ctx: *const u64) {}

// struct Qdisc_ops (include/net/sch_generic.h): only the members this
// program initializes are declared — libbpf's struct_ops relocation
// matches local struct members against the kernel type by name (see
// bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct Qdisc_ops {
    enqueue: extern "C" fn(*const u64) -> i32,
    dequeue: extern "C" fn(*const u64) -> *mut c_void,
    init: extern "C" fn(*const u64) -> i32,
    reset: extern "C" fn(*const u64),
    destroy: extern "C" fn(*const u64),
    id: [u8; 16],
}

unsafe impl Sync for Qdisc_ops {}

#[link_section = ".struct_ops"]
#[no_mangle]
static test: Qdisc_ops = Qdisc_ops {
    enqueue: dynptr_use_after_invalidate_clone,
    dequeue: bpf_qdisc_test_dequeue,
    init: bpf_qdisc_test_init,
    reset: bpf_qdisc_test_reset,
    destroy: bpf_qdisc_test_destroy,
    id: *b"bpf_qdisc_test\0\0",
};

bpf_object!("GPL");
