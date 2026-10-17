// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/verifier_mtu.c
// (bpf-rs-core idiom). A single verifier test: bpf_check_mtu() is passed a
// pointer to a stack-local __u32 that is left uninitialized on purpose (the
// C source declares `__u32 mtu;` with no initializer). Privileged load
// succeeds; unprivileged, with CAP_BPF|CAP_NET_ADMIN dropped, the verifier
// rejects the uninitialized stack read.
//
// Both halves of that are decl tags on the C object, mirrored below by
// test_tags! and appended to the built object by scripts/btf_test_tags.py.
// __caps_unpriv takes the numbers bpf_misc.h's EXPAND_QUOTE produces for
// CAP_BPF|CAP_NET_ADMIN.

use core::ffi::c_void;
use core::mem::MaybeUninit;

use bpf_rs_core::bpf_map;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_check_mtu, bpf_get_current_comm, bpf_map_lookup_elem};
use bpf_rs_core::test_tags;

const TCX_PASS: i32 = 0;
const XDP_PASS: i32 = 2;

/// UAPI struct xdp_md (linux/bpf.h); the xdp program's context must be
/// typed so in BTF.
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

// BPF_MAP_TYPE_ARRAY = 2, BPF_F_RDONLY_PROG = 1 << 7, BPF_F_WRONLY_PROG = 1 << 8.
bpf_map! {
    map_mtu_wo {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        map_flags: *const [i32; 256], // BPF_F_WRONLY_PROG
        key: *const u32,
        value: *const u32,
    }
}

bpf_map! {
    map_mtu_rw {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u32,
    }
}

bpf_map! {
    map_mtu_ro {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        map_flags: *const [i32; 128], // BPF_F_RDONLY_PROG
        key: *const u32,
        value: *const u32,
    }
}

test_tags! {
    tc_uninit_mtu:
        __description("uninit/mtu: write rejected"),
        __success,
        __caps_unpriv("39|12"),
        __failure_unpriv,
        __msg_unpriv("invalid read from stack");
    tc_writeonly_mtu: __failure, __msg("read from map forbidden");
    tc_readwrite_mtu: __success;
    xdp_writeonly_mtu: __failure, __msg("read from map forbidden");
    tc_readonly_mtu: __failure, __msg("write into map forbidden");
    tc_writeonly_output: __success;
}

#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tc_uninit_mtu(ctx: *const __sk_buff) -> i32 {
    let mut mtu: MaybeUninit<u32> = MaybeUninit::uninit();

    bpf_check_mtu(ctx as *const c_void, 0, mtu.as_mut_ptr(), 0, 0);
    TCX_PASS
}

#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tc_writeonly_mtu(ctx: *const __sk_buff) -> i32 {
    let key: u32 = 0;
    let mtu = bpf_map_lookup_elem(&map_mtu_wo, &key) as *mut u32;
    if !mtu.is_null() {
        bpf_check_mtu(ctx as *const c_void, 0, mtu, 0, 0);
    }
    TCX_PASS
}

#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tc_readwrite_mtu(ctx: *const __sk_buff) -> i32 {
    let key: u32 = 0;
    let mtu = bpf_map_lookup_elem(&map_mtu_rw, &key) as *mut u32;
    if !mtu.is_null() {
        bpf_check_mtu(ctx as *const c_void, 0, mtu, 0, 0);
    }
    TCX_PASS
}

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn xdp_writeonly_mtu(ctx: *const xdp_md) -> i32 {
    let key: u32 = 0;
    let mtu = bpf_map_lookup_elem(&map_mtu_wo, &key) as *mut u32;
    if !mtu.is_null() {
        bpf_check_mtu(ctx as *const c_void, 0, mtu, 0, 0);
    }
    XDP_PASS
}

#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tc_readonly_mtu(ctx: *const __sk_buff) -> i32 {
    let key: u32 = 0;
    let mtu = bpf_map_lookup_elem(&map_mtu_ro, &key) as *mut u32;
    if !mtu.is_null() {
        bpf_check_mtu(ctx as *const c_void, 0, mtu, 0, 0);
    }
    TCX_PASS
}

#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tc_writeonly_output(_ctx: *const __sk_buff) -> i32 {
    let key: u32 = 0;
    let out = bpf_map_lookup_elem(&map_mtu_wo, &key) as *mut u32;
    if !out.is_null() {
        bpf_get_current_comm(out as *mut c_void, core::mem::size_of::<u32>() as u32);
    }
    TCX_PASS
}

// The C source names its license global `LICENSE` (most selftests use
// `_license`, which is what bpf_rs_core::bpf_object! hardcodes) — the
// symbol name must match exactly for the internalize keep-list to retain
// it, so this is written out by hand instead of via the macro.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
