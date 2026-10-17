// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/verifier_const.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_const.rs
// (include!d below): tcx1, tcx2, tcx3, tcx4, tcx5, tcx6, tcx7, bprm.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_const` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: tcx1 tcx2 tcx3 tcx4 tcx5 tcx6 tcx7 bprm

// the C's anonymous types, named here; scripts/btf_anon.py clears
// the names in the object's BTF
// BTF_ANON

use bpf_rs_core::{test_tags};
use core::ffi::c_void;

test_tags! {
    tcx1:
        __description("rodata/strtol: write rejected"),
        __failure,
        __msg("write into map forbidden");
    tcx2:
        __description("bss/strtol: write accepted"),
        __success;
    tcx3:
        __description("data/strtol: write accepted"),
        __success;
    tcx4:
        __description("rodata/mtu: write rejected"),
        __failure,
        __msg("write into map forbidden");
    tcx5:
        __description("bss/mtu: write accepted"),
        __success;
    tcx6:
        __description("data/mtu: write accepted"),
        __success;
    tcx7:
        __description("rodata/mark: write with unknown reg rejected"),
        __failure,
        __msg("write into map forbidden");
    bprm:
        __description("rodata/mark: write with unknown reg rejected"),
        __failure,
        __msg("write into map forbidden");
}

// Map key/value types, shaped like the C object's BTF (the kernel
// checks some of them member by member, so no explicit padding).
// translint: allow(padding)
#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union __sk_buff__anon26 {
    flow_keys: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union __sk_buff__anon30 {
    sk: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct __sk_buff {
    len: u32,
    pkt_type: u32,
    mark: u32,
    queue_mapping: u32,
    protocol: u32,
    vlan_present: u32,
    vlan_tci: u32,
    vlan_proto: u32,
    priority: u32,
    ingress_ifindex: u32,
    ifindex: u32,
    tc_index: u32,
    cb: [u32; 5],
    hash: u32,
    tc_classid: u32,
    data: u32,
    data_end: u32,
    napi_id: u32,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [u32; 4],
    local_ip6: [u32; 4],
    remote_port: u32,
    local_port: u32,
    data_meta: u32,
    __anon26: __sk_buff__anon26,
    tstamp: u64,
    wire_len: u32,
    gso_segs: u32,
    __anon30: __sk_buff__anon30,
    gso_size: u32,
    tstamp_type: u8,
    hwtstamp: u64,
}

#[no_mangle]
static mut bar: i64 = 0;

#[no_mangle]
static mut bart: i64 = 96;

#[no_mangle]
static foo: i64 = 42;

include!("hand/verifier_const.rs");

// The C source names its license global `LICENSE`; the symbol
// name must match for the keep-list, so bpf_object! is written out.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
