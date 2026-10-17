// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/verifier_map_lookup_refine.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_map_lookup_refine.rs
// (include!d below): mapofmaps_value_as_kfunc_mem_buf, mapofmaps_value_as_helper_mem_buf, mapofmaps_value_as_helper_fixed_mem.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_map_lookup_refine` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: mapofmaps_value_as_kfunc_mem_buf mapofmaps_value_as_helper_mem_buf mapofmaps_value_as_helper_fixed_mem

// the C's anonymous types, named here; scripts/btf_anon.py clears
// the names in the object's BTF
// BTF_ANON

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    mapofmaps_value_as_kfunc_mem_buf:
        __failure,
        __msg("type=map_ptr_or_null expected=fp");
    mapofmaps_value_as_helper_mem_buf:
        __failure,
        __msg("type=map_ptr_or_null expected=fp");
    mapofmaps_value_as_helper_fixed_mem:
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1");
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

bpf_map! {
    inner_map {
        r#type: *const [i32; 2],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i32,
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct outer_map {
    r#type: *const [i32; 12],
    max_entries: *const [i32; 1],
    key: *const i32,
    values: [*const inner_map; 1],
}
unsafe impl Sync for outer_map {}

#[link_section = ".maps"]
#[no_mangle]
static outer_map: outer_map = outer_map {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    values: [&inner_map],
};

extern "C" {
    fn bpf_dynptr_from_skb(a0: *mut c_void, a1: u64, a2: *mut c_void) -> i32;
    fn bpf_dynptr_slice(a0: *mut c_void, a1: u64, a2: *mut c_void, a3: u64) -> *mut c_void;
}

include!("hand/verifier_map_lookup_refine.rs");

bpf_object!("GPL");
