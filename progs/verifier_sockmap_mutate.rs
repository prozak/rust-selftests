// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Translation of tools/testing/selftests/bpf/progs/verifier_sockmap_mutate.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_sockmap_mutate.rs
// (include!d below): test_sched_act, test_sched_cls, test_flow_dissector_delete, test_flow_dissector_update, test_trace_iter, test_raw_tp_delete, test_raw_tp_update, test_sk_lookup, test_sk_reuseport, test_socket_filter, test_sockops_delete, test_sockops_update, test_sockops_update_dedicated, test_xdp.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_sockmap_mutate` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: test_sched_act test_sched_cls test_flow_dissector_delete test_flow_dissector_update test_trace_iter test_raw_tp_delete test_raw_tp_update test_sk_lookup test_sk_reuseport test_socket_filter test_sockops_delete test_sockops_update test_sockops_update_dedicated test_xdp

// the C's anonymous types, named here; scripts/btf_anon.py clears
// the names in the object's BTF
// BTF_ANON

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    test_sched_act:
        __failure,
        __msg("cannot update sockmap in this context");
    test_sched_cls:
        __failure,
        __msg("cannot update sockmap in this context");
    test_flow_dissector_delete:
        __failure,
        __msg("cannot update sockmap in this context");
    test_flow_dissector_update:
        __failure,
        __msg("cannot update sockmap in this context");
    test_trace_iter:
        __success;
    test_raw_tp_delete:
        __failure,
        __msg("cannot update sockmap in this context");
    test_raw_tp_update:
        __failure,
        __msg("cannot update sockmap in this context");
    test_sk_lookup:
        __success;
    test_sk_reuseport:
        __success;
    test_socket_filter:
        __failure,
        __msg("cannot update sockmap in this context");
    test_sockops_delete:
        __success;
    test_sockops_update:
        __failure,
        __msg("cannot update sockmap in this context");
    test_sockops_update_dedicated:
        __success;
    test_xdp:
        __failure,
        __msg("cannot update sockmap in this context");
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

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_iter__sockmap__anon0 {
    sk: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_sk_lookup__anon0__anon0 {
    sk: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_sk_lookup__anon0 {
    __anon0: bpf_sk_lookup__anon0__anon0,
    cookie: u64,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_sk_lookup {
    __anon0: bpf_sk_lookup__anon0,
    family: u32,
    protocol: u32,
    remote_ip4: u32,
    remote_ip6: [u32; 4],
    remote_port: u16,
    local_ip4: u32,
    local_ip6: [u32; 4],
    local_port: u32,
    ingress_ifindex: u32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union sk_reuseport_md__anon0 {
    data: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union sk_reuseport_md__anon1 {
    data_end: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union sk_reuseport_md__anon7 {
    sk: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union sk_reuseport_md__anon8 {
    migrating_sk: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct sk_reuseport_md {
    __anon0: sk_reuseport_md__anon0,
    __anon1: sk_reuseport_md__anon1,
    len: u32,
    eth_protocol: u32,
    ip_protocol: u32,
    bind_inany: u32,
    hash: u32,
    __anon7: sk_reuseport_md__anon7,
    __anon8: sk_reuseport_md__anon8,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_sock_ops__anon1 {
    args: [u32; 4],
    reply: u32,
    replylong: [u32; 4],
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_sock_ops__anon35 {
    sk: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_sock_ops__anon36 {
    skb_data: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
union bpf_sock_ops__anon37 {
    skb_data_end: *mut c_void,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_sock_ops {
    op: u32,
    __anon1: bpf_sock_ops__anon1,
    family: u32,
    remote_ip4: u32,
    local_ip4: u32,
    remote_ip6: [u32; 4],
    local_ip6: [u32; 4],
    remote_port: u32,
    local_port: u32,
    is_fullsock: u32,
    snd_cwnd: u32,
    srtt_us: u32,
    bpf_sock_ops_cb_flags: u32,
    state: u32,
    rtt_min: u32,
    snd_ssthresh: u32,
    rcv_nxt: u32,
    snd_nxt: u32,
    snd_una: u32,
    mss_cache: u32,
    ecn_flags: u32,
    rate_delivered: u32,
    rate_interval_us: u32,
    packets_out: u32,
    retrans_out: u32,
    total_retrans: u32,
    segs_in: u32,
    data_segs_in: u32,
    segs_out: u32,
    data_segs_out: u32,
    lost_out: u32,
    sacked_out: u32,
    sk_txhash: u32,
    bytes_received: u64,
    bytes_acked: u64,
    __anon35: bpf_sock_ops__anon35,
    __anon36: bpf_sock_ops__anon36,
    __anon37: bpf_sock_ops__anon37,
    skb_len: u32,
    skb_tcp_flags: u32,
    skb_hwtstamp: u64,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct xdp_md {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

bpf_map! {
    sockmap {
        r#type: *const [i32; 15],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i32,
    }
}

bpf_map! {
    sockhash {
        r#type: *const [i32; 18],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i32,
    }
}

#[no_mangle]
#[allow(non_upper_case_globals)]
static mut zero: i32 = 0;

include!("hand/verifier_sockmap_mutate.rs");

bpf_object!("GPL");
