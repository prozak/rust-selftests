// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of tools/testing/selftests/bpf/progs/verifier_sock.c, GENERATED
// by scripts/naked_gen.py --with-c-bodies (bpf-rs-core idiom), except the
// function(s) with C bodies, translated by hand in progs/hand/verifier_sock.rs
// (include!d below): skb_pull_data2, skb_pull_data1, invalidate_pkt_pointers_from_global_func, xdp_pull_data2, xdp_pull_data1, invalidate_xdp_pkt_pointers_from_global_func, invalidate_xdp_pkt_pointers, tail_call, static_tail_call, invalidate_pkt_pointers_by_global_tail_call, invalidate_pkt_pointers_by_static_tail_call, invalidate_pkt_pointers_by_tail_call.
// Every other function in the C
// source is `__naked` hand-written BPF asm, carried here verbatim as
// `// BPF_NAKED:` raw asm (scripts/naked_abi.py) with bpf_misc.h's operands
// resolved the way clang resolves them (helper ids and constants as
// literals; maps, subprograms and kfuncs as `sym`), the `%=` labels
// suffixed with the function's name, and the test_loader decl tags
// mirrored verbatim from the C object. Regenerate with
// `scripts/naked_gen.py verifier_sock` rather than editing by hand;
// scripts/translint.py's naked-verbatim check compares the built object
// with the C object instruction by instruction.

// BPF_PROGRAM_ORDER: skb_sk_no_null_check sk_family_non_fullsock_field_1 sk_rx_queue_mapping_no_sign_ext sk_rx_queue_mapping_narrow_load_mask sk_sk_type_fullsock_field_1 sk_no_skb_sk_check_1 no_null_check_on_ret_1 sk_sk_type_fullsock_field_2 sk_family_non_fullsock_field_2 sk_sk_state_narrow_load port_word_load_backward_compatibility sk_dst_port_half_load dst_port_half_load_invalid_1 sk_dst_port_byte_load dst_port_byte_load_invalid dst_port_half_load_invalid_2 dst_ip6_load_2nd_byte sk_sk_type_narrow_load sk_sk_protocol_narrow_load skb_sk_beyond_last_field_1 sk_no_skb_sk_check_2 no_null_check_on_ret_2 skb_sk_tp_snd_cwnd_1 skb_sk_tp_bytes_acked skb_sk_beyond_last_field_2 skb_sk_tp_snd_cwnd_2 bpf_sk_release_skb_sk bpf_sk_fullsock_skb_sk bpf_tcp_sock_skb_sk sk_null_0_value_null sk_1_1_value_1 stack_value_1_stack_value map_lookup_elem_smap_key xskmap_key_xs_queue_id map_lookup_elem_sockmap_key map_lookup_elem_sockhash_key field_bpf_sk_release_sk_1 field_bpf_sk_release_sk_2 ctx_reuseport_array_key_flags reuseport_ctx_sockmap_key_flags reuseport_ctx_sockhash_key_flags of_bpf_skc_to_helpers post_bind4_read_src_ip6 post_bind4_read_mark post_bind6_read_src_ip4 sock_create_read_src_port skb_pull_data2 skb_pull_data1 invalidate_pkt_pointers_from_global_func xdp_pull_data2 xdp_pull_data1 invalidate_xdp_pkt_pointers_from_global_func invalidate_xdp_pkt_pointers tail_call static_tail_call invalidate_pkt_pointers_by_global_tail_call invalidate_pkt_pointers_by_static_tail_call invalidate_pkt_pointers_by_tail_call

use bpf_rs_core::{bpf_map, bpf_object, test_tags};
use core::ffi::c_void;

test_tags! {
    skb_sk_no_null_check:
        __description("skb->sk: no NULL check"),
        __failure,
        __msg("invalid mem access 'sock_common_or_null'"),
        __failure_unpriv;
    sk_family_non_fullsock_field_1:
        __description("skb->sk: sk->family [non fullsock field]"),
        __success,
        __success_unpriv,
        __retval("0");
    sk_rx_queue_mapping_no_sign_ext:
        __description("skb->sk: sk->rx_queue_mapping [no sign extension]"),
        __success,
        __success_unpriv,
        __retval("0");
    sk_rx_queue_mapping_narrow_load_mask:
        __description("skb->sk: sk->rx_queue_mapping [narrow load mask]"),
        __success,
        __success_unpriv,
        __retval("0");
    sk_sk_type_fullsock_field_1:
        __description("skb->sk: sk->type [fullsock field]"),
        __failure,
        __msg("invalid sock_common access"),
        __failure_unpriv;
    sk_no_skb_sk_check_1:
        __description("bpf_sk_fullsock(skb->sk): no !skb->sk check"),
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1"),
        __failure_unpriv;
    no_null_check_on_ret_1:
        __description("sk_fullsock(skb->sk): no NULL check on ret"),
        __failure,
        __msg("invalid mem access 'sock_or_null'"),
        __failure_unpriv;
    sk_sk_type_fullsock_field_2:
        __description("sk_fullsock(skb->sk): sk->type [fullsock field]"),
        __success,
        __success_unpriv,
        __retval("0");
    sk_family_non_fullsock_field_2:
        __description("sk_fullsock(skb->sk): sk->family [non fullsock field]"),
        __success,
        __success_unpriv,
        __retval("0");
    sk_sk_state_narrow_load:
        __description("sk_fullsock(skb->sk): sk->state [narrow load]"),
        __success,
        __success_unpriv,
        __retval("0");
    port_word_load_backward_compatibility:
        __description("sk_fullsock(skb->sk): sk->dst_port [word load] (backward compatibility)"),
        __success,
        __success_unpriv,
        __retval("0");
    sk_dst_port_half_load:
        __description("sk_fullsock(skb->sk): sk->dst_port [half load]"),
        __success,
        __success_unpriv,
        __retval("0");
    dst_port_half_load_invalid_1:
        __description("sk_fullsock(skb->sk): sk->dst_port [half load] (invalid)"),
        __failure,
        __msg("invalid sock access"),
        __failure_unpriv;
    sk_dst_port_byte_load:
        __description("sk_fullsock(skb->sk): sk->dst_port [byte load]"),
        __success,
        __success_unpriv,
        __retval("0");
    dst_port_byte_load_invalid:
        __description("sk_fullsock(skb->sk): sk->dst_port [byte load] (invalid)"),
        __failure,
        __msg("invalid sock access"),
        __failure_unpriv;
    dst_port_half_load_invalid_2:
        __description("sk_fullsock(skb->sk): past sk->dst_port [half load] (invalid)"),
        __failure,
        __msg("invalid sock access"),
        __failure_unpriv;
    dst_ip6_load_2nd_byte:
        __description("sk_fullsock(skb->sk): sk->dst_ip6 [load 2nd byte]"),
        __success,
        __success_unpriv,
        __retval("0");
    sk_sk_type_narrow_load:
        __description("sk_fullsock(skb->sk): sk->type [narrow load]"),
        __success,
        __success_unpriv,
        __retval("0");
    sk_sk_protocol_narrow_load:
        __description("sk_fullsock(skb->sk): sk->protocol [narrow load]"),
        __success,
        __success_unpriv,
        __retval("0");
    skb_sk_beyond_last_field_1:
        __description("sk_fullsock(skb->sk): beyond last field"),
        __failure,
        __msg("invalid sock access"),
        __failure_unpriv;
    sk_no_skb_sk_check_2:
        __description("bpf_tcp_sock(skb->sk): no !skb->sk check"),
        __failure,
        __msg("Possibly NULL pointer passed to trusted R1"),
        __failure_unpriv;
    no_null_check_on_ret_2:
        __description("bpf_tcp_sock(skb->sk): no NULL check on ret"),
        __failure,
        __msg("invalid mem access 'tcp_sock_or_null'"),
        __failure_unpriv;
    skb_sk_tp_snd_cwnd_1:
        __description("bpf_tcp_sock(skb->sk): tp->snd_cwnd"),
        __success,
        __success_unpriv,
        __retval("0");
    skb_sk_tp_bytes_acked:
        __description("bpf_tcp_sock(skb->sk): tp->bytes_acked"),
        __success,
        __success_unpriv,
        __retval("0");
    skb_sk_beyond_last_field_2:
        __description("bpf_tcp_sock(skb->sk): beyond last field"),
        __failure,
        __msg("invalid tcp_sock access"),
        __failure_unpriv;
    skb_sk_tp_snd_cwnd_2:
        __description("bpf_tcp_sock(bpf_sk_fullsock(skb->sk)): tp->snd_cwnd"),
        __success,
        __success_unpriv,
        __retval("0");
    bpf_sk_release_skb_sk:
        __description("bpf_sk_release(skb->sk)"),
        __failure,
        __msg("release function bpf_sk_release expects referenced PTR_TO_BTF_ID passed to R1");
    bpf_sk_fullsock_skb_sk:
        __description("bpf_sk_release(bpf_sk_fullsock(skb->sk))"),
        __failure,
        __msg("release function bpf_sk_release expects referenced PTR_TO_BTF_ID passed to R1");
    bpf_tcp_sock_skb_sk:
        __description("bpf_sk_release(bpf_tcp_sock(skb->sk))"),
        __failure,
        __msg("release function bpf_sk_release expects referenced PTR_TO_BTF_ID passed to R1");
    sk_null_0_value_null:
        __description("sk_storage_get(map, skb->sk, NULL, 0): value == NULL"),
        __success,
        __retval("0");
    sk_1_1_value_1:
        __description("sk_storage_get(map, skb->sk, 1, 1): value == 1"),
        __failure,
        __msg("R3 type=scalar expected=fp");
    stack_value_1_stack_value:
        __description("sk_storage_get(map, skb->sk, &stack_value, 1): stack_value"),
        __success,
        __retval("0");
    map_lookup_elem_smap_key:
        __description("bpf_map_lookup_elem(smap, &key)"),
        __failure,
        __msg("cannot pass map_type 24 into func bpf_map_lookup_elem");
    xskmap_key_xs_queue_id:
        __description("bpf_map_lookup_elem(xskmap, &key); xs->queue_id"),
        __success,
        __retval("0");
    map_lookup_elem_sockmap_key:
        __description("bpf_map_lookup_elem(sockmap, &key)"),
        __failure,
        __msg("Unreleased reference id=2 alloc_insn=6");
    map_lookup_elem_sockhash_key:
        __description("bpf_map_lookup_elem(sockhash, &key)"),
        __failure,
        __msg("Unreleased reference id=2 alloc_insn=6");
    field_bpf_sk_release_sk_1:
        __description("bpf_map_lookup_elem(sockmap, &key); sk->type [fullsock field]; bpf_sk_release(sk)"),
        __success;
    field_bpf_sk_release_sk_2:
        __description("bpf_map_lookup_elem(sockhash, &key); sk->type [fullsock field]; bpf_sk_release(sk)"),
        __success;
    ctx_reuseport_array_key_flags:
        __description("bpf_sk_select_reuseport(ctx, reuseport_array, &key, flags)"),
        __success;
    reuseport_ctx_sockmap_key_flags:
        __description("bpf_sk_select_reuseport(ctx, sockmap, &key, flags)"),
        __success;
    reuseport_ctx_sockhash_key_flags:
        __description("bpf_sk_select_reuseport(ctx, sockhash, &key, flags)"),
        __success;
    of_bpf_skc_to_helpers:
        __description("mark null check on return value of bpf_skc_to helpers"),
        __failure,
        __msg("invalid mem access");
    post_bind4_read_src_ip6:
        __description("sk->src_ip6[0] [load 1st byte]"),
        __failure,
        __msg("invalid bpf_context access off=28 size=2");
    post_bind4_read_mark:
        __description("sk->mark [load mark]"),
        __failure,
        __msg("invalid bpf_context access off=16 size=2");
    post_bind6_read_src_ip4:
        __description("sk->src_ip4 [load src_ip4]"),
        __failure,
        __msg("invalid bpf_context access off=24 size=2");
    sock_create_read_src_port:
        __description("sk->src_port [word load]"),
        __failure,
        __msg("invalid bpf_context access off=44 size=2");
    invalidate_pkt_pointers_from_global_func:
        __failure,
        __msg("invalid mem access");
    invalidate_xdp_pkt_pointers_from_global_func:
        __failure,
        __msg("invalid mem access");
    invalidate_xdp_pkt_pointers:
        __failure,
        __msg("invalid mem access");
    invalidate_pkt_pointers_by_global_tail_call:
        __failure,
        __msg("invalid mem access");
    invalidate_pkt_pointers_by_static_tail_call:
        __failure,
        __msg("invalid mem access");
    invalidate_pkt_pointers_by_tail_call:
        __success;
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
struct xdp_md {
    data: u32,
    data_end: u32,
    data_meta: u32,
    ingress_ifindex: u32,
    rx_queue_index: u32,
    egress_ifindex: u32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
#[derive(Clone, Copy)]
struct val {
    cnt: i32,
    l: bpf_spin_lock,
}

bpf_map! {
    sk_storage_map {
        r#type: *const [i32; 24],
        max_entries: *const [i32; 0],
        key: *const i32,
        value: *const val,
        map_flags: *const [i32; 1],
    }
}

bpf_map! {
    map_xskmap {
        r#type: *const [i32; 17],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i32,
    }
}

bpf_map! {
    map_sockmap {
        r#type: *const [i32; 15],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i32,
    }
}

bpf_map! {
    map_sockhash {
        r#type: *const [i32; 18],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i32,
    }
}

bpf_map! {
    map_reuseport_array {
        r#type: *const [i32; 20],
        max_entries: *const [i32; 1],
        key: *const u32,
        value: *const u64,
    }
}

bpf_map! {
    jmp_table {
        r#type: *const [i32; 3],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

extern "C" {
    fn bpf_xdp_pull_data(a0: *mut c_void, a1: u32) -> i32;
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: skb_sk_no_null_check
extern "C" fn skb_sk_no_null_check() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "r0 = *(u32*)(r1 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_family_non_fullsock_field_1
extern "C" fn sk_family_non_fullsock_field_1() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_0;",
            "r0 = 0;",
            "exit;",
            "l0_0:",
            "r0 = *(u32*)(r1 + 4);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_rx_queue_mapping_no_sign_ext
extern "C" fn sk_rx_queue_mapping_no_sign_ext() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_1;",
            "r0 = 0xdead;",
            "exit;",
            "l0_1:",
            "r0 = *(u32*)(r1 + 76);",
            "r0 >>= 32;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "socket"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_rx_queue_mapping_narrow_load_mask
extern "C" fn sk_rx_queue_mapping_narrow_load_mask() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_2;",
            "r0 = 0xdead;",
            "exit;",
            "l0_2:",
            "r0 = *(u16*)(r1 + 76);",
            "r0 >>= 16;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_sk_type_fullsock_field_1
extern "C" fn sk_sk_type_fullsock_field_1() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_3;",
            "r0 = 0;",
            "exit;",
            "l0_3:",
            "r0 = *(u32*)(r1 + 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_no_skb_sk_check_1
extern "C" fn sk_no_skb_sk_check_1() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "call 95;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_null_check_on_ret_1
extern "C" fn no_null_check_on_ret_1() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_4;",
            "r0 = 0;",
            "exit;",
            "l0_4:",
            "call 95;",
            "r0 = *(u32*)(r0 + 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_sk_type_fullsock_field_2
extern "C" fn sk_sk_type_fullsock_field_2() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_5;",
            "r0 = 0;",
            "exit;",
            "l0_5:",
            "call 95;",
            "if r0 != 0 goto l1_5;",
            "r0 = 0;",
            "exit;",
            "l1_5:",
            "r0 = *(u32*)(r0 + 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_family_non_fullsock_field_2
extern "C" fn sk_family_non_fullsock_field_2() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_6;",
            "r0 = 0;",
            "exit;",
            "l0_6:",
            "call 95;",
            "if r0 != 0 goto l1_6;",
            "exit;",
            "l1_6:",
            "r0 = *(u32*)(r0 + 4);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_sk_state_narrow_load
extern "C" fn sk_sk_state_narrow_load() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_7;",
            "r0 = 0;",
            "exit;",
            "l0_7:",
            "call 95;",
            "if r0 != 0 goto l1_7;",
            "r0 = 0;",
            "exit;",
            "l1_7:",
            "r0 = *(u8*)(r0 + 72);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: port_word_load_backward_compatibility
extern "C" fn port_word_load_backward_compatibility() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_8;",
            "r0 = 0;",
            "exit;",
            "l0_8:",
            "call 95;",
            "if r0 != 0 goto l1_8;",
            "r0 = 0;",
            "exit;",
            "l1_8:",
            "r0 = *(u32*)(r0 + 48);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_dst_port_half_load
extern "C" fn sk_dst_port_half_load() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_9;",
            "r0 = 0;",
            "exit;",
            "l0_9:",
            "call 95;",
            "if r0 != 0 goto l1_9;",
            "r0 = 0;",
            "exit;",
            "l1_9:",
            "r0 = *(u16*)(r0 + 48);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dst_port_half_load_invalid_1
extern "C" fn dst_port_half_load_invalid_1() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_10;",
            "r0 = 0;",
            "exit;",
            "l0_10:",
            "call 95;",
            "if r0 != 0 goto l1_10;",
            "r0 = 0;",
            "exit;",
            "l1_10:",
            "r0 = *(u16*)(r0 + 50);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_dst_port_byte_load
extern "C" fn sk_dst_port_byte_load() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_11;",
            "r0 = 0;",
            "exit;",
            "l0_11:",
            "call 95;",
            "if r0 != 0 goto l1_11;",
            "r0 = 0;",
            "exit;",
            "l1_11:",
            "r2 = *(u8*)(r0 + 48);",
            "r2 = *(u8*)(r0 + 49);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dst_port_byte_load_invalid
extern "C" fn dst_port_byte_load_invalid() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_12;",
            "r0 = 0;",
            "exit;",
            "l0_12:",
            "call 95;",
            "if r0 != 0 goto l1_12;",
            "r0 = 0;",
            "exit;",
            "l1_12:",
            "r0 = *(u8*)(r0 + 50);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dst_port_half_load_invalid_2
extern "C" fn dst_port_half_load_invalid_2() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_13;",
            "r0 = 0;",
            "exit;",
            "l0_13:",
            "call 95;",
            "if r0 != 0 goto l1_13;",
            "r0 = 0;",
            "exit;",
            "l1_13:",
            "r0 = *(u16*)(r0 + 50);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: dst_ip6_load_2nd_byte
extern "C" fn dst_ip6_load_2nd_byte() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_14;",
            "r0 = 0;",
            "exit;",
            "l0_14:",
            "call 95;",
            "if r0 != 0 goto l1_14;",
            "r0 = 0;",
            "exit;",
            "l1_14:",
            "r0 = *(u8*)(r0 + 57);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_sk_type_narrow_load
extern "C" fn sk_sk_type_narrow_load() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_15;",
            "r0 = 0;",
            "exit;",
            "l0_15:",
            "call 95;",
            "if r0 != 0 goto l1_15;",
            "r0 = 0;",
            "exit;",
            "l1_15:",
            "r0 = *(u8*)(r0 + 8);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_sk_protocol_narrow_load
extern "C" fn sk_sk_protocol_narrow_load() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_16;",
            "r0 = 0;",
            "exit;",
            "l0_16:",
            "call 95;",
            "if r0 != 0 goto l1_16;",
            "r0 = 0;",
            "exit;",
            "l1_16:",
            "r0 = *(u8*)(r0 + 12);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: skb_sk_beyond_last_field_1
extern "C" fn skb_sk_beyond_last_field_1() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_17;",
            "r0 = 0;",
            "exit;",
            "l0_17:",
            "call 95;",
            "if r0 != 0 goto l1_17;",
            "r0 = 0;",
            "exit;",
            "l1_17:",
            "r0 = *(u32*)(r0 + 80);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_no_skb_sk_check_2
extern "C" fn sk_no_skb_sk_check_2() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "call 96;",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: no_null_check_on_ret_2
extern "C" fn no_null_check_on_ret_2() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_18;",
            "r0 = 0;",
            "exit;",
            "l0_18:",
            "call 96;",
            "r0 = *(u32*)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: skb_sk_tp_snd_cwnd_1
extern "C" fn skb_sk_tp_snd_cwnd_1() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_19;",
            "r0 = 0;",
            "exit;",
            "l0_19:",
            "call 96;",
            "if r0 != 0 goto l1_19;",
            "exit;",
            "l1_19:",
            "r0 = *(u32*)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: skb_sk_tp_bytes_acked
extern "C" fn skb_sk_tp_bytes_acked() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_20;",
            "r0 = 0;",
            "exit;",
            "l0_20:",
            "call 96;",
            "if r0 != 0 goto l1_20;",
            "exit;",
            "l1_20:",
            "r0 = *(u64*)(r0 + 88);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: skb_sk_beyond_last_field_2
extern "C" fn skb_sk_beyond_last_field_2() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_21;",
            "r0 = 0;",
            "exit;",
            "l0_21:",
            "call 96;",
            "if r0 != 0 goto l1_21;",
            "exit;",
            "l1_21:",
            "r0 = *(u64*)(r0 + 96);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: skb_sk_tp_snd_cwnd_2
extern "C" fn skb_sk_tp_snd_cwnd_2() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_22;",
            "r0 = 0;",
            "exit;",
            "l0_22:",
            "call 95;",
            "if r0 != 0 goto l1_22;",
            "exit;",
            "l1_22:",
            "r1 = r0;",
            "call 96;",
            "if r0 != 0 goto l2_22;",
            "exit;",
            "l2_22:",
            "r0 = *(u32*)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_sk_release_skb_sk
extern "C" fn bpf_sk_release_skb_sk() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 == 0 goto l0_23;",
            "call 86;",
            "l0_23:",
            "r0 = 0;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_sk_fullsock_skb_sk
extern "C" fn bpf_sk_fullsock_skb_sk() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_24;",
            "r0 = 0;",
            "exit;",
            "l0_24:",
            "call 95;",
            "if r0 != 0 goto l1_24;",
            "exit;",
            "l1_24:",
            "r1 = r0;",
            "call 86;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: bpf_tcp_sock_skb_sk
extern "C" fn bpf_tcp_sock_skb_sk() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_25;",
            "r0 = 0;",
            "exit;",
            "l0_25:",
            "call 96;",
            "if r0 != 0 goto l1_25;",
            "exit;",
            "l1_25:",
            "r1 = r0;",
            "call 86;",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_null_0_value_null
extern "C" fn sk_null_0_value_null() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_26;",
            "r0 = 0;",
            "exit;",
            "l0_26:",
            "call 95;",
            "if r0 != 0 goto l1_26;",
            "r0 = 0;",
            "exit;",
            "l1_26:",
            "r4 = 0;",
            "r3 = 0;",
            "r2 = r0;",
            "r1 = {sk_storage_map} ll;",
            "call 107;",
            "r0 = 0;",
            "exit;",
            sk_storage_map = sym sk_storage_map,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sk_1_1_value_1
extern "C" fn sk_1_1_value_1() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_27;",
            "r0 = 0;",
            "exit;",
            "l0_27:",
            "call 95;",
            "if r0 != 0 goto l1_27;",
            "r0 = 0;",
            "exit;",
            "l1_27:",
            "r4 = 1;",
            "r3 = 1;",
            "r2 = r0;",
            "r1 = {sk_storage_map} ll;",
            "call 107;",
            "r0 = 0;",
            "exit;",
            sk_storage_map = sym sk_storage_map,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: stack_value_1_stack_value
extern "C" fn stack_value_1_stack_value() {
    unsafe {
        core::arch::asm!(
            "r2 = 0;",
            "*(u64*)(r10 - 8) = r2;",
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_28;",
            "r0 = 0;",
            "exit;",
            "l0_28:",
            "call 95;",
            "if r0 != 0 goto l1_28;",
            "r0 = 0;",
            "exit;",
            "l1_28:",
            "r4 = 1;",
            "r3 = r10;",
            "r3 += -8;",
            "r2 = r0;",
            "r1 = {sk_storage_map} ll;",
            "call 107;",
            "r0 = 0;",
            "exit;",
            sk_storage_map = sym sk_storage_map,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_lookup_elem_smap_key
extern "C" fn map_lookup_elem_smap_key() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {sk_storage_map} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            sk_storage_map = sym sk_storage_map,
            options(nostack)
        );
    }
}

#[link_section = "xdp"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: xskmap_key_xs_queue_id
extern "C" fn xskmap_key_xs_queue_id() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 8) = r1;",
            "r2 = r10;",
            "r2 += -8;",
            "r1 = {map_xskmap} ll;",
            "call 1;",
            "if r0 != 0 goto l0_29;",
            "exit;",
            "l0_29:",
            "r0 = *(u32*)(r0 + 0);",
            "r0 = 0;",
            "exit;",
            map_xskmap = sym map_xskmap,
            options(nostack)
        );
    }
}

#[link_section = "sk_skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_lookup_elem_sockmap_key
extern "C" fn map_lookup_elem_sockmap_key() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_sockmap} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_sockmap = sym map_sockmap,
            options(nostack)
        );
    }
}

#[link_section = "sk_skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: map_lookup_elem_sockhash_key
extern "C" fn map_lookup_elem_sockhash_key() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_sockhash} ll;",
            "call 1;",
            "r0 = 0;",
            "exit;",
            map_sockhash = sym map_sockhash,
            options(nostack)
        );
    }
}

#[link_section = "sk_skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: field_bpf_sk_release_sk_1
extern "C" fn field_bpf_sk_release_sk_1() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_sockmap} ll;",
            "call 1;",
            "if r0 != 0 goto l0_30;",
            "exit;",
            "l0_30:",
            "r1 = r0;",
            "r0 = *(u32*)(r0 + 8);",
            "call 86;",
            "exit;",
            map_sockmap = sym map_sockmap,
            options(nostack)
        );
    }
}

#[link_section = "sk_skb"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: field_bpf_sk_release_sk_2
extern "C" fn field_bpf_sk_release_sk_2() {
    unsafe {
        core::arch::asm!(
            "r1 = 0;",
            "*(u32*)(r10 - 4) = r1;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {map_sockhash} ll;",
            "call 1;",
            "if r0 != 0 goto l0_31;",
            "exit;",
            "l0_31:",
            "r1 = r0;",
            "r0 = *(u32*)(r0 + 8);",
            "call 86;",
            "exit;",
            map_sockhash = sym map_sockhash,
            options(nostack)
        );
    }
}

#[link_section = "sk_reuseport"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: ctx_reuseport_array_key_flags
extern "C" fn ctx_reuseport_array_key_flags() {
    unsafe {
        core::arch::asm!(
            "r4 = 0;",
            "r2 = 0;",
            "*(u32*)(r10 - 4) = r2;",
            "r3 = r10;",
            "r3 += -4;",
            "r2 = {map_reuseport_array} ll;",
            "call 82;",
            "exit;",
            map_reuseport_array = sym map_reuseport_array,
            options(nostack)
        );
    }
}

#[link_section = "sk_reuseport"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reuseport_ctx_sockmap_key_flags
extern "C" fn reuseport_ctx_sockmap_key_flags() {
    unsafe {
        core::arch::asm!(
            "r4 = 0;",
            "r2 = 0;",
            "*(u32*)(r10 - 4) = r2;",
            "r3 = r10;",
            "r3 += -4;",
            "r2 = {map_sockmap} ll;",
            "call 82;",
            "exit;",
            map_sockmap = sym map_sockmap,
            options(nostack)
        );
    }
}

#[link_section = "sk_reuseport"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reuseport_ctx_sockhash_key_flags
extern "C" fn reuseport_ctx_sockhash_key_flags() {
    unsafe {
        core::arch::asm!(
            "r4 = 0;",
            "r2 = 0;",
            "*(u32*)(r10 - 4) = r2;",
            "r3 = r10;",
            "r3 += -4;",
            "r2 = {map_sockmap} ll;",
            "call 82;",
            "exit;",
            map_sockmap = sym map_sockmap,
            options(nostack)
        );
    }
}

#[link_section = "tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: of_bpf_skc_to_helpers
extern "C" fn of_bpf_skc_to_helpers() {
    unsafe {
        core::arch::asm!(
            "r1 = *(u64*)(r1 + 168);",
            "if r1 != 0 goto l0_32;",
            "r0 = 0;",
            "exit;",
            "l0_32:",
            "r6 = r1;",
            "call 137;",
            "r7 = r0;",
            "r1 = r6;",
            "call 139;",
            "r8 = r0;",
            "if r8 != 0 goto l1_32;",
            "r0 = 0;",
            "exit;",
            "l1_32:",
            "r0 = *(u8*)(r7 + 0);",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/post_bind4"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_bind4_read_src_ip6
extern "C" fn post_bind4_read_src_ip6() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = *(u16*)(r6 + 28);",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/post_bind4"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_bind4_read_mark
extern "C" fn post_bind4_read_mark() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = *(u16*)(r6 + 16);",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/post_bind6"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: post_bind6_read_src_ip4
extern "C" fn post_bind6_read_src_ip4() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = *(u16*)(r6 + 24);",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

#[link_section = "cgroup/sock_create"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: sock_create_read_src_port
extern "C" fn sock_create_read_src_port() {
    unsafe {
        core::arch::asm!(
            "r6 = r1;",
            "r7 = *(u16*)(r6 + 44);",
            "r0 = 1;",
            "exit;",
            options(nostack)
        );
    }
}

include!("hand/verifier_sock.rs");

bpf_object!("GPL");
