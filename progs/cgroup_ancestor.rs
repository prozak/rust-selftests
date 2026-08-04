#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgroup_ancestor.c
// (bpf-rs-core idiom).
//
// The C original does `sk = bpf_core_cast(sk, struct sock)` on skb->sk (a
// `bpf_core_type_id_kernel(struct sock)` TYPE_ID CO-RE relocation) to read
// sk_protocol/sk_dport. This pipeline's field_reloc pass only emits
// FIELD_BYTE_OFFSET/FIELD_EXISTS relocations, not TYPE_ID (see
// recvmsg_unix_prog.rs, tcp_ca_untrusted_btf_write.rs), so that specific cast
// can't be reproduced. Instead, `bpf_skc_to_udp6_sock()` (a plain helper
// call, BPF_FUNC id 140, available to SEC("tc") via tc_cls_act_func_proto's
// fallback to bpf_sk_base_func_proto) narrows the ctx's
// PTR_TO_SOCK_COMMON_OR_NULL `sk` to a real PTR_TO_BTF_ID for
// `struct udp6_sock` -- the kernel helper itself already requires
// sk_fullsock(sk) && sk->sk_protocol == IPPROTO_UDP && sk->sk_type ==
// SOCK_DGRAM && sk->sk_family == AF_INET6, which is exactly the traffic this
// test's userspace side sends (`::1` SOCK_DGRAM). The returned pointer is a
// real kernel struct address, so ordinary `#[btf]` byte-offset field
// relocations reach sk_protocol/sk_dport through the real nesting
// (udp6_sock.udp.inet.sk.{sk_protocol,__sk_common.skc_dport}) exactly like
// C's `container_of` chain in tcp_ca_incompl_cong_ops.rs.

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK};
use bpf_rs_core::helpers::{bpf_skb_ancestor_cgroup_id, bpf_skc_to_udp6_sock};
use bpf_rs_core::vload;
use btf_macros::btf;
use core::ffi::c_void;

const NUM_CGROUP_LEVELS: usize = 4;
const IPPROTO_UDP: u16 = 17;

#[no_mangle]
static mut cgroup_ids: [u64; NUM_CGROUP_LEVELS] = [0; NUM_CGROUP_LEVELS];

#[no_mangle]
static mut dport: u16 = 0;

// Minimal local BTF views of the real kernel nesting chain
// (include/net/sock.h, include/net/inet_sock.h, include/linux/udp.h,
// include/linux/ipv6.h): only the fields/links this program touches. CO-RE
// field-byte-offset relocation matches these by name against the target
// kernel's real structs, walking through skc_dport's anonymous union in
// sock_common the same way bpf_iter_netlink.rs's sk_backlog.rmem_alloc walks
// through an anonymous struct.
#[btf]
struct sock_common {
    skc_dport: u16,
}

#[btf]
struct sock {
    __sk_common: sock_common,
    sk_protocol: u16,
}

#[btf]
struct inet_sock {
    sk: sock,
}

#[btf]
struct udp_sock {
    inet: inet_sock,
}

#[btf]
struct udp6_sock {
    udp: udp_sock,
}

#[inline(always)]
fn log_nth_level(skb: *const __sk_buff, level: u32) {
    let id = bpf_skb_ancestor_cgroup_id(skb as *const c_void, level as i32);
    unsafe {
        let base = core::ptr::addr_of_mut!(cgroup_ids) as *mut u64;
        base.add(level as usize).write(id);
    }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn log_cgroup_id(skb: *const __sk_buff) -> i32 {
    let sk_raw = vload!((*skb).sk);
    if sk_raw == 0 {
        return TC_ACT_OK;
    }

    let usk = bpf_skc_to_udp6_sock(sk_raw as *mut c_void) as *const udp6_sock;
    if usk.is_null() {
        return TC_ACT_OK;
    }

    let sk_view = unsafe { &*usk }.udp().inet().sk();
    let protocol = unsafe { *sk_view.sk_protocol().as_ptr() };
    let sk_dport = unsafe { *sk_view.__sk_common().skc_dport().as_ptr() };

    if protocol == IPPROTO_UDP && sk_dport == unsafe { dport } {
        log_nth_level(skb, 0);
        log_nth_level(skb, 1);
        log_nth_level(skb, 2);
        log_nth_level(skb, 3);
    }

    TC_ACT_OK
}

bpf_object!("GPL");
