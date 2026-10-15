// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgroup_ancestor.c
// (bpf-rs-core idiom).
//
// bpf_core_cast(sk, struct sock) is bpf_rdonly_cast(sk,
// bpf_core_type_id_kernel(struct sock)); the type id is the BTF_TYPE_ID
// declaration below (scripts/type_id.py).

// BTF_TYPE_ID: tid_sock struct sock

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::{__sk_buff, TC_ACT_OK};
use bpf_rs_core::helpers::bpf_skb_ancestor_cgroup_id;
use bpf_rs_core::vload;
use btf_macros::btf;
use core::ffi::c_void;

const NUM_CGROUP_LEVELS: usize = 4;
const IPPROTO_UDP: u16 = 17;

#[no_mangle]
static mut cgroup_ids: [u64; NUM_CGROUP_LEVELS] = [0; NUM_CGROUP_LEVELS];

#[no_mangle]
static mut dport: u16 = 0;

// Local CO-RE views of struct sock and struct sock_common (include/net/
// sock.h): only the fields this program reads, matched by name against the
// kernel's structs. sk_dport is sock.h's #define for __sk_common.skc_dport.
#[btf]
struct sock_common {
    skc_dport: u16,
}

#[btf]
struct sock {
    __sk_common: sock_common,
    sk_protocol: u16,
}

extern "C" {
    fn bpf_rdonly_cast(obj: *const c_void, btf_id: u32) -> *mut c_void;
    fn tid_sock() -> u64;
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

    let sk = unsafe { bpf_rdonly_cast(sk_raw as *const c_void, tid_sock() as u32) }
        as *const sock;
    let sk_view = unsafe { &*sk };
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
