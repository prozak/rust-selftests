// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tcp_autolowat.c
// (bpf-rs-core idiom). A struct bpf_tcp_ops instance parses RPC descriptors
// (header and payload lengths) out of every skb queued to the receive queue
// through a dynptr, tracks the sequence where the next descriptor starts in
// the socket's storage element, and sets SO_RCVLOWAT so that the reader
// wakes up once a whole RPC has arrived; the cgroup/setsockopt program turns
// it on for a socket through a private option. prog_tests/tcp_autolowat.c
// drives sends and recvs and checks the rcvlowat the kernel reports;
// test_name is the subtest's name, a C `char` array the test writes.
// bpf_core_cast() is bpf_rdonly_cast with the kernel type id; the LOG()
// macro of the C expands to nothing (DEBUG is not defined).
// BTF_C_CHAR: u8
// BTF_TYPE_ID: tid_tcp_skb_cb struct tcp_skb_cb
// BTF_TYPE_ID: tid_tcp_sock struct tcp_sock

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_dynptr_read, bpf_sk_storage_get, bpf_tcp_sock};
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

const SOL_BPF: i32 = 0xdeadbeefu32 as i32;
const BPF_TCP_AUTOLOWAT: i32 = 0x8badf00du32 as i32;
const BPF_TCP_OPS_FLAG_RCVQ: u32 = 16;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;
const TCPHDR_FIN: u16 = 0x01;
const INT_MAX: u64 = 0x7fffffff;

const RPC_DESC_SIZE: u32 = 8; // sizeof(struct rpc_descriptor)
const MAX_RPC_DESC_PER_SKB: i32 = 100;

#[allow(non_camel_case_types)]
#[repr(C)]
struct rpc_descriptor {
    header_len: u32,
    payload_len: u32,
}

// the map value: only ever reached through the storage element's pointer
// translint: allow(padding)
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_autolowat_cb {
    /* Don't put this field at the end; BPF verifier complains. */
    rpc_desc_buf: [u8; RPC_DESC_SIZE as usize],
    rpc_desc_seq: u32,
    rpc_end_seq: u32,
    rpc_desc_buff_len: u8,
}

bpf_map! {
    tcp_autolowat_map {
        r#type: *const [i32; 24],   // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const tcp_autolowat_cb,
    }
}

#[no_mangle]
static mut test_name: [u8; 64] = [0; 64];

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

/// UAPI struct bpf_sockopt (linux/bpf.h). sk/optval/optval_end are
/// __bpf_md_ptr unions, represented as u64.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sockopt {
    pub sk: u64,
    pub optval: u64,
    pub optval_end: u64,
    pub level: i32,
    pub optname: i32,
    pub optlen: i32,
    pub retval: i32,
}

#[btf]
struct sock {
    sk_rcvlowat: i32,
}

#[btf]
struct inet_sock {
    sk: sock,
}

#[btf]
struct inet_connection_sock {
    icsk_inet: inet_sock,
}

#[btf]
struct tcp_sock {
    inet_conn: inet_connection_sock,
    copied_seq: u32,
}

#[btf]
struct sk_buff {
    cb: [u8; 48],
}

#[btf]
struct tcp_skb_cb {
    seq: u32,
    end_seq: u32,
    tcp_flags: u16,
}

extern "C" {
    fn tid_tcp_skb_cb() -> u64;
    fn tid_tcp_sock() -> u64;
    fn bpf_rdonly_cast(obj: *const c_void, btf_id: u32) -> *mut c_void;
    fn bpf_dynptr_from_skb(skb: *mut c_void, flags: u64, ptr__uninit: *mut bpf_dynptr) -> i32;
    fn bpf_tcp_ops_set_flags(tp: *mut c_void, enable: u32, disable: u32) -> i32;
    fn bpf_tcp_ops_set_rcvlowat(sk: *mut c_void, rcvlowat: i32) -> i32;
}

#[inline(always)]
fn before(seq1: u32, seq2: u32) -> bool {
    (seq1.wrapping_sub(seq2) as i32) < 0
}

#[inline(always)]
fn after(seq2: u32, seq1: u32) -> bool {
    before(seq1, seq2)
}

/// 0 = a whole descriptor is in the buffer, 1 = partial, -1 = disable
#[inline(always)]
unsafe fn tcp_parse_descriptor(cb: *mut tcp_autolowat_cb, dptr: *mut bpf_dynptr, seq: u32, end_seq: u32) -> i32 {
    let rpc_copied_seq: u32 = (*cb).rpc_desc_seq.wrapping_add((*cb).rpc_desc_buff_len as u32);

    let copy_len: u64; /* u32 should work, but not for no_alu32 :/ */
    if before((*cb).rpc_desc_seq.wrapping_add(RPC_DESC_SIZE), end_seq) {
        copy_len = (RPC_DESC_SIZE - (*cb).rpc_desc_buff_len as u32) as u64;
    } else {
        copy_len = end_seq.wrapping_sub(rpc_copied_seq) as u64;
    }

    if copy_len == 0 {
        return -1; /* FIN. */
    }
    if copy_len > RPC_DESC_SIZE as u64 {
        return -1; /* always false, only for verifier. */
    }
    if (*cb).rpc_desc_buff_len as u32 >= RPC_DESC_SIZE {
        return -1; /* always false, only for verifier. */
    }

    let err = bpf_dynptr_read(
        (addr_of_mut!((*cb).rpc_desc_buf) as *mut u8).add((*cb).rpc_desc_buff_len as usize) as *mut c_void,
        copy_len,
        dptr,
        rpc_copied_seq.wrapping_sub(seq) as u64,
        0,
    );
    if err != 0 {
        return -1;
    }

    (*cb).rpc_desc_buff_len = (*cb).rpc_desc_buff_len.wrapping_add(copy_len as u8);

    if (*cb).rpc_desc_buff_len as u32 != RPC_DESC_SIZE {
        return 1;
    }

    let rpc_desc = addr_of_mut!((*cb).rpc_desc_buf) as *const rpc_descriptor;
    let rpc_len: u64 =
        RPC_DESC_SIZE as u64 + (*rpc_desc).header_len as u64 + (*rpc_desc).payload_len as u64;

    if rpc_len > INT_MAX {
        return -1;
    }

    (*cb).rpc_end_seq = (*cb).rpc_desc_seq.wrapping_add(rpc_len as u32);

    0
}

#[inline(always)]
unsafe fn tcp_set_autolowat(cb: *mut tcp_autolowat_cb, sk: *mut c_void) {
    let tp = sk as *const tcp_sock;
    let copied_seq = *(&*tp).copied_seq().as_ptr();
    let val: u32; /* To handle wraparound. */

    if before(copied_seq, (*cb).rpc_desc_seq) {
        val = (*cb).rpc_desc_seq.wrapping_sub(copied_seq);
    } else if (*cb).rpc_desc_buff_len as u32 != RPC_DESC_SIZE {
        val = RPC_DESC_SIZE;
    } else {
        val = (*cb).rpc_end_seq.wrapping_sub(copied_seq);
    }

    if val != *(&*tp).inet_conn().icsk_inet().sk().sk_rcvlowat().as_ptr() as u32 {
        bpf_tcp_ops_set_rcvlowat(sk, val as i32);
    }
}

#[inline(always)]
unsafe fn tcp_disable_autolowat(sk: *mut c_void) {
    bpf_tcp_ops_set_flags(sk, 0, BPF_TCP_OPS_FLAG_RCVQ);

    bpf_tcp_ops_set_rcvlowat(sk, 1);
}

#[inline(always)]
unsafe fn tcp_do_autolowat(cb: *mut tcp_autolowat_cb, sk: *mut c_void, skb: *mut sk_buff) {
    let mut dptr = MaybeUninit::<bpf_dynptr>::uninit();

    let ret: i32 = 'update: {
        if bpf_dynptr_from_skb(skb as *mut c_void, 0, dptr.as_mut_ptr()) != 0 {
            break 'update -1;
        }

        let tcb = bpf_rdonly_cast((&*skb).cb().as_ptr() as *const c_void, tid_tcp_skb_cb() as u32)
            as *const tcp_skb_cb;
        let seq = *(&*tcb).seq().as_ptr();
        let end_seq = (*(&*tcb).end_seq().as_ptr())
            .wrapping_sub(((*(&*tcb).tcp_flags().as_ptr() & TCPHDR_FIN) != 0) as u32);

        if (*cb).rpc_desc_buff_len as u32 != RPC_DESC_SIZE {
            let ret = tcp_parse_descriptor(cb, dptr.as_mut_ptr(), seq, end_seq);
            if ret != 0 {
                break 'update ret;
            }
        }

        let mut i: i32 = 0;
        let mut ret: i32 = 0;

        loop {
            let n = i;
            i += 1;
            if n > MAX_RPC_DESC_PER_SKB {
                ret = -1;
                break;
            }

            if after((*cb).rpc_end_seq, end_seq) {
                break;
            }

            (*cb).rpc_desc_seq = (*cb).rpc_end_seq;
            (*cb).rpc_desc_buff_len = 0;

            if (*cb).rpc_end_seq == end_seq {
                break;
            }

            ret = tcp_parse_descriptor(cb, dptr.as_mut_ptr(), seq, end_seq);
            if ret != 0 {
                break;
            }
        }
        ret
    };

    if ret >= 0 {
        tcp_set_autolowat(cb, sk);
    } else {
        tcp_disable_autolowat(sk);
    }
}

// BPF_PROG(tcp_autolowat_enqueue_rcvq, struct sock *sk, struct sk_buff *skb)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn tcp_autolowat_enqueue_rcvq(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;
    let skb = arg(ctx, 1) as *mut sk_buff;

    let cb = bpf_sk_storage_get(&tcp_autolowat_map, sk, core::ptr::null(), 0) as *mut tcp_autolowat_cb;
    if cb.is_null() {
        return;
    }

    unsafe { tcp_do_autolowat(cb, sk, skb) };
}

// BPF_PROG(tcp_autolowat_dequeue_rcvq, struct sock *sk)
#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn tcp_autolowat_dequeue_rcvq(ctx: *const u64) {
    let sk = arg(ctx, 0) as *mut c_void;

    let cb = bpf_sk_storage_get(&tcp_autolowat_map, sk, core::ptr::null(), 0) as *mut tcp_autolowat_cb;
    if cb.is_null() {
        return;
    }

    unsafe { tcp_set_autolowat(cb, sk) };
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_tcp_ops {
    enqueue_rcvq: extern "C" fn(*const u64),
    dequeue_rcvq: extern "C" fn(*const u64),
}

unsafe impl Sync for bpf_tcp_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static tcp_autolowat_ops: bpf_tcp_ops = bpf_tcp_ops {
    enqueue_rcvq: tcp_autolowat_enqueue_rcvq,
    dequeue_rcvq: tcp_autolowat_dequeue_rcvq,
};

#[inline(always)]
unsafe fn tcp_init_autolowat_cb(btp: *mut c_void) -> i32 {
    let cb = bpf_sk_storage_get(&tcp_autolowat_map, btp, core::ptr::null(), BPF_SK_STORAGE_GET_F_CREATE)
        as *mut tcp_autolowat_cb;
    if cb.is_null() {
        return -1;
    }

    let tp = bpf_rdonly_cast(btp, tid_tcp_sock() as u32) as *const tcp_sock;

    let copied_seq = *(&*tp).copied_seq().as_ptr();
    (*cb).rpc_desc_seq = copied_seq;
    (*cb).rpc_end_seq = copied_seq;

    bpf_tcp_ops_set_flags(btp, BPF_TCP_OPS_FLAG_RCVQ, 0)
}

#[link_section = "cgroup/setsockopt"]
#[no_mangle]
extern "C" fn tcp_autolowat_setsockopt(ctx: *mut bpf_sockopt) -> i32 {
    unsafe {
        let optval_end = (*ctx).optval_end as *mut u8;
        let optval = (*ctx).optval as *mut i32;

        if (*ctx).level != SOL_BPF || (*ctx).optname != BPF_TCP_AUTOLOWAT {
            return 1;
        }

        if (optval.add(1) as *mut u8) > optval_end {
            return 0; /* -EPERM */
        }

        let btp = bpf_tcp_sock((*ctx).sk as *const c_void);
        if btp.is_null() {
            return 1;
        }

        if *optval != 0 && tcp_init_autolowat_cb(btp) != 0 {
            return 0; /* -EPERM */
        }

        /*
         * BPF has consumed this option, don't call kernel
         * setsockopt handler.
         */
        (*ctx).optlen = -1;
    }
    1
}

bpf_object!("GPL");
