#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/mptcp_sock.c
// (bpf-rs-core idiom).
//
// `struct bpf_sock_ops` isn't provided by bpf_rs_core::ctx, so it is hand
// declared here with the exact UAPI field order/types (linux/bpf.h) -- the
// kernel's sock_ops_convert_ctx_access() rewrites ctx loads by hardcoded
// byte offset, so the local layout must reproduce the real struct's offsets
// for `op` and `sk` exactly (same reasoning as ctx.rs's __sk_buff).
//
// tsk->is_mptcp mirrors bpf_core_field_exists(tsk->is_mptcp) via the #[btf]
// view's `.exists()` terminal (a real field_exists CO-RE relocation,
// distinct from `.as_ptr()`'s byte_offset relocation) before reading it,
// same ternary shape as the C source.
//
// ca_name is bulk-read via bpf_probe_read_kernel into a stack buffer, then
// stored into the map value with a byte-at-a-time volatile loop -- a plain
// array assignment/`copy_nonoverlapping` here gets recognized by MemCpyOpt
// and rewritten to an unresolvable `bpf_arena_memcpy` kfunc call (same
// precedent as type_cast.rs's `name` field and the memset-shaped zeroing
// below).

use bpf_rs_core::helpers::{
    bpf_probe_read_kernel, bpf_sk_storage_get, bpf_skc_to_mptcp_sock, bpf_skc_to_tcp_sock,
};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object, vload};
use btf_macros::btf;
use core::ffi::c_void;

// enum bpf_map_type: BPF_MAP_TYPE_SK_STORAGE.
const BPF_MAP_TYPE_SK_STORAGE: usize = 24;
// enum: BPF_F_NO_PREALLOC.
const BPF_F_NO_PREALLOC: usize = 1;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;
// enum (uapi/linux/bpf.h sock_ops op list): BPF_SOCK_OPS_TCP_CONNECT_CB.
const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 3;

const TCP_CA_NAME_MAX: usize = 16;

/// UAPI struct bpf_sock_ops (linux/bpf.h), full layout through
/// skb_hwtstamp. The `args`/`reply`/`replylong` anonymous union is
/// represented by its widest member's storage; this program never touches
/// it, only its size/alignment matter for keeping later offsets aligned.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock_ops {
    pub op: u32,
    pub reply_union: [u32; 4],
    pub family: u32,
    pub remote_ip4: u32,
    pub local_ip4: u32,
    pub remote_ip6: [u32; 4],
    pub local_ip6: [u32; 4],
    pub remote_port: u32,
    pub local_port: u32,
    pub is_fullsock: u32,
    pub snd_cwnd: u32,
    pub srtt_us: u32,
    pub bpf_sock_ops_cb_flags: u32,
    pub state: u32,
    pub rtt_min: u32,
    pub snd_ssthresh: u32,
    pub rcv_nxt: u32,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub mss_cache: u32,
    pub ecn_flags: u32,
    pub rate_delivered: u32,
    pub rate_interval_us: u32,
    pub packets_out: u32,
    pub retrans_out: u32,
    pub total_retrans: u32,
    pub segs_in: u32,
    pub data_segs_in: u32,
    pub segs_out: u32,
    pub data_segs_out: u32,
    pub lost_out: u32,
    pub sacked_out: u32,
    pub sk_txhash: u32,
    pub bytes_received: u64,
    pub bytes_acked: u64,
    pub sk: u64,
    pub skb_data: u64,
    pub skb_data_end: u64,
    pub skb_len: u32,
    pub skb_tcp_flags: u32,
    pub skb_hwtstamp: u64,
}

// Opaque CO-RE chase target for mptcp_sock's `first` field -- never walked
// further, only its address is copied, same "empty terminal" pattern as
// bpf_iter_bpf_sk_storage_map.rs's `sock`.
#[btf]
struct sock {}

#[btf]
struct tcp_sock {
    is_mptcp: bool,
}

#[btf]
struct mptcp_sock {
    token: u32,
    first: *mut sock,
    ca_name: [u8; TCP_CA_NAME_MAX],
}

#[repr(C)]
struct mptcp_storage {
    invoked: u32,
    is_mptcp: u32,
    sk: *mut c_void,
    token: u32,
    first: *mut c_void,
    ca_name: [u8; TCP_CA_NAME_MAX],
}

bpf_map! {
    socket_storage_map {
        r#type: *const [i32; BPF_MAP_TYPE_SK_STORAGE],
        map_flags: *const [i32; BPF_F_NO_PREALLOC],
        key: *const i32,
        value: *const mptcp_storage,
    }
}

#[no_mangle]
static mut token: u32 = 0;

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn _sockops(ctx: *mut bpf_sock_ops) -> i32 {
    let op = vload!((*ctx).op);
    if op != BPF_SOCK_OPS_TCP_CONNECT_CB {
        return 1;
    }

    let sk = vload!((*ctx).sk) as *mut c_void;
    if sk.is_null() {
        return 1;
    }

    let tsk = bpf_skc_to_tcp_sock(sk as *const c_void) as *mut tcp_sock;
    if tsk.is_null() {
        return 1;
    }
    let tsk_ref = unsafe { &*tsk };

    let is_mptcp = if tsk_ref.is_mptcp().exists() {
        unsafe { *tsk_ref.is_mptcp().as_ptr() }
    } else {
        false
    };

    let storage: *mut mptcp_storage;

    if !is_mptcp {
        storage = bpf_sk_storage_get(
            &socket_storage_map,
            sk,
            core::ptr::null(),
            BPF_SK_STORAGE_GET_F_CREATE,
        ) as *mut mptcp_storage;
        if storage.is_null() {
            return 1;
        }

        unsafe {
            (*storage).token = 0;
            let dst = core::ptr::addr_of_mut!((*storage).ca_name) as *mut u8;
            for i in 0..TCP_CA_NAME_MAX {
                core::ptr::write_volatile(dst.add(i), 0u8);
            }
            (*storage).first = core::ptr::null_mut();
        }
    } else {
        let msk = bpf_skc_to_mptcp_sock(sk as *const c_void) as *mut mptcp_sock;
        if msk.is_null() {
            return 1;
        }
        let msk_ref = unsafe { &*msk };

        storage = bpf_sk_storage_get(
            &socket_storage_map,
            msk as *const c_void,
            core::ptr::null(),
            BPF_SK_STORAGE_GET_F_CREATE,
        ) as *mut mptcp_storage;
        if storage.is_null() {
            return 1;
        }

        let token_val = unsafe { *msk_ref.token().as_ptr() };

        let mut ca_name_buf: [u8; TCP_CA_NAME_MAX] = [0; TCP_CA_NAME_MAX];
        bpf_probe_read_kernel(
            &mut ca_name_buf,
            TCP_CA_NAME_MAX as u32,
            msk_ref.ca_name().as_ptr() as *const c_void,
        );

        let first_val = unsafe { *msk_ref.first().as_ptr() } as *mut c_void;

        unsafe {
            (*storage).token = token_val;
            let dst = core::ptr::addr_of_mut!((*storage).ca_name) as *mut u8;
            for i in 0..TCP_CA_NAME_MAX {
                core::ptr::write_volatile(dst.add(i), ca_name_buf[i]);
            }
            (*storage).first = first_val;
        }
    }

    unsafe {
        (*storage).invoked += 1;
        (*storage).is_mptcp = is_mptcp as u32;
        (*storage).sk = sk;
    }

    1
}

#[link_section = "fentry/mptcp_pm_new_connection"]
#[no_mangle]
extern "C" fn trace_mptcp_pm_new_connection(ctx: *const u64) -> i32 {
    let msk = arg(ctx, 0) as *const mptcp_sock;
    let server_side = arg(ctx, 2) as i32;

    if server_side == 0 {
        let msk_ref = unsafe { &*msk };
        let token_val = unsafe { *msk_ref.token().as_ptr() };
        unsafe { token = token_val };
    }

    0
}

bpf_object!("GPL");
