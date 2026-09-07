#![no_std]
#![no_main]

#![feature(asm_experimental_arch)]

// Translation of mptcp_subflow.c and mptcp_bpf.h. Type casts and every
// kernel field use CO-RE; no kernel BTF IDs or layout offsets are pinned.
// BTF_TYPE_ID: tid_mptcp_sock struct mptcp_sock
// BTF_TYPE_ID: tid_subflow struct mptcp_subflow_context
// BTF_TYPE_ID: tid_icsk struct inet_connection_sock

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_map_lookup_elem, bpf_map_update_elem,
    bpf_setsockopt, bpf_skc_to_mptcp_sock, sync_fetch_and_add_u32,
};
use bpf_rs_core::maps::{self, BpfMap};
use btf_macros::btf;
use core::ffi::c_void;

extern "C" {
    fn tid_mptcp_sock() -> u64;
    fn tid_subflow() -> u64;
    fn tid_icsk() -> u64;
    fn bpf_rdonly_cast(obj: *const c_void, btf_id: u32) -> *mut c_void;
}

const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 3;
const SOL_SOCKET: i32 = 1;
const SO_MARK: i32 = 36;
const SOL_TCP: i32 = 6;
const TCP_CONGESTION: i32 = 13;
const TCP_CA_NAME_MAX: usize = 16;
const IPPROTO_MPTCP: u32 = 262;
const BPF_ANY: u64 = 0;

#[no_mangle]
static mut cc: [u8; TCP_CA_NAME_MAX] = *b"reno\0\0\0\0\0\0\0\0\0\0\0\0";

#[no_mangle]
static mut pid: i32 = 0;

/// Associate a subflow counter to each token.
#[link_section = ".maps"]
#[no_mangle]
static mptcp_sf: BpfMap<u32, u32, { maps::HASH }, 100> = BpfMap::new();

/// UAPI struct bpf_sock_ops (linux/bpf.h), through `sk` only -- nothing past
/// it is read, but every earlier field must keep its exact C offset for the
/// kernel's per-field ctx-access rewrite to line up.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock_ops {
    pub op: u32,
    pub args: [u32; 4],
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

/// UAPI struct bpf_sock (linux/bpf.h), through `protocol` only.
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct bpf_sock {
    pub bound_dev_if: u32,
    pub family: u32,
    pub r#type: u32,
    pub protocol: u32,
}

#[btf]
struct mptcp_pm_data {
    extra_subflows: u8,
}

// CO-RE byte_offset matching requires kind-compatible local/target field
// types (STRUCT vs STRUCT), so this can't be a bare `[u8; 16]` even though
// only its address is ever taken -- an ARRAY-kind local field fails to
// match the target's `struct list_head conn_list;` (STRUCT kind).
#[btf]
struct list_head {
    next: *mut list_head,
}

#[btf]
struct mptcp_sock {
    token: u32,
    pm: mptcp_pm_data,
    conn_list: list_head,
}

#[btf]
struct mptcp_subflow_context {
    node: list_head,
    tcp_sock: *mut sock,
}

#[btf]
struct sock {
    sk_mark: u32,
}

#[btf]
struct inet_connection_sock {
    icsk_ca_ops: *const tcp_congestion_ops,
}

#[btf]
struct tcp_congestion_ops {
    name: [u8; TCP_CA_NAME_MAX],
}

// Match mptcp_bpf.h's can_loop guard using the same BPF may_goto opcode.
#[inline(always)]
unsafe fn can_loop() -> bool {
    let mut ret = true;
    core::arch::asm!(
        "1:",
        ".byte 0xe5",
        ".byte 0",
        ".long (({0} - 1b - 8) / 8) & 0xffff",
        ".short 0",
        label { ret = false; },
    );
    ret
}

#[inline(always)]
unsafe fn subflow_from_node(node: *const list_head) -> *const mptcp_subflow_context {
    // container_of: calculate the CO-RE node offset without dereferencing
    // this temporary view, then restore the type with bpf_core_cast.
    let view = &*(node as *const mptcp_subflow_context);
    let offset = view.node().field.as_ptr() as usize - node as usize;
    bpf_rdonly_cast((node as *const u8).wrapping_sub(offset).cast(), tid_subflow() as u32).cast()
}

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn mptcp_subflow(ctx: *mut bpf_sock_ops) -> i32 {
    let c = unsafe { &*ctx };

    if c.op != BPF_SOCK_OPS_TCP_CONNECT_CB {
        return 1;
    }

    let sk = c.sk as *mut c_void;
    if sk.is_null() {
        return 1;
    }

    let msk_ptr = bpf_skc_to_mptcp_sock(sk) as *const mptcp_sock;
    if msk_ptr.is_null() {
        return 1;
    }
    let msk = unsafe { &*msk_ptr };

    let key = *msk.token().get().unwrap();
    let init: u32 = 1;
    let mut mark: u32;

    let cnt = bpf_map_lookup_elem(&mptcp_sf, &key) as *mut u32;
    if !cnt.is_null() {
        // A new subflow is added to an existing MPTCP connection.
        sync_fetch_and_add_u32(cnt, 1);
        mark = unsafe { *cnt };
    } else {
        // A new MPTCP connection is just initiated and this is its primary
        // subflow.
        bpf_map_update_elem(&mptcp_sf, &key, &init, BPF_ANY);
        mark = init;
    }

    let err = bpf_setsockopt(
        ctx as *mut c_void,
        SOL_SOCKET,
        SO_MARK,
        &mut mark as *mut u32 as *mut c_void,
        core::mem::size_of::<u32>() as i32,
    );
    if err < 0 {
        return 1;
    }
    if mark == 2 {
        bpf_setsockopt(
            ctx as *mut c_void,
            SOL_TCP,
            TCP_CONGESTION,
            core::ptr::addr_of_mut!(cc) as *mut c_void,
            TCP_CA_NAME_MAX as i32,
        );
    }

    1
}

// Keep the two checks separate until field-polyfill lowering: rustc can
// otherwise merge their initial field queries and discard path debug types.
#[inline(never)]
fn check_getsockopt_subflow_mark(msk: &mptcp_sock, ctx: &mut bpf_sockopt) -> i32 {
    let head = msk.conn_list().field.as_ptr();
    let mut pos = unsafe { *(*head).next().as_ptr() };
    let mut i: u32 = 0;
    while pos as *const list_head != head && unsafe { can_loop() } {
        let subflow = unsafe { &*subflow_from_node(pos) };
        let ssk = unsafe { &**subflow.tcp_sock().as_ptr() };
        i += 1;
        if unsafe { *ssk.sk_mark().as_ptr() } != i {
            ctx.retval = -2;
            break;
        }
        pos = unsafe { *subflow.node().next().as_ptr() };
    }
    1
}

#[inline(never)]
fn check_getsockopt_subflow_cc(msk: &mptcp_sock, ctx: &mut bpf_sockopt) -> i32 {
    let head = msk.conn_list().field.as_ptr();
    let mut pos = unsafe { *(*head).next().as_ptr() };
    while pos as *const list_head != head && unsafe { can_loop() } {
        let subflow = unsafe { &*subflow_from_node(pos) };
        let ssk = unsafe { &**subflow.tcp_sock().as_ptr() };
        let icsk = unsafe { &*(bpf_rdonly_cast(ssk as *const sock as *const c_void,
                                            tid_icsk() as u32) as *const inet_connection_sock) };
        if unsafe { *ssk.sk_mark().as_ptr() } == 2 {
            let ops = unsafe { &**icsk.icsk_ca_ops().as_ptr() };
            let name = ops.name().as_ptr().cast::<u8>();
            let mut j = 0;
            while j < TCP_CA_NAME_MAX {
                if unsafe { *name.add(j) != cc[j] } {
                    ctx.retval = -2;
                    return 1;
                }
                j += 1;
            }
        }
        pos = unsafe { *subflow.node().next().as_ptr() };
    }
    1
}

#[link_section = "cgroup/getsockopt"]
#[no_mangle]
extern "C" fn _getsockopt_subflow(ctx: *mut bpf_sockopt) -> i32 {
    let c = unsafe { &mut *ctx };

    if (bpf_get_current_pid_tgid() >> 32) != unsafe { pid } as i64 as u64 {
        return 1;
    }

    let sk_ptr = c.sk as *const bpf_sock;
    if sk_ptr.is_null() {
        return 1;
    }
    let sk = unsafe { &*sk_ptr };

    let is_mark_opt = c.level == SOL_SOCKET && c.optname == SO_MARK;
    let is_cc_opt = c.level == SOL_TCP && c.optname == TCP_CONGESTION;
    if sk.protocol != IPPROTO_MPTCP || (!is_mark_opt && !is_cc_opt) {
        return 1;
    }

    let msk_ptr =
        unsafe { bpf_rdonly_cast(c.sk as *const c_void, tid_mptcp_sock() as u32) } as *const mptcp_sock;
    if msk_ptr.is_null() {
        return 1;
    }
    let msk = unsafe { &*msk_ptr };

    let extra_subflows = *msk.pm().extra_subflows().get().unwrap();
    if extra_subflows != 1 {
        c.retval = -1;
        return 1;
    }

    if c.optname == SO_MARK {
        check_getsockopt_subflow_mark(msk, c)
    } else {
        check_getsockopt_subflow_cc(msk, c)
    }
}

bpf_object!("GPL");
