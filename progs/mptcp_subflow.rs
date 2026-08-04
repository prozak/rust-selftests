#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/mptcp_subflow.c
// (bpf-rs-core idiom).
//
// `mptcp_subflow()` needs `msk = bpf_skc_to_mptcp_sock(sk)`, a real numbered
// BPF helper (BPF_FUNC id 196, like the already-used bpf_skc_to_tcp_sock) --
// no CO-RE involved, gives a genuinely-typed TRUSTED PTR_TO_BTF_ID(struct
// mptcp_sock), so its own fields (`token`) are read with ordinary #[btf].
//
// `_getsockopt_subflow()` additionally needs that same cast (the C source
// uses `bpf_core_cast(sk, struct mptcp_sock)` there instead, but the two are
// interchangeable: `sk` is a genuine sock-family pointer either way, and
// bpf_skc_to_mptcp_sock's arg check (ARG_PTR_TO_BTF_ID_SOCK_COMMON) accepts
// PTR_TO_SOCKET/PTR_TO_SOCK_COMMON/PTR_TO_BTF_ID alike -- so reusing the
// helper avoids `bpf_core_type_id_kernel()` entirely, which this pipeline
// cannot emit (btf-macros only emits field byte_offset/field_exists
// relocations, not BPF_TYPE_ID_TARGET casts; see getsockname_unix_prog.rs).
//
// `mptcp_for_each_subflow()` is a different problem: it's
// `list_for_each_entry(subflow, &msk->conn_list, node)`, i.e. container_of
// arithmetic on each `list_head*` walked off `msk->conn_list.next`. The C
// re-types each `list_head*` back to `struct mptcp_subflow_context*` via
// another `bpf_core_cast()` -- same unemittable relocation, and this time
// there's no helper standing in for it. Once the pointer has gone through
// that container_of step the verifier no longer accepts a CO-RE byte_offset
// walk on it (btf_struct_walk would check the offset against `struct
// list_head`, not `mptcp_subflow_context`). The fix used throughout this
// repo for the same wall (see e.g. the pt_regs/GP_DI and arena-base-map-ptr
// memories): stop asking the verifier to track the type at all, and read
// through `bpf_probe_read_kernel` with byte offsets computed once, offline,
// from this exact kernel's vmlinux BTF (`bpftool btf dump file vmlinux`):
//   mptcp_subflow_context.node      = 0   (so a list_head* IS a subflow* --
//                                           no container_of adjustment needed)
//   mptcp_subflow_context.tcp_sock  = 224
//   sock.sk_mark                    = 924
//   inet_connection_sock.icsk_ca_ops = 2016 (== struct sock offset: icsk_inet
//                                             is inet_connection_sock's first
//                                             member, so a `struct sock *` and
//                                             its `inet_connection_sock *`
//                                             view share one address)
//   tcp_congestion_ops.name         = 96
// `bpf_probe_read_kernel`'s source arg is untyped (ARG_ANYTHING), so it
// doesn't care that these addresses are plain scalars with no BTF provenance
// by this point -- exactly the same idiom getsockname_unix_prog.rs already
// uses for sockaddr_un.sun_path.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_map_lookup_elem, bpf_map_update_elem, bpf_probe_read_kernel,
    bpf_setsockopt, bpf_skc_to_mptcp_sock, sync_fetch_and_add_u32,
};
use bpf_rs_core::maps::{self, BpfMap};
use btf_macros::btf;
use core::ffi::c_void;

extern "C" {
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

// `BPF_PROG_TYPE_CGROUP_SOCKOPT` doesn't whitelist bpf_skc_to_mptcp_sock (see
// cg_sockopt_func_proto in kernel/bpf/cgroup.c) -- confirmed by this file's
// first build attempt: "program of this type cannot use helper
// bpf_skc_to_mptcp_sock#196". That's exactly why the C original switches to
// `bpf_core_cast()` (-> bpf_rdonly_cast kfunc) only inside
// `_getsockopt_subflow()`, keeping the helper in the SEC("sockops") program
// where it IS whitelisted. bpf_rdonly_cast's second argument is normally a
// BPF_TYPE_ID_TARGET CO-RE relocation (bpf_core_type_id_kernel()), which
// btf-macros can't emit -- but the *value* that relocation ultimately
// resolves to is just this fixed kernel build's real vmlinux BTF id for
// `struct mptcp_sock`, and that id is static per kernel image, not
// per-boot: it's read straight out of the vmlinux ELF's .BTF section
// (`bpftool btf dump file vmlinux -j`, matching `"kind": "STRUCT", "name":
// "mptcp_sock"` -> `"id"`), the same blob the running kernel exposes at
// /sys/kernel/btf/vmlinux. Hardcoding that resolved value sidesteps the
// relocation machinery entirely, the same way SUBFLOW_TCP_SOCK_OFF and
// friends below sidestep byte_offset relocations.
const MPTCP_SOCK_BTF_ID: u32 = 133756;

const MAX_SUBFLOWS: u32 = 16;
const SUBFLOW_TCP_SOCK_OFF: usize = 224;
const SK_MARK_OFF: usize = 924;
const ICSK_CA_OPS_OFF: usize = 2016;
const CA_OPS_NAME_OFF: usize = 96;

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

#[inline(always)]
fn read_u64(addr: usize) -> u64 {
    let mut v: u64 = 0;
    bpf_probe_read_kernel(&mut v, 8, addr as *const c_void);
    v
}

#[inline(always)]
fn read_u32(addr: usize) -> u32 {
    let mut v: u32 = 0;
    bpf_probe_read_kernel(&mut v, 4, addr as *const c_void);
    v
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

#[inline(always)]
fn check_getsockopt_subflow_mark(msk: &mptcp_sock, ctx: &mut bpf_sockopt) -> i32 {
    let head = msk.conn_list().field.as_ptr() as usize;
    let mut pos = read_u64(head) as usize;
    let mut i: u32 = 0;
    let mut n: u32 = 0;

    while pos != head && n < MAX_SUBFLOWS {
        n += 1;
        i += 1;

        let tcp_sock_ptr = read_u64(pos + SUBFLOW_TCP_SOCK_OFF) as usize;
        let sk_mark = read_u32(tcp_sock_ptr + SK_MARK_OFF);
        if sk_mark != i {
            ctx.retval = -2;
            break;
        }

        pos = read_u64(pos) as usize;
    }

    1
}

#[inline(always)]
fn check_getsockopt_subflow_cc(msk: &mptcp_sock, ctx: &mut bpf_sockopt) -> i32 {
    let head = msk.conn_list().field.as_ptr() as usize;
    let mut pos = read_u64(head) as usize;
    let mut n: u32 = 0;

    while pos != head && n < MAX_SUBFLOWS {
        n += 1;

        let tcp_sock_ptr = read_u64(pos + SUBFLOW_TCP_SOCK_OFF) as usize;
        let sk_mark = read_u32(tcp_sock_ptr + SK_MARK_OFF);

        if sk_mark == 2 {
            let ca_ops_ptr = read_u64(tcp_sock_ptr + ICSK_CA_OPS_OFF) as usize;
            let mut name = [0u8; TCP_CA_NAME_MAX];
            bpf_probe_read_kernel(
                &mut name,
                TCP_CA_NAME_MAX as u32,
                (ca_ops_ptr + CA_OPS_NAME_OFF) as *const c_void,
            );

            // __builtin_memcmp(icsk_ca_ops->name, cc, TCP_CA_NAME_MAX) in the
            // C original: not bpf_strncmp, since `cc` is a plain writable
            // global (matches the C source's non-const `char cc[]`), and
            // bpf_strncmp's needle arg requires a read-only map value.
            let mut equal = true;
            let mut j = 0usize;
            while j < TCP_CA_NAME_MAX {
                if name[j] != unsafe { cc[j] } {
                    equal = false;
                    break;
                }
                j += 1;
            }
            if !equal {
                ctx.retval = -2;
                break;
            }
        }

        pos = read_u64(pos) as usize;
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
        unsafe { bpf_rdonly_cast(c.sk as *const c_void, MPTCP_SOCK_BTF_ID) } as *const mptcp_sock;
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
