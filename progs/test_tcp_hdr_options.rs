#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_tcp_hdr_options.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_load_hdr_opt, bpf_map_update_elem, bpf_reserve_hdr_opt, bpf_setsockopt,
    bpf_sk_storage_get, bpf_sock_ops_cb_flags_set, bpf_store_hdr_opt,
};
use core::ffi::c_void;

const CG_OK: i32 = 1;
const CG_ERR: i32 = 0;

const SOL_TCP: i32 = 6;

const TCPOPT_EXP: u8 = 254;
const TCP_BPF_EXPOPT_BASE_LEN: u8 = 4;

const OPTION_RESEND: u8 = 0;
const OPTION_MAX_DELACK_MS: u8 = 1;
const OPTION_RAND: u8 = 2;
const NR_OPTION_FLAGS: u8 = 3;
const OPTION_MASK: u8 = (1u8 << NR_OPTION_FLAGS) - 1;

const fn test_option_flags(flags: u8, option: u8) -> bool {
    (1 & (flags >> option)) != 0
}

const fn set_option_flags(flags: u8, option: u8) -> u8 {
    flags | (1 << option)
}

const TCPHDR_FIN: u32 = 0x01;
const TCPHDR_SYN: u32 = 0x02;
const TCPHDR_SYNACK: u32 = TCPHDR_SYN | 0x10;

const BPF_NOEXIST: u64 = 1;
const BPF_SK_STORAGE_GET_F_CREATE: u64 = 1;

const BPF_WRITE_HDR_TCP_CURRENT_MSS: u32 = 1;
const BPF_WRITE_HDR_TCP_SYNACK_COOKIE: u32 = 2;
const BPF_LOAD_HDR_OPT_TCP_SYN: u64 = 1 << 0;

const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 3;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: u32 = 4;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: u32 = 5;
const BPF_SOCK_OPS_TCP_LISTEN_CB: u32 = 11;
const BPF_SOCK_OPS_PARSE_HDR_OPT_CB: u32 = 13;
const BPF_SOCK_OPS_HDR_OPT_LEN_CB: u32 = 14;
const BPF_SOCK_OPS_WRITE_HDR_OPT_CB: u32 = 15;

const BPF_SOCK_OPS_STATE_CB_FLAG: u32 = 1 << 2;
const BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG: u32 = 1 << 4;
const BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG: u32 = 1 << 5;
const BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG: u32 = 1 << 6;

const TCP_BPF_DELACK_MAX: i32 = 1003;
const TCP_BPF_RTO_MIN: i32 = 1004;
const TCP_SAVE_SYN: i32 = 27;

const TCPHDR_LEN: usize = 20;

/// UAPI struct bpf_sock_ops (linux/bpf.h), through skb_tcp_flags -- every
/// earlier field must keep its exact C offset for the kernel's per-field
/// ctx-access rewrite to line up. The trailing `args`/`reply`/`replylong`
/// union collapses to its widest member, same as test_tcpbpf_kern.rs.
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
    pub skb_data: u64,
    pub skb_data_end: u64,
    pub skb_len: u32,
    pub skb_tcp_flags: u32,
}

/// UAPI struct bpf_test_option (test_tcp_hdr_options.h), packed 3 bytes.
#[allow(non_camel_case_types)]
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct bpf_test_option {
    pub flags: u8,
    pub max_delack_ms: u8,
    pub rand: u8,
}

const ZERO_OPTION: bpf_test_option = bpf_test_option {
    flags: 0,
    max_delack_ms: 0,
    rand: 0,
};

/// UAPI struct hdr_stg (test_tcp_hdr_options.h).
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct hdr_stg {
    pub active: bool,
    pub resend_syn: bool,
    pub syncookie: bool,
    pub fastopen: bool,
}

const ZERO_HDR_STG: hdr_stg = hdr_stg {
    active: false,
    resend_syn: false,
    syncookie: false,
    fastopen: false,
};

// Field-by-field copy, NOT a whole-struct assignment: rustc/LLVM lowers a
// bare `unsafe { some_static }` byte-copy of this packed (align-1) struct
// into an `llvm.memcpy` intrinsic, which the postproc pipeline then
// rewrites into a `bpf_arena_memcpy` kfunc call the kernel can't resolve
// for a non-arena program.
#[inline(always)]
fn copy_option(src: *const bpf_test_option) -> bpf_test_option {
    bpf_test_option {
        flags: unsafe { (*src).flags },
        max_delack_ms: unsafe { (*src).max_delack_ms },
        rand: unsafe { (*src).rand },
    }
}

/// UAPI struct linum_err (test_tcp_hdr_options.h).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct linum_err {
    pub linum: u32,
    pub err: i32,
}

/// struct tcp_exprm_opt (test_tcp_hdr_options.h), packed.
#[repr(C, packed)]
struct tcp_exprm_opt {
    kind: u8,
    len: u8,
    magic: u16,
    data: [u8; 4],
}

/// struct tcp_opt (test_tcp_hdr_options.h), packed.
#[repr(C, packed)]
struct tcp_opt {
    kind: u8,
    len: u8,
    data: [u8; 4],
}

#[no_mangle]
static mut test_kind: u8 = TCPOPT_EXP;
#[no_mangle]
static mut test_magic: u16 = 0xeB9F;
#[no_mangle]
static mut inherit_cb_flags: u32 = 0;

#[no_mangle]
static mut passive_synack_out: bpf_test_option = ZERO_OPTION;
#[no_mangle]
static mut passive_fin_out: bpf_test_option = ZERO_OPTION;

#[no_mangle]
static mut passive_estab_in: bpf_test_option = ZERO_OPTION;
#[no_mangle]
static mut passive_fin_in: bpf_test_option = ZERO_OPTION;

#[no_mangle]
static mut active_syn_out: bpf_test_option = ZERO_OPTION;
#[no_mangle]
static mut active_fin_out: bpf_test_option = ZERO_OPTION;

#[no_mangle]
static mut active_estab_in: bpf_test_option = ZERO_OPTION;
#[no_mangle]
static mut active_fin_in: bpf_test_option = ZERO_OPTION;

bpf_map! {
    hdr_stg_map {
        r#type: *const [i32; 24],  // BPF_MAP_TYPE_SK_STORAGE
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const hdr_stg,
    }
}

use bpf_rs_core::maps::{self, BpfMap};

#[link_section = ".maps"]
#[no_mangle]
static lport_linum_map: BpfMap<i32, linum_err, { maps::HASH }, 2> = BpfMap::new();

#[inline(always)]
fn skops_want_cookie(skops: *const bpf_sock_ops) -> bool {
    (unsafe { (*skops).args[0] }) == BPF_WRITE_HDR_TCP_SYNACK_COOKIE
}

#[inline(always)]
fn skops_current_mss(skops: *const bpf_sock_ops) -> bool {
    (unsafe { (*skops).args[0] }) == BPF_WRITE_HDR_TCP_CURRENT_MSS
}

#[inline(always)]
fn skops_tcp_flags(skops: *const bpf_sock_ops) -> u8 {
    unsafe { (*skops).skb_tcp_flags as u8 }
}

#[inline(always)]
fn clear_hdr_cb_flags(skops: *mut bpf_sock_ops) {
    let cur = unsafe { (*skops).bpf_sock_ops_cb_flags };
    bpf_sock_ops_cb_flags_set(
        skops,
        (cur & !(BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG))
            as i32,
    );
}

#[inline(always)]
fn set_hdr_cb_flags(skops: *mut bpf_sock_ops, extra: u32) {
    let cur = unsafe { (*skops).bpf_sock_ops_cb_flags };
    bpf_sock_ops_cb_flags_set(
        skops,
        (cur | BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG | extra)
            as i32,
    );
}

#[inline(always)]
fn clear_parse_all_hdr_cb_flags(skops: *mut bpf_sock_ops) {
    let cur = unsafe { (*skops).bpf_sock_ops_cb_flags };
    bpf_sock_ops_cb_flags_set(skops, (cur & !BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG) as i32);
}

#[inline(always)]
fn set_parse_all_hdr_cb_flags(skops: *mut bpf_sock_ops) {
    let cur = unsafe { (*skops).bpf_sock_ops_cb_flags };
    bpf_sock_ops_cb_flags_set(skops, (cur | BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG) as i32);
}

#[inline(never)]
fn ret_cg_err(skops: *mut bpf_sock_ops, err: i32, linum: u32) -> i32 {
    let le = linum_err { linum, err };
    let lport = unsafe { (*skops).local_port } as i32;
    bpf_map_update_elem(&lport_linum_map, &lport, &le, BPF_NOEXIST);
    clear_hdr_cb_flags(skops);
    clear_parse_all_hdr_cb_flags(skops);
    CG_ERR
}

macro_rules! ret_cg_err {
    ($skops:expr, $err:expr) => {
        return ret_cg_err($skops, $err, line!())
    };
}

#[inline(never)]
fn option_total_len(flags: u8) -> u8 {
    if flags == 0 {
        return 0;
    }

    let mut len: u8 = 1; // +1 for flags

    // RESEND bit does not use a byte
    let mut i = OPTION_RESEND + 1;
    while i < NR_OPTION_FLAGS {
        if test_option_flags(flags, i) {
            len = len.wrapping_add(1);
        }
        i += 1;
    }

    let kind = unsafe { test_kind };
    if kind == TCPOPT_EXP {
        len.wrapping_add(TCP_BPF_EXPOPT_BASE_LEN)
    } else {
        len.wrapping_add(2) // +1 kind, +1 kind-len
    }
}

#[inline(never)]
fn write_test_option(test_opt: *const bpf_test_option, data: *mut u8) {
    let mut offset: usize = 0;

    let flags = unsafe { (*test_opt).flags };
    unsafe { *data.add(offset) = flags };
    offset += 1;

    if test_option_flags(flags, OPTION_MAX_DELACK_MS) {
        unsafe { *data.add(offset) = (*test_opt).max_delack_ms };
        offset += 1;
    }

    if test_option_flags(flags, OPTION_RAND) {
        unsafe { *data.add(offset) = (*test_opt).rand };
    }
}

#[inline(never)]
fn store_option(skops: *mut bpf_sock_ops, test_opt: *const bpf_test_option) -> i32 {
    let err: i64;

    let flags = unsafe { (*test_opt).flags };
    let kind = unsafe { test_kind };
    if kind == TCPOPT_EXP {
        let mut w = tcp_exprm_opt {
            kind: TCPOPT_EXP,
            len: option_total_len(flags),
            magic: unsafe { test_magic }.to_be(),
            data: [0u8; 4],
        };
        write_test_option(test_opt, w.data.as_mut_ptr());
        err = bpf_store_hdr_opt(
            skops,
            &w as *const tcp_exprm_opt as *const c_void,
            core::mem::size_of::<tcp_exprm_opt>() as u32,
            0,
        );
    } else {
        let mut w = tcp_opt {
            kind,
            len: option_total_len(flags),
            data: [0u8; 4],
        };
        write_test_option(test_opt, w.data.as_mut_ptr());
        err = bpf_store_hdr_opt(
            skops,
            &w as *const tcp_opt as *const c_void,
            core::mem::size_of::<tcp_opt>() as u32,
            0,
        );
    }

    if err != 0 {
        ret_cg_err!(skops, err as i32);
    }

    CG_OK
}

#[inline(never)]
fn parse_test_option(opt: *mut bpf_test_option, start: *const u8) -> i32 {
    let mut offset: usize = 0;

    let flags = unsafe { *start.add(offset) };
    unsafe { (*opt).flags = flags };
    offset += 1;

    if test_option_flags(flags, OPTION_MAX_DELACK_MS) {
        unsafe { (*opt).max_delack_ms = *start.add(offset) };
        offset += 1;
    }

    if test_option_flags(flags, OPTION_RAND) {
        unsafe { (*opt).rand = *start.add(offset) };
    }

    0
}

#[inline(never)]
fn load_option(skops: *mut bpf_sock_ops, test_opt: *mut bpf_test_option, from_syn: bool) -> i64 {
    let load_flags: u64 = if from_syn { BPF_LOAD_HDR_OPT_TCP_SYN } else { 0 };

    let kind = unsafe { test_kind };
    if kind == TCPOPT_EXP {
        let mut s = tcp_exprm_opt {
            kind: TCPOPT_EXP,
            len: 4,
            magic: unsafe { test_magic }.to_be(),
            data: [0u8; 4],
        };
        let ret = bpf_load_hdr_opt(
            skops,
            &mut s as *mut tcp_exprm_opt as *mut c_void,
            core::mem::size_of::<tcp_exprm_opt>() as u32,
            load_flags,
        );
        if ret < 0 {
            return ret;
        }
        parse_test_option(test_opt, s.data.as_ptr()) as i64
    } else {
        let mut s = tcp_opt {
            kind,
            len: 0,
            data: [0u8; 4],
        };
        let ret = bpf_load_hdr_opt(
            skops,
            &mut s as *mut tcp_opt as *mut c_void,
            core::mem::size_of::<tcp_opt>() as u32,
            load_flags,
        );
        if ret < 0 {
            return ret;
        }
        parse_test_option(test_opt, s.data.as_ptr()) as i64
    }
}

#[inline(never)]
fn synack_opt_len(skops: *mut bpf_sock_ops) -> i32 {
    let mut test_opt = ZERO_OPTION;

    let flags = unsafe { passive_synack_out.flags };
    if flags == 0 {
        return CG_OK;
    }

    let err = load_option(skops, &mut test_opt as *mut bpf_test_option, true);

    // bpf_test_option is not found
    if err == -(libc_enomsg() as i64) {
        return CG_OK;
    }

    if err != 0 {
        ret_cg_err!(skops, err as i32);
    }

    let optlen = option_total_len(unsafe { passive_synack_out.flags });
    if optlen != 0 {
        let err = bpf_reserve_hdr_opt(skops, optlen as u32, 0);
        if err != 0 {
            ret_cg_err!(skops, err as i32);
        }
    }

    CG_OK
}

#[inline(never)]
fn write_synack_opt(skops: *mut bpf_sock_ops) -> i32 {
    let flags = unsafe { passive_synack_out.flags };
    if flags == 0 {
        // We should not even be called since no header space has been
        // reserved.
        ret_cg_err!(skops, 0);
    }

    let mut opt = copy_option(core::ptr::addr_of!(passive_synack_out));
    if skops_want_cookie(skops) {
        opt.flags = set_option_flags(opt.flags, OPTION_RESEND);
    }

    store_option(skops, &opt as *const bpf_test_option)
}

#[inline(never)]
fn syn_opt_len(skops: *mut bpf_sock_ops) -> i32 {
    let flags = unsafe { active_syn_out.flags };
    if flags == 0 {
        return CG_OK;
    }

    let optlen = option_total_len(flags);
    if optlen != 0 {
        let err = bpf_reserve_hdr_opt(skops, optlen as u32, 0);
        if err != 0 {
            ret_cg_err!(skops, err as i32);
        }
    }

    CG_OK
}

#[inline(never)]
fn write_syn_opt(skops: *mut bpf_sock_ops) -> i32 {
    let flags = unsafe { active_syn_out.flags };
    if flags == 0 {
        ret_cg_err!(skops, 0);
    }

    store_option(skops, core::ptr::addr_of!(active_syn_out))
}

#[inline(never)]
fn fin_opt(skops: *mut bpf_sock_ops) -> Option<bpf_test_option> {
    let sk = unsafe { (*skops).sk } as *mut c_void;
    if sk.is_null() {
        return None;
    }

    let stg_ptr = bpf_sk_storage_get(&hdr_stg_map, sk, core::ptr::null_mut(), 0);
    if stg_ptr.is_null() {
        return None;
    }
    let active = unsafe { (*(stg_ptr as *const hdr_stg)).active };

    Some(if active {
        copy_option(core::ptr::addr_of!(active_fin_out))
    } else {
        copy_option(core::ptr::addr_of!(passive_fin_out))
    })
}

#[inline(never)]
fn fin_opt_len(skops: *mut bpf_sock_ops) -> i32 {
    let opt = match fin_opt(skops) {
        Some(opt) => opt,
        None => ret_cg_err!(skops, 0),
    };

    let optlen = option_total_len(opt.flags);
    if optlen != 0 {
        let err = bpf_reserve_hdr_opt(skops, optlen as u32, 0);
        if err != 0 {
            ret_cg_err!(skops, err as i32);
        }
    }

    CG_OK
}

#[inline(never)]
fn write_fin_opt(skops: *mut bpf_sock_ops) -> i32 {
    let opt = match fin_opt(skops) {
        Some(opt) => opt,
        None => ret_cg_err!(skops, 0),
    };

    if opt.flags == 0 {
        ret_cg_err!(skops, 0);
    }

    store_option(skops, &opt as *const bpf_test_option)
}

#[inline(never)]
fn resend_in_ack(skops: *mut bpf_sock_ops) -> i32 {
    let sk = unsafe { (*skops).sk } as *mut c_void;
    if sk.is_null() {
        return -1;
    }

    let stg_ptr = bpf_sk_storage_get(&hdr_stg_map, sk, core::ptr::null_mut(), 0);
    if stg_ptr.is_null() {
        return -1;
    }

    let resend_syn = unsafe { (*(stg_ptr as *const hdr_stg)).resend_syn };
    resend_syn as i32
}

#[inline(never)]
fn nodata_opt_len(skops: *mut bpf_sock_ops) -> i32 {
    let resend = resend_in_ack(skops);
    if resend < 0 {
        ret_cg_err!(skops, 0);
    }

    if resend != 0 {
        return syn_opt_len(skops);
    }

    CG_OK
}

#[inline(never)]
fn write_nodata_opt(skops: *mut bpf_sock_ops) -> i32 {
    let resend = resend_in_ack(skops);
    if resend < 0 {
        ret_cg_err!(skops, 0);
    }

    if resend != 0 {
        return write_syn_opt(skops);
    }

    CG_OK
}

#[inline(always)]
fn data_opt_len(skops: *mut bpf_sock_ops) -> i32 {
    // Same as the nodata version. Mostly to show an example usage on
    // skops->skb_len.
    nodata_opt_len(skops)
}

#[inline(always)]
fn write_data_opt(skops: *mut bpf_sock_ops) -> i32 {
    write_nodata_opt(skops)
}

#[inline(never)]
fn current_mss_opt_len(skops: *mut bpf_sock_ops) -> i32 {
    // Reserve maximum that may be needed
    let err = bpf_reserve_hdr_opt(skops, option_total_len(OPTION_MASK) as u32, 0);
    if err != 0 {
        ret_cg_err!(skops, err as i32);
    }

    CG_OK
}

#[inline(never)]
fn handle_hdr_opt_len(skops: *mut bpf_sock_ops) -> i32 {
    let tcp_flags = skops_tcp_flags(skops) as u32;

    if (tcp_flags & TCPHDR_SYNACK) == TCPHDR_SYNACK {
        return synack_opt_len(skops);
    }

    if tcp_flags & TCPHDR_SYN != 0 {
        return syn_opt_len(skops);
    }

    if tcp_flags & TCPHDR_FIN != 0 {
        return fin_opt_len(skops);
    }

    if skops_current_mss(skops) {
        // The kernel is calculating the MSS
        return current_mss_opt_len(skops);
    }

    if unsafe { (*skops).skb_len } != 0 {
        return data_opt_len(skops);
    }

    nodata_opt_len(skops)
}

#[inline(never)]
fn handle_write_hdr_opt(skops: *mut bpf_sock_ops) -> i32 {
    let tcp_flags = skops_tcp_flags(skops) as u32;

    if (tcp_flags & TCPHDR_SYNACK) == TCPHDR_SYNACK {
        return write_synack_opt(skops);
    }

    if tcp_flags & TCPHDR_SYN != 0 {
        return write_syn_opt(skops);
    }

    if tcp_flags & TCPHDR_FIN != 0 {
        return write_fin_opt(skops);
    }

    let th = unsafe { (*skops).skb_data } as usize;
    let data_end = unsafe { (*skops).skb_data_end } as usize;
    if th + TCPHDR_LEN > data_end {
        ret_cg_err!(skops, 0);
    }

    let doff_byte = unsafe { *((th + 12) as *const u8) };
    let hdrlen = ((doff_byte >> 4) as usize) << 2;

    if (unsafe { (*skops).skb_len } as usize) > hdrlen {
        write_data_opt(skops)
    } else {
        write_nodata_opt(skops)
    }
}

#[inline(never)]
fn set_delack_max(skops: *mut bpf_sock_ops, max_delack_ms: u8) -> i64 {
    let mut max_delack_us: u32 = (max_delack_ms as u32) * 1000;

    bpf_setsockopt(
        skops as *mut c_void,
        SOL_TCP,
        TCP_BPF_DELACK_MAX,
        &mut max_delack_us as *mut u32 as *mut c_void,
        core::mem::size_of::<u32>() as i32,
    )
}

#[inline(never)]
fn set_rto_min(skops: *mut bpf_sock_ops, peer_max_delack_ms: u8) -> i64 {
    let mut min_rto_us: u32 = (peer_max_delack_ms as u32) * 1000;

    bpf_setsockopt(
        skops as *mut c_void,
        SOL_TCP,
        TCP_BPF_RTO_MIN,
        &mut min_rto_us as *mut u32 as *mut c_void,
        core::mem::size_of::<u32>() as i32,
    )
}

#[inline(never)]
fn handle_active_estab(skops: *mut bpf_sock_ops) -> i32 {
    let mut init_stg = hdr_stg {
        active: true,
        resend_syn: false,
        syncookie: false,
        fastopen: false,
    };

    let err = load_option(skops, core::ptr::addr_of_mut!(active_estab_in), false);
    if err != 0 && err != -(libc_enomsg() as i64) {
        ret_cg_err!(skops, err as i32);
    }

    init_stg.resend_syn = test_option_flags(unsafe { active_estab_in.flags }, OPTION_RESEND);

    let sk = unsafe { (*skops).sk } as *mut c_void;
    if sk.is_null()
        || bpf_sk_storage_get(
            &hdr_stg_map,
            sk,
            &mut init_stg as *mut hdr_stg as *mut c_void,
            BPF_SK_STORAGE_GET_F_CREATE,
        )
        .is_null()
    {
        ret_cg_err!(skops, 0);
    }

    if init_stg.resend_syn {
        // Don't clear the write_hdr cb now because the ACK may get lost
        // and retransmit may be needed.
        //
        // PARSE_ALL_HDR cb flag is set to learn if this resend_syn
        // option has received by the peer.
        //
        // The header option will be resent until a valid packet is
        // received at handle_parse_hdr() and all hdr cb flags will be
        // cleared in handle_parse_hdr().
        set_parse_all_hdr_cb_flags(skops);
    } else if unsafe { active_fin_out.flags } == 0 {
        // No options will be written from now
        clear_hdr_cb_flags(skops);
    }

    let max_delack_ms = unsafe { active_syn_out.max_delack_ms };
    if max_delack_ms != 0 {
        let err = set_delack_max(skops, max_delack_ms);
        if err != 0 {
            ret_cg_err!(skops, err as i32);
        }
    }

    let peer_max_delack_ms = unsafe { active_estab_in.max_delack_ms };
    if peer_max_delack_ms != 0 {
        let err = set_rto_min(skops, peer_max_delack_ms);
        if err != 0 {
            ret_cg_err!(skops, err as i32);
        }
    }

    CG_OK
}

#[inline(never)]
fn handle_passive_estab(skops: *mut bpf_sock_ops) -> i32 {
    let mut init_stg = ZERO_HDR_STG;

    unsafe { inherit_cb_flags = (*skops).bpf_sock_ops_cb_flags };

    let mut err = load_option(skops, core::ptr::addr_of_mut!(passive_estab_in), true);
    if err == -(libc_enoent() as i64) {
        // saved_syn is not found. It was in syncookie mode. We have
        // asked the active side to resend the options in ACK, so try to
        // find the bpf_test_option from ACK now.
        err = load_option(skops, core::ptr::addr_of_mut!(passive_estab_in), false);
        init_stg.syncookie = true;
    }

    // ENOMSG: The bpf_test_option is not found which is fine. Bail out
    // now for all other errors.
    if err != 0 && err != -(libc_enomsg() as i64) {
        ret_cg_err!(skops, err as i32);
    }

    let th = unsafe { (*skops).skb_data } as usize;
    let data_end = unsafe { (*skops).skb_data_end } as usize;
    if th + TCPHDR_LEN > data_end {
        ret_cg_err!(skops, 0);
    }

    let flags_byte = unsafe { *((th + 13) as *const u8) };
    let syn = (flags_byte >> 1) & 1;

    if syn != 0 {
        // Fastopen

        // Cannot clear cb_flags to stop write_hdr cb. synack is not
        // sent yet for fast open. Even it was, the synack may need to
        // be retransmitted.
        //
        // PARSE_ALL_HDR cb flag is set to learn if synack has reached
        // the peer. All cb_flags will be cleared in handle_parse_hdr().
        set_parse_all_hdr_cb_flags(skops);
        init_stg.fastopen = true;
    } else if unsafe { passive_fin_out.flags } == 0 {
        // No options will be written from now
        clear_hdr_cb_flags(skops);
    }

    let sk = unsafe { (*skops).sk } as *mut c_void;
    if sk.is_null()
        || bpf_sk_storage_get(
            &hdr_stg_map,
            sk,
            &mut init_stg as *mut hdr_stg as *mut c_void,
            BPF_SK_STORAGE_GET_F_CREATE,
        )
        .is_null()
    {
        ret_cg_err!(skops, 0);
    }

    let max_delack_ms = unsafe { passive_synack_out.max_delack_ms };
    if max_delack_ms != 0 {
        let err = set_delack_max(skops, max_delack_ms);
        if err != 0 {
            ret_cg_err!(skops, err as i32);
        }
    }

    let peer_max_delack_ms = unsafe { passive_estab_in.max_delack_ms };
    if peer_max_delack_ms != 0 {
        let err = set_rto_min(skops, peer_max_delack_ms);
        if err != 0 {
            ret_cg_err!(skops, err as i32);
        }
    }

    CG_OK
}

#[inline(never)]
fn handle_parse_hdr(skops: *mut bpf_sock_ops) -> i32 {
    let sk = unsafe { (*skops).sk } as *mut c_void;
    if sk.is_null() {
        ret_cg_err!(skops, 0);
    }

    let th = unsafe { (*skops).skb_data } as usize;
    let data_end = unsafe { (*skops).skb_data_end } as usize;
    if th + TCPHDR_LEN > data_end {
        ret_cg_err!(skops, 0);
    }

    let hdr_stg_ptr = bpf_sk_storage_get(&hdr_stg_map, sk, core::ptr::null_mut(), 0);
    if hdr_stg_ptr.is_null() {
        ret_cg_err!(skops, 0);
    }
    let stg = hdr_stg_ptr as *const hdr_stg;
    let stg_resend_syn = unsafe { (*stg).resend_syn };
    let stg_fastopen = unsafe { (*stg).fastopen };
    let stg_active = unsafe { (*stg).active };

    if stg_resend_syn || stg_fastopen {
        // The PARSE_ALL_HDR cb flag was turned on to ensure that the
        // previously written options have reached the peer. Those
        // previously written option includes:
        //     - Active side: resend_syn in ACK during syncookie
        //      or
        //     - Passive side: SYNACK during fastopen
        //
        // A valid packet has been received here after the 3WHS, so the
        // PARSE_ALL_HDR cb flag can be cleared now.
        clear_parse_all_hdr_cb_flags(skops);
    }

    if stg_resend_syn && unsafe { active_fin_out.flags } == 0 {
        // Active side resent the syn option in ACK because the server
        // was in syncookie mode. A valid packet has been received, so
        // clear header cb flags if there is no more option to send.
        clear_hdr_cb_flags(skops);
    }

    if stg_fastopen && unsafe { passive_fin_out.flags } == 0 {
        // Passive side was in fastopen. A valid packet has been
        // received, so the SYNACK has reached the peer. Clear header cb
        // flags if there is no more option to send.
        clear_hdr_cb_flags(skops);
    }

    let flags_byte = unsafe { *((th + 13) as *const u8) };
    let fin = flags_byte & 1;

    if fin != 0 {
        let err = if stg_active {
            load_option(skops, core::ptr::addr_of_mut!(active_fin_in), false)
        } else {
            load_option(skops, core::ptr::addr_of_mut!(passive_fin_in), false)
        };
        if err != 0 && err != -(libc_enomsg() as i64) {
            ret_cg_err!(skops, err as i32);
        }
    }

    CG_OK
}

// -ENOMSG / -ENOENT as used by the kernel's bpf_load_hdr_opt() error
// contract (include/uapi/asm-generic/errno-base.h).
#[inline(always)]
const fn libc_enomsg() -> u32 {
    42
}

#[inline(always)]
const fn libc_enoent() -> u32 {
    2
}

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn estab(skops: *mut bpf_sock_ops) -> i32 {
    let true_val: i32 = 1;

    let op = unsafe { (*skops).op };

    match op {
        BPF_SOCK_OPS_TCP_LISTEN_CB => {
            let mut tv = true_val;
            bpf_setsockopt(
                skops as *mut c_void,
                SOL_TCP,
                TCP_SAVE_SYN,
                &mut tv as *mut i32 as *mut c_void,
                core::mem::size_of::<i32>() as i32,
            );
            set_hdr_cb_flags(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
        }
        BPF_SOCK_OPS_TCP_CONNECT_CB => {
            set_hdr_cb_flags(skops, 0);
        }
        BPF_SOCK_OPS_PARSE_HDR_OPT_CB => {
            return handle_parse_hdr(skops);
        }
        BPF_SOCK_OPS_HDR_OPT_LEN_CB => {
            return handle_hdr_opt_len(skops);
        }
        BPF_SOCK_OPS_WRITE_HDR_OPT_CB => {
            return handle_write_hdr_opt(skops);
        }
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            return handle_passive_estab(skops);
        }
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB => {
            return handle_active_estab(skops);
        }
        _ => {}
    }

    CG_OK
}

bpf_object!("GPL");
