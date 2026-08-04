#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_misc_tcp_hdr_options.c
// (bpf-rs-core idiom).
//
// The C source keeps a stack-local C union of {tcphdr, ipv6hdr,
// tcp_exprm_opt, tcp_opt, u8[100]} as the scratch buffer passed to
// bpf_load_hdr_opt()/bpf_getsockopt(); those helpers only check the
// buffer's *size* (ARG_PTR_TO_MEM), not any BTF layout, so the union is
// translated as a plain `[u8; 100]` stack array read/written at fixed
// byte offsets via unaligned scalar loads/stores. This sidesteps the
// packed-struct-value-copy -> arena-memcpy-kfunc landmine documented for
// test_tcp_hdr_options.rs entirely (no struct type ever copied by value).
//
// Direct packet access (`skops->skb_data` / `skb_data_end`) uses real
// pointer arithmetic (`.add(N)` + pointer compare) for the bounds check,
// not integer `usize` addition, so the verifier's packet-pointer range
// narrowing actually fires.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_getsockopt, bpf_load_hdr_opt, bpf_map_update_elem, bpf_reserve_hdr_opt, bpf_setsockopt,
    bpf_sock_ops_cb_flags_set, bpf_store_hdr_opt,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{vload, vload_as};
use core::ffi::c_void;

const CG_OK: i32 = 1;
const CG_ERR: i32 = 0;

const SOL_TCP: i32 = 6;
const TCP_SAVE_SYN: i32 = 27;
const TCP_NODELAY: i32 = 1;
const TCP_BPF_SYN: i32 = 1005;
const TCP_BPF_SYN_IP: i32 = 1006;

const EOPNOTSUPP: i64 = -95;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;
const EEXIST: i64 = -17;
const ENOMSG: i64 = -42;

const TCPOPT_WINDOW: u8 = 3;
const TCPOPT_EXP: u8 = 254;

const TCPHDR_ACK: u8 = 0x10;
const TCPHDR_SYN: u8 = 0x02;
const TCPHDR_FIN: u8 = 0x01;
const TCPHDR_SYNACK: u8 = TCPHDR_SYN | TCPHDR_ACK;

const BPF_LOAD_HDR_OPT_TCP_SYN: u64 = 1 << 0;

const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 3;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: u32 = 5;
const BPF_SOCK_OPS_TCP_LISTEN_CB: u32 = 11;
const BPF_SOCK_OPS_PARSE_HDR_OPT_CB: u32 = 13;
const BPF_SOCK_OPS_HDR_OPT_LEN_CB: u32 = 14;
const BPF_SOCK_OPS_WRITE_HDR_OPT_CB: u32 = 15;

const BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG: u32 = 1 << 4;
const BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG: u32 = 1 << 5;
const BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG: u32 = 1 << 6;

const BPF_NOEXIST: u64 = 1;

// UAPI struct bpf_sock_ops, full layout (bpf.h). `sk`/`skb_data`/
// `skb_data_end` are __bpf_md_ptr unions (pointer overlaid with u64),
// represented as u64 like other translations in this repo (mptcp_sockmap.rs).
#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct bpf_sock_ops {
    op: u32,
    reply_union: [u32; 4],
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
    sk: u64,
    skb_data: u64,
    skb_data_end: u64,
    skb_len: u32,
    skb_tcp_flags: u32,
    skb_hwtstamp: u64,
}

#[repr(C)]
struct LinumErr {
    linum: u32,
    err: i32,
}

#[link_section = ".maps"]
#[no_mangle]
static lport_linum_map: BpfMap<i32, LinumErr, { maps::HASH }, 2> = BpfMap::new();

/* options received at passive side */
#[no_mangle]
static mut last_addr16_n: u16 = 256; // __bpf_htons(1)
#[no_mangle]
static mut active_lport_n: u16 = 0;
#[no_mangle]
static mut active_lport_h: u16 = 0;
#[no_mangle]
static mut passive_lport_n: u16 = 0;
#[no_mangle]
static mut passive_lport_h: u16 = 0;

#[no_mangle]
static mut nr_pure_ack: u32 = 0;
#[no_mangle]
static mut nr_data: u32 = 0;
#[no_mangle]
static mut nr_syn: u32 = 0;
#[no_mangle]
static mut nr_fin: u32 = 0;
#[no_mangle]
static mut nr_hwtstamp: u32 = 0;

#[no_mangle]
static mut nodelay_est_ok: bool = false;
#[no_mangle]
static mut nodelay_hdr_len_reject: bool = false;
#[no_mangle]
static mut nodelay_write_hdr_reject: bool = false;

#[inline(always)]
unsafe fn ld8(p: *const u8, off: isize) -> u8 {
    core::ptr::read(p.offset(off))
}

#[inline(always)]
unsafe fn ld16(p: *const u8, off: isize) -> u16 {
    core::ptr::read_unaligned(p.offset(off) as *const u16)
}

#[inline(always)]
unsafe fn st8(p: *mut u8, off: isize, v: u8) {
    core::ptr::write(p.offset(off), v);
}

#[inline(always)]
unsafe fn st16(p: *mut u8, off: isize, v: u16) {
    core::ptr::write_unaligned(p.offset(off) as *mut u16, v);
}

#[inline(always)]
fn clear_hdr_cb_flags(skops: *mut bpf_sock_ops) {
    let flags = vload!((*skops).bpf_sock_ops_cb_flags);
    let new_flags = flags
        & !(BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);
    bpf_sock_ops_cb_flags_set(skops, new_flags as i32);
}

#[inline(always)]
fn set_hdr_cb_flags(skops: *mut bpf_sock_ops, extra: u32) {
    let flags = vload!((*skops).bpf_sock_ops_cb_flags);
    let new_flags = flags
        | BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG
        | BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG
        | extra;
    bpf_sock_ops_cb_flags_set(skops, new_flags as i32);
}

#[inline(always)]
fn clear_parse_all_hdr_cb_flags(skops: *mut bpf_sock_ops) {
    let flags = vload!((*skops).bpf_sock_ops_cb_flags);
    let new_flags = flags & !BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG;
    bpf_sock_ops_cb_flags_set(skops, new_flags as i32);
}

macro_rules! ret_cg_err {
    ($skops:expr, $err:expr) => {{
        let linum_err = LinumErr {
            linum: line!(),
            err: $err,
        };
        let lport = vload!((*$skops).local_port) as i32;
        bpf_map_update_elem(&lport_linum_map, &lport, &linum_err, BPF_NOEXIST);
        clear_hdr_cb_flags($skops);
        clear_parse_all_hdr_cb_flags($skops);
        return CG_ERR;
    }};
}

/// Check the header received from the active side.
fn check_active_hdr_in_common(skops: *mut bpf_sock_ops, check_syn: bool) -> i32 {
    let mut hdr = [0u8; 100];
    let hp = hdr.as_mut_ptr();
    let load_flags: u64 = if check_syn { BPF_LOAD_HDR_OPT_TCP_SYN } else { 0 };

    unsafe { st8(hp, 0, 0xB9) }; // reg_opt.kind

    // The option is 4 bytes long instead of 2 bytes.
    let mut ret = bpf_load_hdr_opt(skops, hp as *mut c_void, 2, load_flags);
    if ret != ENOSPC {
        ret_cg_err!(skops, ret as i32);
    }

    // Test searching magic with regular kind.
    unsafe { st8(hp, 1, 4) }; // reg_opt.len = 4
    ret = bpf_load_hdr_opt(skops, hp as *mut c_void, 6, load_flags);
    if ret != EINVAL {
        ret_cg_err!(skops, ret as i32);
    }

    unsafe { st8(hp, 1, 0) }; // reg_opt.len = 0
    ret = bpf_load_hdr_opt(skops, hp as *mut c_void, 6, load_flags);
    if ret != 4
        || unsafe { ld8(hp, 1) } != 4
        || unsafe { ld8(hp, 0) } != 0xB9
        || unsafe { ld8(hp, 2) } != 0xfa
        || unsafe { ld8(hp, 3) } != 0xce
    {
        ret_cg_err!(skops, ret as i32);
    }

    // Test searching experimental option with invalid kind length.
    unsafe {
        st8(hp, 0, TCPOPT_EXP); // exprm_opt.kind
        st8(hp, 1, 5); // exprm_opt.len
        st16(hp, 2, 0); // exprm_opt.magic
    }
    ret = bpf_load_hdr_opt(skops, hp as *mut c_void, 8, load_flags);
    if ret != EINVAL {
        ret_cg_err!(skops, ret as i32);
    }

    // Test searching experimental option with 0 magic value.
    unsafe { st8(hp, 1, 4) }; // exprm_opt.len = 4
    ret = bpf_load_hdr_opt(skops, hp as *mut c_void, 8, load_flags);
    if ret != ENOMSG {
        ret_cg_err!(skops, ret as i32);
    }

    let magic = 0xeB9Fu16.to_be();
    unsafe { st16(hp, 2, magic) };
    ret = bpf_load_hdr_opt(skops, hp as *mut c_void, 8, load_flags);
    if ret != 4
        || unsafe { ld8(hp, 1) } != 4
        || unsafe { ld8(hp, 0) } != TCPOPT_EXP
        || unsafe { ld16(hp, 2) } != magic
    {
        ret_cg_err!(skops, ret as i32);
    }

    if !check_syn {
        return CG_OK;
    }

    // Test loading from skops->syn_skb if sk_state == TCP_NEW_SYN_RECV.
    // Test loading from tp->saved_syn for other sk_state.
    let mut ret64 = bpf_getsockopt(skops, SOL_TCP, TCP_BPF_SYN_IP, hp as *mut c_void, 40);
    if ret64 != ENOSPC {
        ret_cg_err!(skops, ret64 as i32);
    }

    let last_n = unsafe { last_addr16_n };
    // hdr.ip6.saddr.s6_addr16[7] @ offset 8+14=22, daddr @ 24+14=38.
    if unsafe { ld16(hp, 22) } != last_n || unsafe { ld16(hp, 38) } != last_n {
        ret_cg_err!(skops, 0);
    }

    ret64 = bpf_getsockopt(skops, SOL_TCP, TCP_BPF_SYN_IP, hp as *mut c_void, 100);
    if ret64 < 0 {
        ret_cg_err!(skops, ret64 as i32);
    }

    // pth = (struct tcphdr *)(&hdr.ip6 + 1) => offset 40.
    let passive_n = unsafe { passive_lport_n };
    let active_n = unsafe { active_lport_n };
    if unsafe { ld16(hp, 42) } != passive_n || unsafe { ld16(hp, 40) } != active_n {
        ret_cg_err!(skops, 0);
    }

    ret64 = bpf_getsockopt(skops, SOL_TCP, TCP_BPF_SYN, hp as *mut c_void, 100);
    if ret64 < 0 {
        ret_cg_err!(skops, ret64 as i32);
    }

    if unsafe { ld16(hp, 2) } != passive_n || unsafe { ld16(hp, 0) } != active_n {
        ret_cg_err!(skops, 0);
    }

    CG_OK
}

fn check_active_syn_in(skops: *mut bpf_sock_ops) -> i32 {
    check_active_hdr_in_common(skops, true)
}

fn check_active_hdr_in(skops: *mut bpf_sock_ops) -> i32 {
    if check_active_hdr_in_common(skops, false) == CG_ERR {
        return CG_ERR;
    }

    let th = vload!((*skops).skb_data) as usize as *const u8;
    let data_end = vload!((*skops).skb_data_end) as usize as *const u8;
    if unsafe { th.add(20) } > data_end {
        ret_cg_err!(skops, 0);
    }

    let byte12 = unsafe { ld8(th, 12) };
    let byte13 = unsafe { ld8(th, 13) };
    let doff = (byte12 >> 4) & 0x0F;
    let hdrlen = (doff as u32) << 2;
    let skb_len = vload!((*skops).skb_len);

    if hdrlen < skb_len {
        unsafe { nr_data += 1 };
    }

    let fin = (byte13 & TCPHDR_FIN) != 0;
    let ack = (byte13 & TCPHDR_ACK) != 0;

    if fin {
        unsafe { nr_fin += 1 };
    }

    if ack && !fin && hdrlen == skb_len {
        unsafe { nr_pure_ack += 1 };
    }

    if vload!((*skops).skb_hwtstamp) != 0 {
        unsafe { nr_hwtstamp += 1 };
    }

    CG_OK
}

fn active_opt_len(skops: *mut bpf_sock_ops) -> i32 {
    // Reserve more than enough to allow the -EEXIST test in
    // write_active_opt().
    let err = bpf_reserve_hdr_opt(skops, 12, 0);
    if err != 0 {
        ret_cg_err!(skops, err as i32);
    }
    CG_OK
}

fn write_active_opt(skops: *mut bpf_sock_ops) -> i32 {
    let mut exprm_opt = [0u8; 8];
    let mut reg_opt = [0u8; 6];
    let mut win_scale_opt = [0u8; 6];

    unsafe {
        let ep = exprm_opt.as_mut_ptr();
        st8(ep, 0, TCPOPT_EXP);
        st8(ep, 1, 4);
        st16(ep, 2, 0xeB9Fu16.to_be());

        let rp = reg_opt.as_mut_ptr();
        st8(rp, 0, 0xB9);
        st8(rp, 1, 4);
        st8(rp, 2, 0xfa);
        st8(rp, 3, 0xce);

        st8(win_scale_opt.as_mut_ptr(), 0, TCPOPT_WINDOW);
    }

    let ep = exprm_opt.as_ptr() as *const c_void;
    let rp = reg_opt.as_ptr() as *const c_void;

    let mut err = bpf_store_hdr_opt(skops, ep, 8, 0);
    if err != 0 {
        ret_cg_err!(skops, err as i32);
    }

    // Store the same exprm option.
    err = bpf_store_hdr_opt(skops, ep, 8, 0);
    if err != EEXIST {
        // -EEXIST
        ret_cg_err!(skops, err as i32);
    }

    err = bpf_store_hdr_opt(skops, rp, 6, 0);
    if err != 0 {
        ret_cg_err!(skops, err as i32);
    }
    err = bpf_store_hdr_opt(skops, rp, 6, 0);
    if err != EEXIST {
        ret_cg_err!(skops, err as i32);
    }

    // Check the option has been written and can be searched.
    let mut ret = bpf_load_hdr_opt(skops, exprm_opt.as_mut_ptr() as *mut c_void, 8, 0);
    if ret != 4
        || unsafe { ld8(exprm_opt.as_ptr(), 1) } != 4
        || unsafe { ld8(exprm_opt.as_ptr(), 0) } != TCPOPT_EXP
        || unsafe { ld16(exprm_opt.as_ptr(), 2) } != 0xeB9Fu16.to_be()
    {
        ret_cg_err!(skops, ret as i32);
    }

    unsafe { st8(reg_opt.as_mut_ptr(), 1, 0) }; // reg_opt.len = 0
    ret = bpf_load_hdr_opt(skops, reg_opt.as_mut_ptr() as *mut c_void, 6, 0);
    if ret != 4
        || unsafe { ld8(reg_opt.as_ptr(), 1) } != 4
        || unsafe { ld8(reg_opt.as_ptr(), 0) } != 0xB9
        || unsafe { ld8(reg_opt.as_ptr(), 2) } != 0xfa
        || unsafe { ld8(reg_opt.as_ptr(), 3) } != 0xce
    {
        ret_cg_err!(skops, ret as i32);
    }

    let th = vload!((*skops).skb_data) as usize as *const u8;
    let data_end = vload!((*skops).skb_data_end) as usize as *const u8;
    if unsafe { th.add(20) } > data_end {
        ret_cg_err!(skops, 0);
    }

    let byte13 = unsafe { ld8(th, 13) };
    let syn = (byte13 & TCPHDR_SYN) != 0;

    if syn {
        let lp = vload!((*skops).local_port);
        unsafe { active_lport_h = lp as u16 };
        let src = unsafe { ld16(th, 0) };
        unsafe { active_lport_n = src };

        // Search the win scale option written by kernel in the SYN packet.
        ret = bpf_load_hdr_opt(skops, win_scale_opt.as_mut_ptr() as *mut c_void, 6, 0);
        if ret != 3
            || unsafe { ld8(win_scale_opt.as_ptr(), 1) } != 3
            || unsafe { ld8(win_scale_opt.as_ptr(), 0) } != TCPOPT_WINDOW
        {
            ret_cg_err!(skops, ret as i32);
        }

        // Write the win scale option that kernel has already written.
        let err2 = bpf_store_hdr_opt(
            skops,
            win_scale_opt.as_ptr() as *const c_void,
            6,
            0,
        );
        if err2 != EEXIST {
            ret_cg_err!(skops, err2 as i32);
        }
    }

    CG_OK
}

fn handle_hdr_opt_len(skops: *mut bpf_sock_ops) -> i32 {
    let tcp_flags = vload_as!((*skops).skb_tcp_flags, u8);

    if (tcp_flags & TCPHDR_SYNACK) == TCPHDR_SYNACK {
        // Check the SYN from bpf_sock_ops_kern->syn_skb.
        return check_active_syn_in(skops);
    }

    // Passive side should have cleared the write hdr cb by now.
    let lp = vload!((*skops).local_port) as u16;
    if lp == unsafe { passive_lport_h } {
        ret_cg_err!(skops, 0);
    }

    active_opt_len(skops)
}

fn handle_write_hdr_opt(skops: *mut bpf_sock_ops) -> i32 {
    let lp = vload!((*skops).local_port) as u16;
    if lp == unsafe { passive_lport_h } {
        ret_cg_err!(skops, 0);
    }

    write_active_opt(skops)
}

fn handle_parse_hdr(skops: *mut bpf_sock_ops) -> i32 {
    // Passive side is not writing any non-standard/unknown option, so the
    // active side should never be called.
    let lp = vload!((*skops).local_port) as u16;
    if lp == unsafe { active_lport_h } {
        ret_cg_err!(skops, 0);
    }

    check_active_hdr_in(skops)
}

fn handle_passive_estab(skops: *mut bpf_sock_ops) -> i32 {
    // No more write hdr cb.
    let flags = vload!((*skops).bpf_sock_ops_cb_flags);
    bpf_sock_ops_cb_flags_set(
        skops,
        (flags & !BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG) as i32,
    );

    // Recheck the SYN but check the tp->saved_syn this time.
    let err = check_active_syn_in(skops);
    if err == CG_ERR {
        return err;
    }

    unsafe { nr_syn += 1 };

    // The ack has header option written by the active side also.
    check_active_hdr_in(skops)
}

#[link_section = "sockops"]
#[no_mangle]
extern "C" fn misc_estab(skops: *mut bpf_sock_ops) -> i32 {
    let mut true_val: i32 = 1;
    let mut false_val: i32 = 0;

    let op = vload!((*skops).op);

    if op == BPF_SOCK_OPS_TCP_LISTEN_CB {
        let lp = vload!((*skops).local_port) as u16;
        unsafe {
            passive_lport_h = lp;
            passive_lport_n = lp.to_be();
        }
        bpf_setsockopt(
            skops,
            SOL_TCP,
            TCP_SAVE_SYN,
            &mut true_val as *mut i32 as *mut c_void,
            4,
        );
        set_hdr_cb_flags(skops, 0);
    } else if op == BPF_SOCK_OPS_TCP_CONNECT_CB {
        set_hdr_cb_flags(skops, 0);
    } else if op == BPF_SOCK_OPS_PARSE_HDR_OPT_CB {
        return handle_parse_hdr(skops);
    } else if op == BPF_SOCK_OPS_HDR_OPT_LEN_CB {
        let ret = bpf_setsockopt(
            skops,
            SOL_TCP,
            TCP_NODELAY,
            &mut true_val as *mut i32 as *mut c_void,
            4,
        );
        if ret == EOPNOTSUPP {
            unsafe { nodelay_hdr_len_reject = true };
        }
        return handle_hdr_opt_len(skops);
    } else if op == BPF_SOCK_OPS_WRITE_HDR_OPT_CB {
        let ret = bpf_setsockopt(
            skops,
            SOL_TCP,
            TCP_NODELAY,
            &mut true_val as *mut i32 as *mut c_void,
            4,
        );
        if ret == EOPNOTSUPP {
            unsafe { nodelay_write_hdr_reject = true };
        }
        return handle_write_hdr_opt(skops);
    } else if op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB {
        let ret = bpf_setsockopt(
            skops,
            SOL_TCP,
            TCP_NODELAY,
            &mut false_val as *mut i32 as *mut c_void,
            4,
        );
        if ret == 0 {
            unsafe { nodelay_est_ok = true };
        }
        return handle_passive_estab(skops);
    }

    CG_OK
}

bpf_object!("GPL");
