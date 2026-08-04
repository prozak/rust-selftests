#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_bpf_nf.c
// (bpf-rs-core idiom).
//
// The C source shares one function body (`nf_ct_test`/`nf_ct_opts_new_test`)
// between the xdp and tc programs by taking `lookup_fn`/`alloc_fn` as void*
// function pointers cast from the real `bpf_xdp_ct_*`/`bpf_skb_ct_*` kfuncs.
// A real Rust function-pointer value risks surviving as an indirect call
// (`call reg`), which the BPF verifier rejects outside tail-call/callback
// kfunc contexts. `nf_ct_test`/`nf_ct_opts_new_test` are instead generic over
// a `const IS_XDP: bool`; `ct_lookup`/`ct_alloc` branch on that compile-time
// constant, so each of the two monomorphized instantiations contains a
// dead `if`/`else` arm that LLVM folds away, leaving only direct kfunc
// calls -- functionally identical to the C trick, verifier-safe by
// construction instead of by-inlining-luck.
//
// Every conntrack kfunc pointer (nf_conn/nf_conn___init) is carried as
// `*mut c_void` end to end, same as verifier_vfs_accept.rs's kfunc chains:
// the verifier's PTR_TO_BTF_ID tracking for these values comes from the
// actual kfunc call instruction's real kernel prototype (resolved by
// add_ksyms.py from kernel BTF), not from any type we declare locally --
// exactly the property the C source's own `(void *)`-cast function-pointer
// trick already relies on (a `struct nf_conn *`-typed fn-ptr variable
// happily carries a value the verifier still tracks as
// PTR_TO_BTF_ID(nf_conn___init) when passed to `bpf_ct_insert_entry`).
//
// `bpf_ct_opts___local`/`bpf_ct_opts___new` and `bpf_sock_tuple` are
// KF_ARG_PTR_TO_MEM_SIZE kfunc args (paired with an explicit `__sz`/`__len`
// parameter): the kernel's own opts_len check
// (`net/netfilter/nf_conntrack_bpf.c`: `opts_len == NF_BPF_CT_OPTS_SZ(16) ||
// opts_len == 12`) validates size at runtime, not BTF type identity, so
// these are plain local `#[repr(C)]` structs -- no CO-RE needed, and no
// need to match a real kernel type name. `nf_inet_addr_buf` (the
// `bpf_ct_set_nat_info` address argument) is a plain KF_ARG_PTR_TO_MEM: the
// verifier only checks readable/writable size, so a 16-byte local buffer
// (matching `union nf_inet_addr`'s real size, confirmed via
// `bpftool btf dump`) suffices.
//
// `nf_conn`'s real kernel fields (`mark`/`timeout`/`status`/`tuplehash`) are
// read through a genuine `#[btf]` CO-RE chain rooted at the PTR_TO_BTF_ID
// value the alloc/lookup kfuncs return. `tuplehash` is a real (non-flexible)
// `struct nf_conntrack_tuple_hash tuplehash[2]` array; this crate's `#[btf]`
// has no indexed-path support (see btf/src/lib.rs's array `BtfType` impl
// comment), so indexing past element 0 needs plain pointer arithmetic on
// the CO-RE-resolved array base. `TUPLEHASH_ELEM_SIZE` (56) is
// `sizeof(struct nf_conntrack_tuple_hash)`, confirmed against this build's
// own vmlinux BTF via `bpftool btf dump file <vmlinux>` (`STRUCT
// 'nf_conntrack_tuple_hash' size=56`) -- same build-kernel-matches-run-
// kernel precondition as every other hardcoded-offset trick in this repo.
// The resulting element-1 address is reinterpreted as a fresh `#[btf]` root
// (own function per terminal field read, per
// btf-second-field-access-same-root-crashes-opt).
//
// `dst`/`u` are named fields of anonymous struct/union types in the real
// `struct nf_conntrack_tuple`/`nf_conntrack_man` -- named fields of
// anonymous aggregate types need an explicit intermediate `#[btf]` struct
// (see bpf_iter_ipv6_route.rs's `in6_u`); a plain Rust `struct` standing in
// for a target `union` field (`nf_inet_addr`, `nf_conntrack_man_proto`) is
// the same validated pattern that file established.
//
// `CONFIG_HZ` (`__kconfig extern`) is hardcoded to 1000 (this build's
// `CONFIG_HZ_1000=y`) rather than kept as an extern: rustc emits no BTF for
// extern statics, and `prog_tests/bpf_nf.c` never reads `skel->kconfig`, it
// only asserts a tolerance range on `test_delta_timeout` -- same shortcut as
// bpf_iter_tcp4.rs.
//
// Both `nf_ct_test` and `nf_ct_opts_new_test` locally shadow the file-scope
// globals `saddr`/`sport`/`daddr`/`dport` with same-named stack locals
// inside their "alloc succeeded" block (`__u16 sport = ...` etc in C). C's
// scoping silently reverts to the globals once that block ends;
// `nf_ct_test`'s final lookup (the pre-established, iptables-CONNMARK'd
// connection check) depends on this revert. The Rust locals are named
// `nat_*` throughout to make that revert explicit rather than relying on
// shadowing.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_get_prandom_u32, bpf_jiffies64};
use btf_macros::btf;

const EINVAL: i32 = 22;
const ENOENT: i32 = 2;
const EAFNOSUPPORT: i32 = 97;

const CT_OPTS_ERROR_GUARD: i32 = 0x12345678;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;

const NF_NAT_MANIP_SRC: i32 = 0;
const NF_NAT_MANIP_DST: i32 = 1;

const IP_CT_DIR_ORIGINAL: u8 = 0;
const IP_CT_DIR_REPLY: u8 = 1;
const NF_CT_ZONE_DIR_ORIG: u8 = 1 << IP_CT_DIR_ORIGINAL;
const NF_CT_ZONE_DIR_REPL: u8 = 1 << IP_CT_DIR_REPLY;

const IPS_SEEN_REPLY: u32 = 1 << 1;
const IPS_CONFIRMED: u32 = 1 << 3;

const CONFIG_HZ: u64 = 1000;

// sizeof(struct nf_conntrack_tuple_hash) on the target kernel; see file
// header comment.
const TUPLEHASH_ELEM_SIZE: usize = 56;

/// UAPI struct xdp_md (linux/bpf.h).
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    pub ingress_ifindex: u32,
    pub rx_queue_index: u32,
    pub egress_ifindex: u32,
}

// ------------------------------------------------------- locally-typed kfunc args --

// KF_ARG_PTR_TO_MEM_SIZE (opts__sz-checked at runtime, see file header
// comment): local layout, matches C's `bpf_ct_opts___local` (old/12-byte
// ABI shape).
#[repr(C)]
struct bpf_ct_opts___local {
    netns_id: i32,
    error: i32,
    l4proto: u8,
    dir: u8,
    reserved: [u8; 2],
}

// Matches C's `bpf_ct_opts___new` (current/16-byte ABI shape).
#[repr(C)]
struct bpf_ct_opts___new {
    netns_id: i32,
    error: i32,
    l4proto: u8,
    dir: u8,
    ct_zone_id: u16,
    ct_zone_dir: u8,
    reserved: [u8; 3],
}

// KF_ARG_PTR_TO_MEM_SIZE (tuple__sz-checked): only the `.ipv4` union member
// is ever touched, so this struct is simply that member's layout,
// matching `sizeof(bpf_tuple.ipv4)`.
#[repr(C)]
struct bpf_sock_tuple {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

// KF_ARG_PTR_TO_MEM for bpf_ct_set_nat_info's `addr`: 16 bytes, matching
// `union nf_inet_addr`'s real size; `.ip` at offset 0 is the only member
// ever written.
#[repr(C)]
struct nf_inet_addr_buf {
    ip: u32,
    _pad: [u32; 3],
}

// ------------------------------------------------------------- CO-RE chain --

#[btf]
struct nf_inet_addr {
    ip: u32,
}

#[btf]
struct nf_conntrack_man_proto {
    all: u16,
}

#[btf]
struct nf_conntrack_man {
    u3: nf_inet_addr,
    u: nf_conntrack_man_proto,
}

// `struct { union nf_inet_addr u3; union { ... } u; ...; } dst;`: an
// anonymous struct reached through the named field `dst`.
#[btf]
struct nf_conntrack_tuple_dst {
    u3: nf_inet_addr,
    u: nf_conntrack_man_proto,
}

#[btf]
struct nf_conntrack_tuple {
    src: nf_conntrack_man,
    dst: nf_conntrack_tuple_dst,
}

#[btf]
struct nf_conntrack_tuple_hash {
    tuple: nf_conntrack_tuple,
}

#[btf]
struct nf_conn {
    timeout: u32,
    tuplehash: [nf_conntrack_tuple_hash; 2],
    status: u64,
    mark: u32,
}

// -------------------------------------------------------------- kfuncs --

extern "C" {
    fn bpf_xdp_ct_alloc(
        ctx: *mut c_void,
        tuple: *mut c_void,
        tuple_len: u32,
        opts: *mut c_void,
        opts_len: u32,
    ) -> *mut c_void;
    fn bpf_xdp_ct_lookup(
        ctx: *mut c_void,
        tuple: *mut c_void,
        tuple_len: u32,
        opts: *mut c_void,
        opts_len: u32,
    ) -> *mut c_void;
    fn bpf_skb_ct_alloc(
        ctx: *mut c_void,
        tuple: *mut c_void,
        tuple_len: u32,
        opts: *mut c_void,
        opts_len: u32,
    ) -> *mut c_void;
    fn bpf_skb_ct_lookup(
        ctx: *mut c_void,
        tuple: *mut c_void,
        tuple_len: u32,
        opts: *mut c_void,
        opts_len: u32,
    ) -> *mut c_void;
    fn bpf_ct_insert_entry(ct: *mut c_void) -> *mut c_void;
    fn bpf_ct_release(ct: *mut c_void);
    fn bpf_ct_set_timeout(ct: *mut c_void, timeout: u32);
    fn bpf_ct_change_timeout(ct: *mut c_void, timeout: u32) -> i32;
    fn bpf_ct_change_status(ct: *mut c_void, status: u32) -> i32;
    fn bpf_ct_set_nat_info(ct: *mut c_void, addr: *mut c_void, port: i32, manip: i32) -> i32;
}

#[inline(always)]
fn ct_lookup<const IS_XDP: bool>(
    ctx: *mut c_void,
    tuple: *mut bpf_sock_tuple,
    tuple_len: u32,
    opts: *mut c_void,
    opts_len: u32,
) -> *mut c_void {
    unsafe {
        if IS_XDP {
            bpf_xdp_ct_lookup(ctx, tuple as *mut c_void, tuple_len, opts, opts_len)
        } else {
            bpf_skb_ct_lookup(ctx, tuple as *mut c_void, tuple_len, opts, opts_len)
        }
    }
}

#[inline(always)]
fn ct_alloc<const IS_XDP: bool>(
    ctx: *mut c_void,
    tuple: *mut bpf_sock_tuple,
    tuple_len: u32,
    opts: *mut c_void,
    opts_len: u32,
) -> *mut c_void {
    unsafe {
        if IS_XDP {
            bpf_xdp_ct_alloc(ctx, tuple as *mut c_void, tuple_len, opts, opts_len)
        } else {
            bpf_skb_ct_alloc(ctx, tuple as *mut c_void, tuple_len, opts, opts_len)
        }
    }
}

// ------------------------------------------------- branch-isolated CO-RE reads --

#[inline(never)]
fn ct_mark_get(ct: *const nf_conn) -> u32 {
    *unsafe { &*ct }.mark().get().unwrap()
}

#[inline(never)]
fn ct_mark_set(ct: *const nf_conn, v: u32) {
    unsafe { *(&*ct).mark().as_mut_ptr() = v };
}

#[inline(never)]
fn ct_timeout_get(ct: *const nf_conn) -> u32 {
    *unsafe { &*ct }.timeout().get().unwrap()
}

#[inline(never)]
fn ct_status_get(ct: *const nf_conn) -> u64 {
    *unsafe { &*ct }.status().get().unwrap()
}

#[inline(never)]
fn ct_tuplehash_base(ct: *const nf_conn) -> *const u8 {
    unsafe { &*ct }.tuplehash().as_ptr() as *const u8
}

fn ct_reply_hash(ct: *const nf_conn) -> *const nf_conntrack_tuple_hash {
    unsafe { ct_tuplehash_base(ct).add(TUPLEHASH_ELEM_SIZE) as *const nf_conntrack_tuple_hash }
}

#[inline(never)]
fn ct_reply_dst_ip(reply: *const nf_conntrack_tuple_hash) -> u32 {
    *unsafe { &*reply }.tuple().dst().u3().ip().get().unwrap()
}

#[inline(never)]
fn ct_reply_dst_all(reply: *const nf_conntrack_tuple_hash) -> u16 {
    *unsafe { &*reply }.tuple().dst().u().all().get().unwrap()
}

#[inline(never)]
fn ct_reply_src_ip(reply: *const nf_conntrack_tuple_hash) -> u32 {
    *unsafe { &*reply }.tuple().src().u3().ip().get().unwrap()
}

#[inline(never)]
fn ct_reply_src_all(reply: *const nf_conntrack_tuple_hash) -> u16 {
    *unsafe { &*reply }.tuple().src().u().all().get().unwrap()
}

// -------------------------------------------------------------- globals --

#[no_mangle]
static mut test_einval_reserved: i32 = 0;
#[no_mangle]
static mut test_einval_reserved_new: i32 = 0;
#[no_mangle]
static mut test_einval_netns_id: i32 = 0;
#[no_mangle]
static mut test_einval_len_opts: i32 = 0;
#[no_mangle]
static mut test_einval_len_opts_small_lookup: i32 = 0;
#[no_mangle]
static mut test_einval_len_opts_small_alloc: i32 = 0;
#[no_mangle]
static mut test_eproto_l4proto: i32 = 0;
#[no_mangle]
static mut test_enonet_netns_id: i32 = 0;
#[no_mangle]
static mut test_enoent_lookup: i32 = 0;
#[no_mangle]
static mut test_eafnosupport: i32 = 0;
#[no_mangle]
static mut test_alloc_entry: i32 = -EINVAL;
#[no_mangle]
static mut test_insert_entry: i32 = -EAFNOSUPPORT;
#[no_mangle]
static mut test_succ_lookup: i32 = -ENOENT;
#[no_mangle]
static mut test_ct_zone_id_alloc_entry: i32 = -EINVAL;
#[no_mangle]
static mut test_ct_zone_id_insert_entry: i32 = -EAFNOSUPPORT;
#[no_mangle]
static mut test_ct_zone_id_succ_lookup: i32 = -ENOENT;
#[no_mangle]
static mut test_ct_zone_dir_enoent_lookup: i32 = 0;
#[no_mangle]
static mut test_ct_zone_id_enoent_lookup: i32 = 0;
#[no_mangle]
static mut test_delta_timeout: u32 = 0;
#[no_mangle]
static mut test_status: u32 = 0;
#[no_mangle]
static mut test_insert_lookup_mark: u32 = 0;
#[no_mangle]
static mut test_snat_addr: i32 = -EINVAL;
#[no_mangle]
static mut test_dnat_addr: i32 = -EINVAL;
#[no_mangle]
static mut saddr: u32 = 0;
#[no_mangle]
static mut sport: u16 = 0;
#[no_mangle]
static mut daddr: u32 = 0;
#[no_mangle]
static mut dport: u16 = 0;
#[no_mangle]
static mut test_exist_lookup: i32 = -ENOENT;
#[no_mangle]
static mut test_exist_lookup_mark: u32 = 0;

// -------------------------------------------------------------- test bodies --

fn nf_ct_test<const IS_XDP: bool>(ctx: *mut c_void) {
    let mut opts_def = bpf_ct_opts___local {
        netns_id: -1,
        error: 0,
        l4proto: IPPROTO_TCP,
        dir: 0,
        reserved: [0, 0],
    };
    let mut bpf_tuple = bpf_sock_tuple {
        saddr: 0,
        daddr: 0,
        sport: 0,
        dport: 0,
    };
    let tuple_sz = core::mem::size_of::<bpf_sock_tuple>() as u32;
    let opts_sz = core::mem::size_of::<bpf_ct_opts___local>() as u32;

    opts_def.reserved[0] = 1;
    let mut ct = ct_lookup::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz,
        &mut opts_def as *mut _ as *mut c_void,
        opts_sz,
    );
    opts_def.reserved[0] = 0;
    opts_def.l4proto = IPPROTO_TCP;
    if !ct.is_null() {
        unsafe { bpf_ct_release(ct) };
    } else {
        unsafe { test_einval_reserved = opts_def.error };
    }

    opts_def.netns_id = -2;
    ct = ct_lookup::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz,
        &mut opts_def as *mut _ as *mut c_void,
        opts_sz,
    );
    opts_def.netns_id = -1;
    if !ct.is_null() {
        unsafe { bpf_ct_release(ct) };
    } else {
        unsafe { test_einval_netns_id = opts_def.error };
    }

    ct = ct_lookup::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz,
        &mut opts_def as *mut _ as *mut c_void,
        opts_sz - 1,
    );
    if !ct.is_null() {
        unsafe { bpf_ct_release(ct) };
    } else {
        unsafe { test_einval_len_opts = opts_def.error };
    }

    opts_def.error = CT_OPTS_ERROR_GUARD;
    ct = ct_lookup::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz,
        &mut opts_def as *mut _ as *mut c_void,
        core::mem::size_of::<i32>() as u32,
    );
    if !ct.is_null() {
        unsafe { bpf_ct_release(ct) };
        unsafe { test_einval_len_opts_small_lookup = -EINVAL };
    } else {
        unsafe { test_einval_len_opts_small_lookup = opts_def.error };
    }

    opts_def.error = CT_OPTS_ERROR_GUARD;
    ct = ct_alloc::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz,
        &mut opts_def as *mut _ as *mut c_void,
        core::mem::size_of::<i32>() as u32,
    );
    if !ct.is_null() {
        ct = unsafe { bpf_ct_insert_entry(ct) };
        if !ct.is_null() {
            unsafe { bpf_ct_release(ct) };
        }
        unsafe { test_einval_len_opts_small_alloc = -EINVAL };
    } else {
        unsafe { test_einval_len_opts_small_alloc = opts_def.error };
    }

    opts_def.l4proto = IPPROTO_ICMP;
    ct = ct_lookup::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz,
        &mut opts_def as *mut _ as *mut c_void,
        opts_sz,
    );
    opts_def.l4proto = IPPROTO_TCP;
    if !ct.is_null() {
        unsafe { bpf_ct_release(ct) };
    } else {
        unsafe { test_eproto_l4proto = opts_def.error };
    }

    opts_def.netns_id = 0xf00f;
    ct = ct_lookup::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz,
        &mut opts_def as *mut _ as *mut c_void,
        opts_sz,
    );
    opts_def.netns_id = -1;
    if !ct.is_null() {
        unsafe { bpf_ct_release(ct) };
    } else {
        unsafe { test_enonet_netns_id = opts_def.error };
    }

    ct = ct_lookup::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz,
        &mut opts_def as *mut _ as *mut c_void,
        opts_sz,
    );
    if !ct.is_null() {
        unsafe { bpf_ct_release(ct) };
    } else {
        unsafe { test_enoent_lookup = opts_def.error };
    }

    ct = ct_lookup::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz - 1,
        &mut opts_def as *mut _ as *mut c_void,
        opts_sz,
    );
    if !ct.is_null() {
        unsafe { bpf_ct_release(ct) };
    } else {
        unsafe { test_eafnosupport = opts_def.error };
    }

    bpf_tuple.saddr = bpf_get_prandom_u32();
    bpf_tuple.daddr = bpf_get_prandom_u32();
    bpf_tuple.sport = bpf_get_prandom_u32() as u16;
    bpf_tuple.dport = bpf_get_prandom_u32() as u16;

    ct = ct_alloc::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz,
        &mut opts_def as *mut _ as *mut c_void,
        opts_sz,
    );
    if !ct.is_null() {
        let nat_sport: u16 = bpf_get_prandom_u32() as u16;
        let nat_dport: u16 = bpf_get_prandom_u32() as u16;
        let mut nat_saddr = nf_inet_addr_buf {
            ip: 0,
            _pad: [0; 3],
        };
        let mut nat_daddr = nf_inet_addr_buf {
            ip: 0,
            _pad: [0; 3],
        };

        unsafe { bpf_ct_set_timeout(ct, 10000) };
        ct_mark_set(ct as *const nf_conn, 77);

        nat_saddr.ip = bpf_get_prandom_u32();
        unsafe {
            bpf_ct_set_nat_info(
                ct,
                &mut nat_saddr as *mut _ as *mut c_void,
                nat_sport as i32,
                NF_NAT_MANIP_SRC,
            )
        };
        nat_daddr.ip = bpf_get_prandom_u32();
        unsafe {
            bpf_ct_set_nat_info(
                ct,
                &mut nat_daddr as *mut _ as *mut c_void,
                nat_dport as i32,
                NF_NAT_MANIP_DST,
            )
        };

        let ct_ins = unsafe { bpf_ct_insert_entry(ct) };
        if !ct_ins.is_null() {
            let ct_lk = ct_lookup::<IS_XDP>(
                ctx,
                &mut bpf_tuple,
                tuple_sz,
                &mut opts_def as *mut _ as *mut c_void,
                opts_sz,
            );
            if !ct_lk.is_null() {
                let reply = ct_reply_hash(ct_lk as *const nf_conn);
                let dst_ip = ct_reply_dst_ip(reply);
                let dst_all = ct_reply_dst_all(reply);
                let src_ip = ct_reply_src_ip(reply);
                let src_all = ct_reply_src_all(reply);

                if dst_ip == nat_saddr.ip && dst_all == nat_sport.to_be() {
                    unsafe { test_snat_addr = 0 };
                }
                if src_ip == nat_daddr.ip && src_all == nat_dport.to_be() {
                    unsafe { test_dnat_addr = 0 };
                }

                unsafe { bpf_ct_change_timeout(ct_lk, 10000) };
                let timeout = ct_timeout_get(ct_lk as *const nf_conn) as u64;
                let now = bpf_jiffies64();
                unsafe { test_delta_timeout = timeout.wrapping_sub(now) as u32 };
                unsafe { test_delta_timeout = ((test_delta_timeout as u64) / CONFIG_HZ) as u32 };
                unsafe { test_insert_lookup_mark = ct_mark_get(ct_lk as *const nf_conn) };
                unsafe { bpf_ct_change_status(ct_lk, IPS_CONFIRMED | IPS_SEEN_REPLY) };
                unsafe { test_status = ct_status_get(ct_lk as *const nf_conn) as u32 };

                unsafe { bpf_ct_release(ct_lk) };
                unsafe { test_succ_lookup = 0 };
            }
            unsafe { bpf_ct_release(ct_ins) };
            unsafe { test_insert_entry = 0 };
        }
        unsafe { test_alloc_entry = 0 };
    }

    bpf_tuple.saddr = unsafe { saddr };
    bpf_tuple.daddr = unsafe { daddr };
    bpf_tuple.sport = unsafe { sport };
    bpf_tuple.dport = unsafe { dport };
    ct = ct_lookup::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz,
        &mut opts_def as *mut _ as *mut c_void,
        opts_sz,
    );
    if !ct.is_null() {
        unsafe { test_exist_lookup = 0 };
        if ct_mark_get(ct as *const nf_conn) == 42 {
            ct_mark_set(ct as *const nf_conn, 43);
            unsafe { test_exist_lookup_mark = ct_mark_get(ct as *const nf_conn) };
        }
        unsafe { bpf_ct_release(ct) };
    } else {
        unsafe { test_exist_lookup = opts_def.error };
    }
}

fn nf_ct_opts_new_test<const IS_XDP: bool>(ctx: *mut c_void) {
    let mut opts_def = bpf_ct_opts___new {
        netns_id: -1,
        error: 0,
        l4proto: IPPROTO_TCP,
        dir: 0,
        ct_zone_id: 0,
        ct_zone_dir: 0,
        reserved: [0, 0, 0],
    };
    let mut bpf_tuple = bpf_sock_tuple {
        saddr: 0,
        daddr: 0,
        sport: 0,
        dport: 0,
    };
    let tuple_sz = core::mem::size_of::<bpf_sock_tuple>() as u32;
    let opts_sz = core::mem::size_of::<bpf_ct_opts___new>() as u32;

    opts_def.reserved[0] = 1;
    let mut ct = ct_lookup::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz,
        &mut opts_def as *mut _ as *mut c_void,
        opts_sz,
    );
    opts_def.reserved[0] = 0;
    if !ct.is_null() {
        unsafe { bpf_ct_release(ct) };
    } else {
        unsafe { test_einval_reserved_new = opts_def.error };
    }

    bpf_tuple.saddr = bpf_get_prandom_u32();
    bpf_tuple.daddr = bpf_get_prandom_u32();
    bpf_tuple.sport = bpf_get_prandom_u32() as u16;
    bpf_tuple.dport = bpf_get_prandom_u32() as u16;

    opts_def.ct_zone_id = 10;
    opts_def.ct_zone_dir = NF_CT_ZONE_DIR_ORIG;
    ct = ct_alloc::<IS_XDP>(
        ctx,
        &mut bpf_tuple,
        tuple_sz,
        &mut opts_def as *mut _ as *mut c_void,
        opts_sz,
    );
    if !ct.is_null() {
        let nat_sport: u16 = bpf_get_prandom_u32() as u16;
        let nat_dport: u16 = bpf_get_prandom_u32() as u16;
        let mut nat_saddr = nf_inet_addr_buf {
            ip: 0,
            _pad: [0; 3],
        };
        let mut nat_daddr = nf_inet_addr_buf {
            ip: 0,
            _pad: [0; 3],
        };

        unsafe { bpf_ct_set_timeout(ct, 10000) };

        nat_saddr.ip = bpf_get_prandom_u32();
        unsafe {
            bpf_ct_set_nat_info(
                ct,
                &mut nat_saddr as *mut _ as *mut c_void,
                nat_sport as i32,
                NF_NAT_MANIP_SRC,
            )
        };
        nat_daddr.ip = bpf_get_prandom_u32();
        unsafe {
            bpf_ct_set_nat_info(
                ct,
                &mut nat_daddr as *mut _ as *mut c_void,
                nat_dport as i32,
                NF_NAT_MANIP_DST,
            )
        };

        let ct_ins = unsafe { bpf_ct_insert_entry(ct) };
        if !ct_ins.is_null() {
            let mut ct_lk = ct_lookup::<IS_XDP>(
                ctx,
                &mut bpf_tuple,
                tuple_sz,
                &mut opts_def as *mut _ as *mut c_void,
                opts_sz,
            );
            if !ct_lk.is_null() {
                unsafe { bpf_ct_release(ct_lk) };
                unsafe { test_ct_zone_id_succ_lookup = 0 };
            }

            opts_def.ct_zone_dir = NF_CT_ZONE_DIR_REPL;
            ct_lk = ct_lookup::<IS_XDP>(
                ctx,
                &mut bpf_tuple,
                tuple_sz,
                &mut opts_def as *mut _ as *mut c_void,
                opts_sz,
            );
            opts_def.ct_zone_dir = NF_CT_ZONE_DIR_ORIG;
            if !ct_lk.is_null() {
                unsafe { bpf_ct_release(ct_lk) };
            } else {
                unsafe { test_ct_zone_dir_enoent_lookup = opts_def.error };
            }

            opts_def.ct_zone_id = 0;
            ct_lk = ct_lookup::<IS_XDP>(
                ctx,
                &mut bpf_tuple,
                tuple_sz,
                &mut opts_def as *mut _ as *mut c_void,
                opts_sz,
            );
            if !ct_lk.is_null() {
                unsafe { bpf_ct_release(ct_lk) };
            } else {
                unsafe { test_ct_zone_id_enoent_lookup = opts_def.error };
            }

            unsafe { bpf_ct_release(ct_ins) };
            unsafe { test_ct_zone_id_insert_entry = 0 };
        }
        unsafe { test_ct_zone_id_alloc_entry = 0 };
    }
}

// ------------------------------------------------------------- programs --

#[link_section = "xdp"]
#[no_mangle]
extern "C" fn nf_xdp_ct_test(ctx: *const xdp_md) -> i32 {
    nf_ct_test::<true>(ctx as *mut c_void);
    nf_ct_opts_new_test::<true>(ctx as *mut c_void);
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn nf_skb_ct_test(ctx: *const __sk_buff) -> i32 {
    nf_ct_test::<false>(ctx as *mut c_void);
    nf_ct_opts_new_test::<false>(ctx as *mut c_void);
    0
}

bpf_object!("GPL");
