#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_ipv6_route.c
// (bpf-rs-core idiom).
//
// C's `extern bool CONFIG_IPV6_SUBTREES __kconfig __weak;` is elided: rustc
// emits no BTF for an extern static (kconfig externs are unfixable), and
// prog_tests/bpf_iter.c's test_ipv6_route() only drives a dummy read that
// discards the printed content ("not check contents, but ensure read() ends
// without error"), so the CONFIG_IPV6_SUBTREES branch is hardcoded to the C
// source's `else` arm (a kernel built with IPV6_SUBTREES disabled would take
// the same path).
//
// `rt->fib6_nh[0]` (a C99 flexible array member) and `nh->nh_info->fib6_nh`
// are both plain `struct fib6_nh` accesses at the field-name level; the
// flexible-array member contributes no elements to `sizeof(struct
// fib6_info)`, so `&rt->fib6_nh[0]` is simply the address of that trailing
// field, matched here as an ordinary (non-array) `#[btf]` field the same way
// `nh_info->fib6_nh` is.
//
// The two `fib6_nh` sources (`rt`'s own trailing field vs. `nh->nh_info`'s)
// must be read by two separate `#[inline(never)]` helpers rather than
// selected between with a plain `if/else` expression: merging two `#[btf]`
// chains' terminal `.as_ptr()` reads into one shared variable across a
// branch corrupts the field-relocation debug info bpf-postproc's
// FieldRelocPass depends on ("no path parameter type"); routing each chain
// through its own never-inlined function keeps their CO-RE polyfill calls
// debug-info-isolated (same workaround family as the sh_info-corruption
// shared-fn fix used elsewhere in this crate).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_seq_printf;
use btf_macros::btf;
use core::ffi::c_void;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__ipv6_route {
    meta: *mut bpf_iter_meta,
    rt: *mut fib6_info,
}

#[btf]
struct atomic_t {
    counter: i32,
}

#[btf]
struct refcount_t {
    refs: atomic_t,
}

#[btf]
struct in6_u {
    u6_addr8: [u8; 16],
}

// `struct in6_addr { union { __u8 u6_addr8[16]; ... } in6_u; }`: `in6_u` is a
// *named* union member (unlike e.g. `nexthop`'s `nh_info`/`nh_grp`, which is
// a true anonymous member with no trailing identifier and so auto-flattens
// under CO-RE field matching), so it must be declared and traversed
// explicitly here rather than skipped straight to `u6_addr8`.
#[btf]
struct in6_addr {
    in6_u: in6_u,
}

#[btf]
struct rt6key {
    addr: in6_addr,
    plen: i32,
}

#[btf]
struct nhc_gw_union {
    ipv6: in6_addr,
}

#[btf]
struct net_device {
    name: [u8; 16],
}

#[btf]
struct fib_nh_common {
    nhc_dev: *mut net_device,
    nhc_gw_family: u8,
    nhc_gw: nhc_gw_union,
}

#[btf]
struct fib6_nh {
    nh_common: fib_nh_common,
}

#[btf]
struct nh_info {
    fib6_nh: fib6_nh,
}

#[btf]
struct nexthop {
    nh_info: *mut nh_info,
}

#[btf]
struct fib6_info {
    fib6_ref: refcount_t,
    fib6_dst: rt6key,
    fib6_flags: u32,
    fib6_metric: u32,
    nh: *mut nexthop,
    // `struct fib6_nh fib6_nh[0]`: a C99 flexible array member. Declaring it
    // as a plain (non-array) `#[btf]` field mismatches the target BTF's
    // ARRAY kind and fails CO-RE byte-offset resolution at load
    // ("failed to resolve CO-RE relocation ... fib6_info.fib6_nh..."); an
    // array-of-1 keeps the ARRAY kind so the outer field offset resolves,
    // and its element address (via `.as_ptr()`, cast, then a fresh deref)
    // is exactly `&rt->fib6_nh[0]`.
    fib6_nh: [fib6_nh; 1],
}

const RTF_GATEWAY: u32 = 0x0002;

#[inline(never)]
fn nh_info_from_rt(rt: &fib6_info) -> (u8, *const u8, *mut net_device) {
    unsafe {
        let fib6_nh_ptr = rt.fib6_nh().as_ptr() as *const fib6_nh;
        let fib6_nh_ref = &*fib6_nh_ptr;
        let gw_family = *fib6_nh_ref.nh_common().nhc_gw_family().as_ptr();
        let gw6_ptr = fib6_nh_ref
            .nh_common()
            .nhc_gw()
            .ipv6()
            .in6_u()
            .u6_addr8()
            .as_ptr() as *const u8;
        let dev_ptr = *fib6_nh_ref.nh_common().nhc_dev().as_ptr();
        (gw_family, gw6_ptr, dev_ptr)
    }
}

#[inline(never)]
fn nh_info_from_nexthop(nh_info_ref: &nh_info) -> (u8, *const u8, *mut net_device) {
    unsafe {
        let gw_family = *nh_info_ref.fib6_nh().nh_common().nhc_gw_family().as_ptr();
        let gw6_ptr = nh_info_ref
            .fib6_nh()
            .nh_common()
            .nhc_gw()
            .ipv6()
            .in6_u()
            .u6_addr8()
            .as_ptr() as *const u8;
        let dev_ptr = *nh_info_ref.fib6_nh().nh_common().nhc_dev().as_ptr();
        (gw_family, gw6_ptr, dev_ptr)
    }
}

#[link_section = "iter/ipv6_route"]
#[no_mangle]
extern "C" fn dump_ipv6_route(ctx: *const bpf_iter__ipv6_route) -> i32 {
    let ctx = unsafe { &*ctx };
    if ctx.rt.is_null() {
        return 0;
    }
    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;
    let rt = unsafe { &*ctx.rt };

    let mut flags = unsafe { *rt.fib6_flags().as_ptr() };
    let nh_ptr = unsafe { *rt.nh().as_ptr() };

    let (gw_family, gw6_ptr, dev_ptr) = if !nh_ptr.is_null() {
        let nh_ref = unsafe { &*nh_ptr };
        let nh_info_ptr = unsafe { *nh_ref.nh_info().as_ptr() };
        let nh_info_ref = unsafe { &*nh_info_ptr };
        nh_info_from_nexthop(nh_info_ref)
    } else {
        nh_info_from_rt(rt)
    };

    let dst_addr = rt.fib6_dst().addr().in6_u().u6_addr8().as_ptr();
    let dst_plen = unsafe { *rt.fib6_dst().plen().as_ptr() } as u32;

    static FMT_DST: [u8; 11] = *b"%pi6 %02x \0";
    let params_dst: [u64; 2] = [dst_addr as u64, dst_plen as u64];
    bpf_seq_printf(
        seq,
        FMT_DST.as_ptr() as *const c_void,
        FMT_DST.len() as u32,
        params_dst.as_ptr() as *const c_void,
        core::mem::size_of_val(&params_dst) as u32,
    );

    static FMT_SRC_ZERO: [u8; 37] = *b"00000000000000000000000000000000 00 \0";
    bpf_seq_printf(
        seq,
        FMT_SRC_ZERO.as_ptr() as *const c_void,
        FMT_SRC_ZERO.len() as u32,
        core::ptr::null(),
        0,
    );

    if gw_family != 0 {
        flags |= RTF_GATEWAY;
        static FMT_GW: [u8; 6] = *b"%pi6 \0";
        let params_gw: [u64; 1] = [gw6_ptr as u64];
        bpf_seq_printf(
            seq,
            FMT_GW.as_ptr() as *const c_void,
            FMT_GW.len() as u32,
            params_gw.as_ptr() as *const c_void,
            core::mem::size_of_val(&params_gw) as u32,
        );
    } else {
        static FMT_GW_ZERO: [u8; 34] = *b"00000000000000000000000000000000 \0";
        bpf_seq_printf(
            seq,
            FMT_GW_ZERO.as_ptr() as *const c_void,
            FMT_GW_ZERO.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    let fib6_metric = unsafe { *rt.fib6_metric().as_ptr() };
    let refcnt = unsafe { *rt.fib6_ref().refs().counter().as_ptr() } as u32;

    if !dev_ptr.is_null() {
        let dev_ref = unsafe { &*dev_ptr };
        let name_ptr = dev_ref.name().as_ptr();
        static FMT_TAIL_DEV: [u8; 25] = *b"%08x %08x %08x %08x %8s\n\0";
        let params_tail: [u64; 5] = [
            fib6_metric as u64,
            refcnt as u64,
            0,
            flags as u64,
            name_ptr as u64,
        ];
        bpf_seq_printf(
            seq,
            FMT_TAIL_DEV.as_ptr() as *const c_void,
            FMT_TAIL_DEV.len() as u32,
            params_tail.as_ptr() as *const c_void,
            core::mem::size_of_val(&params_tail) as u32,
        );
    } else {
        static FMT_TAIL: [u8; 21] = *b"%08x %08x %08x %08x\n\0";
        let params_tail: [u64; 4] = [fib6_metric as u64, refcnt as u64, 0, flags as u64];
        bpf_seq_printf(
            seq,
            FMT_TAIL.as_ptr() as *const c_void,
            FMT_TAIL.len() as u32,
            params_tail.as_ptr() as *const c_void,
            core::mem::size_of_val(&params_tail) as u32,
        );
    }

    0
}

bpf_object!("GPL");
