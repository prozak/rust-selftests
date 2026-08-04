#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/sock_iter_batch.c
// (bpf-rs-core idiom).
//
// C's `sk = bpf_core_cast(sk, struct sock)` / `bpf_core_cast(sk, struct
// sock)` re-tags the pointer's verifier-tracked BTF type purely so
// subsequent `->` field reads validate against `struct sock`'s type tree
// instead of the narrower ctx-registered type (`sock_common` for
// iter/tcp's `sk_common`, `udp_sock` for iter/udp's `udp_sk`). It is
// unnecessary here: every field this program reads (sk_family, sk_state,
// sk_v6_rcv_saddr, sk_rcv_saddr, sk_num, sk_net -- all `#define`d in
// net/sock.h as `__sk_common.skc_*`) lives inside `struct sock_common`
// itself, and `struct sock_common` sits at byte offset 0 of both `struct
// sock` and `struct udp_sock` (`inet_sock`/`udp_sock` docs: "has to be the
// first member"). The verifier's `btf_struct_walk` validates a raw
// (root_type, byte_offset) pair by recursing through embedded (non-pointer)
// members regardless of which local `#[btf]` struct name was used to
// compute that offset at CO-RE-relocation time -- so a `#[btf] struct
// sock_common` reached via a plain pointer reinterpret (mirroring C's own
// `(struct sock *)ctx->sk_common` / `(struct sock *)ctx->udp_sk` casts,
// which are themselves plain reinterprets, not CO-RE casts) walks
// successfully from either ctx-registered root type. `bpf_rdonly_cast`
// itself is unreachable from this pipeline anyway: its `type` argument
// needs `bpf_core_type_id_kernel()`, a `BPF_CORE_TYPE_ID_KERNEL` relocation
// the btf-macros crate doesn't implement (see type_cast.rs).
//
// ipv4_addr_loopback/ipv6_addr_loopback are routed through their own
// `#[inline(never)]` functions (see
// btf-chain-merge-across-branches-corrupts-debuginfo) since the caller
// picks between them via a runtime `if sk_family == AF_INET6` -- merging
// two distinct `#[btf]` chains' terminal reads into one if/else-selected
// SSA value corrupts bpf-postproc's field-reloc debuginfo; each branch
// must fully resolve inside its own never-inlined call.
//
// `net->hash_mix`/`net->ipv4.tcp_death_row.hashinfo`/`->lhash2_mask` and
// `sk->sk_net.net->ipv4.udp_table`/`->mask` are ordinary CO-RE walks
// through real (distinct, non-sock_common) kernel struct pointers reached
// via named fields -- no special handling needed. `udp_sk(sk)->
// udp_portaddr_hash` is `container_of(sk, struct udp_sock, inet.sk)
// ->udp_portaddr_hash`, and since `inet`/`sk` are both first-members
// (offset 0), that macro expands to `sk->__sk_common.skc_u16hashes[1]`
// -- read straight off the same `sock_common` view via `skc_u16hashes`
// (an anonymous, unnamed union member of `sock_common`, so it flattens
// directly onto the struct per the same auto-flatten rule as
// `skc_family`/`skc_rcv_saddr`).
//
// `sk_v6_rcv_saddr.s6_addr32` (`in6_addr.in6_u.u6_addr32`) is bulk-read via
// `bpf_probe_read_kernel` into a local `[u32; 4]` rather than walked
// element-by-element through the CO-RE pointer, both because `in6_u` is a
// *named* union member (needs an explicit intermediate `#[btf]` struct,
// see btf-named-union-member-no-auto-flatten) and because `jhash2` then
// needs to stride an arbitrary sub-slice of it in a loop -- easiest done
// safely on an already-local, plain-Rust array (same bulk-copy precedent
// as mptcp_sock.rs's `ca_name`).
//
// `bpf_get_socket_cookie` is the `bpf_get_socket_ptr_cookie_proto` overload
// for tracing/iter programs (`ARG_PTR_TO_BTF_ID_SOCK_COMMON`), added to
// bpf-rs-core/src/helpers.rs (FN id 46, existing thunk! pattern -- no prior
// wrapper existed). `bpf_sock_destroy` is a real kfunc (net/core/filter.c),
// declared extern per the kfunc section.
//
// `bucket[idx]`/`ports[N]` use raw pointer arithmetic instead of Rust array
// indexing where the index is a runtime value (`idx`), matching the
// pkt-bounds-check-needs-raw-pointer-add precedent -- a runtime-index
// `[]` access emits a bounds-check panic branch the verifier rejects as
// unreachable-but-present code.

use core::ffi::c_void;

use bpf_rs_core::helpers::{bpf_get_socket_cookie, bpf_probe_read_kernel, bpf_seq_write};
use bpf_rs_core::bpf_object;
use btf_macros::btf;

const AF_INET6: u16 = 10;

// ------------------------------------------------------------------ ctx --

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__tcp {
    meta: *mut bpf_iter_meta,
    sk_common: *mut sock_common,
    // uid_t uid __aligned(8); -- unused, omitted.
}

#[repr(C)]
struct bpf_iter__udp {
    meta: *mut bpf_iter_meta,
    // Real kernel type is `struct udp_sock *` (PTR_TRUSTED); kept as
    // c_void here and reinterpreted below, mirroring the C source's own
    // `(struct sock *)ctx->udp_sk` plain cast (see file header comment).
    udp_sk: *mut c_void,
    // uid_t uid __aligned(8); int bucket __aligned(8); -- unused, omitted.
}

// -------------------------------------------------------- kernel structs --

#[btf]
struct in6_u_union {
    u6_addr32: [u32; 4],
}

#[btf]
struct in6_addr {
    in6_u: in6_u_union,
}

#[btf]
struct possible_net_t {
    net: *mut net,
}

#[btf]
struct sock_common {
    skc_rcv_saddr: u32,
    skc_v6_rcv_saddr: in6_addr,
    skc_num: u16,
    skc_family: u16,
    skc_state: u8,
    skc_net: possible_net_t,
    skc_u16hashes: [u16; 2],
}

#[btf]
struct inet_hashinfo {
    lhash2_mask: u32,
}

#[btf]
struct inet_timewait_death_row {
    hashinfo: *mut inet_hashinfo,
}

#[btf]
struct udp_table {
    mask: u32,
}

#[btf]
struct netns_ipv4 {
    tcp_death_row: inet_timewait_death_row,
    udp_table: *mut udp_table,
}

#[btf]
struct net {
    hash_mix: u32,
    ipv4: netns_ipv4,
}

extern "C" {
    fn bpf_sock_destroy(sock: *mut sock_common) -> i32;
}

// -------------------------------------------------------------- globals --

#[link_section = ".rodata"]
#[no_mangle]
static sf: u32 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static ss: u32 = 0;
#[link_section = ".rodata"]
#[no_mangle]
static ports: [u16; 2] = [0; 2];
#[no_mangle]
static mut bucket: [u32; 2] = [0; 2];
#[link_section = ".rodata"]
#[no_mangle]
static destroy_cookie: u64 = 0;

// ---------------------------------------------------------------- jhash --
// tools/testing/selftests/bpf/progs/test_jhash.h's jhash2, only the
// entry point this file actually calls.

const JHASH_INITVAL: u32 = 0xdeadbeef;

#[inline(always)]
fn rol32(word: u32, shift: u32) -> u32 {
    word.rotate_left(shift)
}

#[inline(always)]
fn jhash_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c);
    *a ^= rol32(*c, 4);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= rol32(*a, 6);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= rol32(*b, 8);
    *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c);
    *a ^= rol32(*c, 16);
    *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a);
    *b ^= rol32(*a, 19);
    *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b);
    *c ^= rol32(*b, 4);
    *b = b.wrapping_add(*a);
}

#[inline(always)]
fn jhash_final(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b;
    *c = c.wrapping_sub(rol32(*b, 14));
    *a ^= *c;
    *a = a.wrapping_sub(rol32(*c, 11));
    *b ^= *a;
    *b = b.wrapping_sub(rol32(*a, 25));
    *c ^= *b;
    *c = c.wrapping_sub(rol32(*b, 16));
    *a ^= *c;
    *a = a.wrapping_sub(rol32(*c, 4));
    *b ^= *a;
    *b = b.wrapping_sub(rol32(*a, 14));
    *c ^= *b;
    *c = c.wrapping_sub(rol32(*b, 24));
}

fn jhash2(k: &[u32; 4], length: u32, initval: u32) -> u32 {
    let mut a = JHASH_INITVAL
        .wrapping_add(length << 2)
        .wrapping_add(initval);
    let mut b = a;
    let mut c = a;

    let mut len = length;
    let mut idx: usize = 0;
    while len > 3 {
        a = a.wrapping_add(k[idx]);
        b = b.wrapping_add(k[idx + 1]);
        c = c.wrapping_add(k[idx + 2]);
        jhash_mix(&mut a, &mut b, &mut c);
        len -= 3;
        idx += 3;
    }

    if len >= 1 {
        if len >= 3 {
            c = c.wrapping_add(k[idx + 2]);
        }
        if len >= 2 {
            b = b.wrapping_add(k[idx + 1]);
        }
        a = a.wrapping_add(k[idx]);
        jhash_final(&mut a, &mut b, &mut c);
    }

    c
}

// ------------------------------------------------------------- helpers --

#[inline(never)]
fn ipv4_addr_loopback(sk: *mut sock_common) -> bool {
    let sk_ref = unsafe { &*sk };
    let saddr = unsafe { *sk_ref.skc_rcv_saddr().as_ptr() };
    saddr == 0x7f000001u32.swap_bytes()
}

#[inline(never)]
fn ipv6_addr_loopback(sk: *mut sock_common) -> bool {
    let sk_ref = unsafe { &*sk };
    let mut addr32: [u32; 4] = [0; 4];
    bpf_probe_read_kernel(
        &mut addr32,
        16,
        sk_ref.skc_v6_rcv_saddr().in6_u().u6_addr32().as_ptr() as *const c_void,
    );
    (addr32[0] | addr32[1] | addr32[2] | (addr32[3] ^ 1u32.swap_bytes())) == 0
}

#[inline(never)]
fn read_v6_addr(sk: *mut sock_common, out: &mut [u32; 4]) {
    let sk_ref = unsafe { &*sk };
    bpf_probe_read_kernel(
        out,
        16,
        sk_ref.skc_v6_rcv_saddr().in6_u().u6_addr32().as_ptr() as *const c_void,
    );
}

#[inline(always)]
fn store_bucket(idx: i32, val: u32) {
    unsafe {
        let ptr = core::ptr::addr_of_mut!(bucket) as *mut u32;
        core::ptr::write(ptr.add(idx as usize), val);
    }
}

#[inline(always)]
fn load_port(idx: usize) -> u16 {
    unsafe {
        let ptr = core::ptr::addr_of!(ports) as *const u16;
        core::ptr::read_volatile(ptr.add(idx))
    }
}

// ------------------------------------------------------------- programs --

#[link_section = "iter/tcp"]
#[no_mangle]
extern "C" fn iter_tcp_soreuse(ctx: *const bpf_iter__tcp) -> i32 {
    let ctx = unsafe { &*ctx };
    let sk = ctx.sk_common;
    if sk.is_null() {
        return 0;
    }

    let sock_cookie = bpf_get_socket_cookie(sk);

    let sf_val = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(sf)) };
    let ss_val = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ss)) };

    let sk_ref = unsafe { &*sk };
    let family = unsafe { *sk_ref.skc_family().as_ptr() };
    if family as u32 != sf_val {
        return 0;
    }
    let state = unsafe { *sk_ref.skc_state().as_ptr() };
    if ss_val != 0 && state as u32 != ss_val {
        return 0;
    }
    let is_loopback = if family == AF_INET6 {
        ipv6_addr_loopback(sk)
    } else {
        ipv4_addr_loopback(sk)
    };
    if !is_loopback {
        return 0;
    }

    let sk_num = unsafe { *sk_ref.skc_num().as_ptr() };
    let idx: i32;
    if sk_num == load_port(0) {
        idx = 0;
    } else if sk_num == load_port(1) {
        idx = 1;
    } else if load_port(0) == 0 && load_port(1) == 0 {
        idx = 0;
    } else {
        return 0;
    }

    // bucket selection as in inet_lhash2_bucket_sk().
    let net_ptr = unsafe { *sk_ref.skc_net().net().as_ptr() };
    let net_ref = unsafe { &*net_ptr };
    let hash_mix = unsafe { *net_ref.hash_mix().as_ptr() };

    let mut addr32: [u32; 4] = [0; 4];
    read_v6_addr(sk, &mut addr32);
    let mut hash = jhash2(&addr32, 4, hash_mix);
    hash ^= sk_num as u32;

    let hinfo_ptr = unsafe { *net_ref.ipv4().tcp_death_row().hashinfo().as_ptr() };
    let hinfo_ref = unsafe { &*hinfo_ptr };
    let lhash2_mask = unsafe { *hinfo_ref.lhash2_mask().as_ptr() };

    store_bucket(idx, hash & lhash2_mask);

    let seq = ctx.meta;
    let seq = unsafe { (*seq).seq };
    bpf_seq_write(seq, &idx as *const i32 as *const c_void, 4);
    bpf_seq_write(
        seq,
        &sock_cookie as *const u64 as *const c_void,
        8,
    );

    0
}

#[link_section = "iter/tcp"]
#[no_mangle]
extern "C" fn iter_tcp_destroy(ctx: *const bpf_iter__tcp) -> i32 {
    let ctx = unsafe { &*ctx };
    let sk_common = ctx.sk_common;
    if sk_common.is_null() {
        return 0;
    }

    let sock_cookie = bpf_get_socket_cookie(sk_common);
    let destroy_cookie_val = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(destroy_cookie)) };
    if sock_cookie != destroy_cookie_val {
        return 0;
    }

    unsafe { bpf_sock_destroy(sk_common) };

    let seq = unsafe { (*ctx.meta).seq };
    bpf_seq_write(seq, &sock_cookie as *const u64 as *const c_void, 8);

    0
}

#[link_section = "iter/udp"]
#[no_mangle]
extern "C" fn iter_udp_soreuse(ctx: *const bpf_iter__udp) -> i32 {
    let ctx = unsafe { &*ctx };
    let sk = ctx.udp_sk as *mut sock_common;
    if sk.is_null() {
        return 0;
    }

    let sock_cookie = bpf_get_socket_cookie(sk);

    let sf_val = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(sf)) };

    let sk_ref = unsafe { &*sk };
    let family = unsafe { *sk_ref.skc_family().as_ptr() };
    if family as u32 != sf_val {
        return 0;
    }
    let is_loopback = if family == AF_INET6 {
        ipv6_addr_loopback(sk)
    } else {
        ipv4_addr_loopback(sk)
    };
    if !is_loopback {
        return 0;
    }

    let sk_num = unsafe { *sk_ref.skc_num().as_ptr() };
    let idx: i32;
    if sk_num == load_port(0) {
        idx = 0;
    } else if sk_num == load_port(1) {
        idx = 1;
    } else if load_port(0) == 0 && load_port(1) == 0 {
        idx = 0;
    } else {
        return 0;
    }

    // bucket selection as in udp_hashslot2().
    let net_ptr = unsafe { *sk_ref.skc_net().net().as_ptr() };
    let net_ref = unsafe { &*net_ptr };
    let udptable_ptr = unsafe { *net_ref.ipv4().udp_table().as_ptr() };
    let udptable_ref = unsafe { &*udptable_ptr };
    let mask = unsafe { *udptable_ref.mask().as_ptr() };

    let portaddr_hash = unsafe { *sk_ref.skc_u16hashes().as_ptr().cast::<u16>().add(1) };
    store_bucket(idx, portaddr_hash as u32 & mask);

    let seq = unsafe { (*ctx.meta).seq };
    bpf_seq_write(seq, &idx as *const i32 as *const c_void, 4);
    bpf_seq_write(
        seq,
        &sock_cookie as *const u64 as *const c_void,
        8,
    );

    0
}

bpf_object!("GPL");
