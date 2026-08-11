#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_sk_lookup.c
// (bpf-rs-core idiom).
//
// `struct bpf_sk_lookup`/`struct sk_reuseport_md` ctx field reads and
// `struct bpf_sock` reads through `ctx->sk` go through the kernel's
// ctx-style narrow-access rewrite (see sk_lookup_convert_ctx_access /
// bpf_sock_is_valid_access in net/core/filter.c), exactly like a real ctx
// field, so narrow reads use raw volatile byte/word loads at the field's
// address (mirroring the C source's LSB/LSW macros) to keep each access a
// separate, correctly-sized BPF_LDX the verifier can rewrite.

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_map_update_elem, bpf_sk_assign, bpf_sk_release,
    bpf_sk_select_reuseport, bpf_trace_printk,
};

// C's bpf_printk sites on sk_assign error paths (kept faithfully).
static ASSIGN_FMT2: [u8; 36] = *b"sk_assign returned %d, expected %d\n\0";
static ASSIGN_FMT1: [u8; 35] = *b"sk_assign returned %d, expected 0\n\0";

#[inline(always)]
fn log_assign2(err: i32, expected: i32) {
    bpf_trace_printk(
        ASSIGN_FMT2.as_ptr() as *const c_void,
        ASSIGN_FMT2.len() as u32,
        err as i64 as u64,
        expected as i64 as u64,
        0,
    );
}

#[inline(always)]
fn log_assign1(err: i32) {
    bpf_trace_printk(
        ASSIGN_FMT1.as_ptr() as *const c_void,
        ASSIGN_FMT1.len() as u32,
        err as i64 as u64,
        0,
        0,
    );
}
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::vload;

const SK_DROP: i32 = 0;
const SK_PASS: i32 = 1;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const IPPROTO_TCP: u32 = 6;
const SOCK_STREAM: u32 = 1;
const BPF_TCP_LISTEN: u32 = 10;

const EEXIST: i32 = 17;
const ESOCKTNOSUPPORT: i32 = 94;

const BPF_SK_LOOKUP_F_REPLACE: u64 = 1 << 0;
const BPF_SK_LOOKUP_F_NO_REUSEPORT: u64 = 1 << 1;

const BPF_ANY: u64 = 0;

const KEY_PROG1: i32 = 0;
const KEY_PROG2: i32 = 1;
const PROG_DONE: i32 = 1;

const KEY_SERVER_A: u32 = 0;
const KEY_SERVER_B: u32 = 1;

const fn htons(x: u16) -> u16 {
    x.to_be()
}
const fn htonl(x: u32) -> u32 {
    x.to_be()
}

const SRC_PORT: u16 = htons(8008);
const SRC_IP4: u32 = htonl((127u32 << 24) | (0u32 << 16) | (0u32 << 8) | 2u32);
const SRC_IP6: [u32; 4] = [htonl(0xfd000000), htonl(0), htonl(0), htonl(2)];

const DST_PORT: u32 = 7007; // Host byte order
const DST_IP4: u32 = htonl((127u32 << 24) | (0u32 << 16) | (0u32 << 8) | 1u32);
const DST_IP6: [u32; 4] = [htonl(0xfd000000), htonl(0), htonl(0), htonl(1)];

const MAX_SOCKS: usize = 32;
const SOCKMAP: usize = 15; // BPF_MAP_TYPE_SOCKMAP

// UAPI struct bpf_sk_lookup (linux/bpf.h). `sk`/`cookie` is a union
// (__bpf_md_ptr), represented as a plain u64 -- only `sk` is ever read here.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_sk_lookup {
    sk: u64,
    family: u32,
    protocol: u32,
    remote_ip4: u32,
    remote_ip6: [u32; 4],
    remote_port: u16,
    _pad: u16,
    local_ip4: u32,
    local_ip6: [u32; 4],
    local_port: u32,
    ingress_ifindex: u32,
}

// UAPI struct sk_reuseport_md (linux/bpf.h). data/data_end/sk/migrating_sk
// are __bpf_md_ptr unions (pointer overlaid with u64), represented as u64.
// None of these programs touch any field but the ctx pointer itself.
#[allow(non_camel_case_types)]
#[repr(C)]
struct sk_reuseport_md {
    #[allow(dead_code)]
    data: u64,
    #[allow(dead_code)]
    data_end: u64,
    #[allow(dead_code)]
    len: u32,
    #[allow(dead_code)]
    eth_protocol: u32,
    #[allow(dead_code)]
    ip_protocol: u32,
    #[allow(dead_code)]
    bind_inany: u32,
    #[allow(dead_code)]
    hash: u32,
    #[allow(dead_code)]
    sk: u64,
    #[allow(dead_code)]
    migrating_sk: u64,
}

// UAPI struct bpf_sock (linux/bpf.h), through family/type/state.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_sock {
    #[allow(dead_code)]
    bound_dev_if: u32,
    family: u32,
    r#type: u32,
    #[allow(dead_code)]
    protocol: u32,
    #[allow(dead_code)]
    mark: u32,
    #[allow(dead_code)]
    priority: u32,
    #[allow(dead_code)]
    src_ip4: u32,
    #[allow(dead_code)]
    src_ip6: [u32; 4],
    #[allow(dead_code)]
    src_port: u32,
    #[allow(dead_code)]
    dst_port: u16,
    #[allow(dead_code)]
    _pad: u16,
    #[allow(dead_code)]
    dst_ip4: u32,
    #[allow(dead_code)]
    dst_ip6: [u32; 4],
    state: u32,
    #[allow(dead_code)]
    rx_queue_mapping: i32,
}

#[link_section = ".maps"]
#[no_mangle]
static redir_map: BpfMap<u32, u64, { SOCKMAP }, MAX_SOCKS> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static run_map: BpfMap<i32, i32, { maps::ARRAY }, 2> = BpfMap::new();

// Volatile least-significant-byte/word reads, mirroring the C source's
// LSB()/LSW() macros (little-endian target, so LSE_INDEX is the identity).
macro_rules! LSB {
    ($place:expr, $idx:expr) => {
        unsafe { core::ptr::read_volatile((core::ptr::addr_of!($place) as *const u8).add($idx)) }
    };
}
macro_rules! LSW {
    ($place:expr, $idx:expr) => {
        unsafe {
            core::ptr::read_volatile((core::ptr::addr_of!($place) as *const u16).add($idx))
        }
    };
}

#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn lookup_pass(_ctx: *const bpf_sk_lookup) -> i32 {
    SK_PASS
}

#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn lookup_drop(_ctx: *const bpf_sk_lookup) -> i32 {
    SK_DROP
}

#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn check_ifindex(ctx: *const bpf_sk_lookup) -> i32 {
    if vload!((*ctx).ingress_ifindex) == 1 {
        SK_DROP
    } else {
        SK_PASS
    }
}

#[link_section = "sk_reuseport"]
#[no_mangle]
extern "C" fn reuseport_pass(_ctx: *const sk_reuseport_md) -> i32 {
    SK_PASS
}

#[link_section = "sk_reuseport"]
#[no_mangle]
extern "C" fn reuseport_drop(_ctx: *const sk_reuseport_md) -> i32 {
    SK_DROP
}

/// Redirect packets destined for port DST_PORT to socket at redir_map[0].
#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn redir_port(ctx: *const bpf_sk_lookup) -> i32 {
    if vload!((*ctx).local_port) != DST_PORT {
        return SK_PASS;
    }

    let sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if sk.is_null() {
        return SK_PASS;
    }

    let err = bpf_sk_assign(ctx as *const c_void, sk, 0);
    bpf_sk_release(sk);
    if err != 0 {
        SK_DROP
    } else {
        SK_PASS
    }
}

/// Redirect packets destined for DST_IP4 address to socket at redir_map[0].
#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn redir_ip4(ctx: *const bpf_sk_lookup) -> i32 {
    if vload!((*ctx).family) != AF_INET {
        return SK_PASS;
    }
    if vload!((*ctx).local_port) != DST_PORT {
        return SK_PASS;
    }
    if vload!((*ctx).local_ip4) != DST_IP4 {
        return SK_PASS;
    }

    let sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if sk.is_null() {
        return SK_PASS;
    }

    let err = bpf_sk_assign(ctx as *const c_void, sk, 0);
    bpf_sk_release(sk);
    if err != 0 {
        SK_DROP
    } else {
        SK_PASS
    }
}

/// Redirect packets destined for DST_IP6 address to socket at redir_map[0].
#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn redir_ip6(ctx: *const bpf_sk_lookup) -> i32 {
    if vload!((*ctx).family) != AF_INET6 {
        return SK_PASS;
    }
    if vload!((*ctx).local_port) != DST_PORT {
        return SK_PASS;
    }
    if vload!((*ctx).local_ip6[0]) != DST_IP6[0]
        || vload!((*ctx).local_ip6[1]) != DST_IP6[1]
        || vload!((*ctx).local_ip6[2]) != DST_IP6[2]
        || vload!((*ctx).local_ip6[3]) != DST_IP6[3]
    {
        return SK_PASS;
    }

    let sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if sk.is_null() {
        return SK_PASS;
    }

    let err = bpf_sk_assign(ctx as *const c_void, sk, 0);
    bpf_sk_release(sk);
    if err != 0 {
        SK_DROP
    } else {
        SK_PASS
    }
}

#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn select_sock_a(ctx: *const bpf_sk_lookup) -> i32 {
    let sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if sk.is_null() {
        return SK_PASS;
    }

    let err = bpf_sk_assign(ctx as *const c_void, sk, 0);
    bpf_sk_release(sk);
    if err != 0 {
        SK_DROP
    } else {
        SK_PASS
    }
}

#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn select_sock_a_no_reuseport(ctx: *const bpf_sk_lookup) -> i32 {
    let sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if sk.is_null() {
        return SK_DROP;
    }

    let err = bpf_sk_assign(ctx as *const c_void, sk, BPF_SK_LOOKUP_F_NO_REUSEPORT);
    bpf_sk_release(sk);
    if err != 0 {
        SK_DROP
    } else {
        SK_PASS
    }
}

#[link_section = "sk_reuseport"]
#[no_mangle]
extern "C" fn select_sock_b(ctx: *const sk_reuseport_md) -> i32 {
    let key: u32 = KEY_SERVER_B;
    let err = bpf_sk_select_reuseport(ctx, &redir_map, &key, 0);
    if err != 0 {
        SK_DROP
    } else {
        SK_PASS
    }
}

/// Check that bpf_sk_assign() returns -EEXIST if socket already selected.
#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn sk_assign_eexist(ctx: *const bpf_sk_lookup) -> i32 {
    let sk_b = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_B);
    if sk_b.is_null() {
        return SK_DROP;
    }
    let err = bpf_sk_assign(ctx as *const c_void, sk_b, 0) as i32;
    if err != 0 {
        bpf_sk_release(sk_b);
        return SK_DROP;
    }
    bpf_sk_release(sk_b);

    let sk_a = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if sk_a.is_null() {
        return SK_DROP;
    }
    let err = bpf_sk_assign(ctx as *const c_void, sk_a, 0) as i32;
    if err != -EEXIST {
        log_assign2(err, -EEXIST);
        bpf_sk_release(sk_a);
        return SK_DROP;
    }

    bpf_sk_release(sk_a); // Success, redirect to KEY_SERVER_B
    SK_PASS
}

/// Check that bpf_sk_assign(BPF_SK_LOOKUP_F_REPLACE) can override selection.
#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn sk_assign_replace_flag(ctx: *const bpf_sk_lookup) -> i32 {
    let sk_a = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if sk_a.is_null() {
        return SK_DROP;
    }
    let err = bpf_sk_assign(ctx as *const c_void, sk_a, 0);
    if err != 0 {
        bpf_sk_release(sk_a);
        return SK_DROP;
    }
    bpf_sk_release(sk_a);

    let sk_b = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_B);
    if sk_b.is_null() {
        return SK_DROP;
    }
    let err = bpf_sk_assign(ctx as *const c_void, sk_b, BPF_SK_LOOKUP_F_REPLACE);
    if err != 0 {
        log_assign1(err as i32);
        bpf_sk_release(sk_b);
        return SK_DROP;
    }

    bpf_sk_release(sk_b); // Success, redirect to KEY_SERVER_B
    SK_PASS
}

/// Check that bpf_sk_assign(sk=NULL) is accepted.
#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn sk_assign_null(ctx: *const bpf_sk_lookup) -> i32 {
    let err = bpf_sk_assign(ctx as *const c_void, core::ptr::null_mut::<c_void>(), 0) as i32;
    if err != 0 {
        log_assign1(err);
        return SK_DROP;
    }

    let sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_B);
    if sk.is_null() {
        return SK_DROP;
    }
    let err = bpf_sk_assign(ctx as *const c_void, sk, BPF_SK_LOOKUP_F_REPLACE) as i32;
    if err != 0 {
        log_assign1(err);
        bpf_sk_release(sk);
        return SK_DROP;
    }

    if vload!((*ctx).sk) != sk as u64 {
        bpf_sk_release(sk);
        return SK_DROP;
    }
    let err = bpf_sk_assign(ctx as *const c_void, core::ptr::null_mut::<c_void>(), 0) as i32;
    if err != -EEXIST {
        bpf_sk_release(sk);
        return SK_DROP;
    }
    let err = bpf_sk_assign(ctx as *const c_void, core::ptr::null_mut::<c_void>(), BPF_SK_LOOKUP_F_REPLACE) as i32;
    if err != 0 {
        bpf_sk_release(sk);
        return SK_DROP;
    }
    let err = bpf_sk_assign(ctx as *const c_void, sk, BPF_SK_LOOKUP_F_REPLACE) as i32;
    if err != 0 {
        bpf_sk_release(sk);
        return SK_DROP;
    }

    bpf_sk_release(sk); // Success, redirect to KEY_SERVER_B
    SK_PASS
}

/// Check that selected sk is accessible through context.
#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn access_ctx_sk(ctx: *const bpf_sk_lookup) -> i32 {
    // Try accessing unassigned (NULL) ctx->sk field
    let sk0 = vload!((*ctx).sk) as *const bpf_sock;
    if !sk0.is_null() && vload!((*sk0).family) != AF_INET {
        return SK_DROP;
    }

    // Assign a value to ctx->sk
    let sk1 = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if sk1.is_null() {
        return SK_DROP;
    }
    let err = bpf_sk_assign(ctx as *const c_void, sk1, 0);
    if err != 0 {
        bpf_sk_release(sk1);
        return SK_DROP;
    }
    // Single ctx->sk load, reused below: the verifier only carries the
    // non-null narrowing from this equality check into dereferences of
    // this exact loaded value, not into a freshly re-issued ctx load.
    let sk = vload!((*ctx).sk) as *const bpf_sock;
    if sk as u64 != sk1 as u64 {
        bpf_sk_release(sk1);
        return SK_DROP;
    }

    // Access ctx->sk fields
    if vload!((*sk).family) != AF_INET
        || vload!((*sk).r#type) != SOCK_STREAM
        || vload!((*sk).state) != BPF_TCP_LISTEN
    {
        bpf_sk_release(sk1);
        return SK_DROP;
    }

    // Reset selection
    let err = bpf_sk_assign(ctx as *const c_void, core::ptr::null_mut::<c_void>(), BPF_SK_LOOKUP_F_REPLACE);
    if err != 0 {
        bpf_sk_release(sk1);
        return SK_DROP;
    }
    if vload!((*ctx).sk) != 0 {
        bpf_sk_release(sk1);
        return SK_DROP;
    }

    // Assign another socket
    let sk2 = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_B);
    if sk2.is_null() {
        bpf_sk_release(sk1);
        return SK_DROP;
    }
    let err = bpf_sk_assign(ctx as *const c_void, sk2, BPF_SK_LOOKUP_F_REPLACE);
    if err != 0 {
        bpf_sk_release(sk1);
        bpf_sk_release(sk2);
        return SK_DROP;
    }
    // Single ctx->sk load, reused below (see comment above).
    let sk = vload!((*ctx).sk) as *const bpf_sock;
    if sk as u64 != sk2 as u64 {
        bpf_sk_release(sk1);
        bpf_sk_release(sk2);
        return SK_DROP;
    }

    // Access reassigned ctx->sk fields
    if vload!((*sk).family) != AF_INET
        || vload!((*sk).r#type) != SOCK_STREAM
        || vload!((*sk).state) != BPF_TCP_LISTEN
    {
        bpf_sk_release(sk1);
        bpf_sk_release(sk2);
        return SK_DROP;
    }

    bpf_sk_release(sk1); // Success, redirect to KEY_SERVER_B
    bpf_sk_release(sk2);
    SK_PASS
}

/// Check narrow loads from ctx fields that support them.
///
/// Narrow loads of size >= target field size from a non-zero offset
/// are not covered because they give bogus results, that is the
/// verifier ignores the offset.
#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn ctx_narrow_access(ctx: *const bpf_sk_lookup) -> i32 {
    let v4 = vload!((*ctx).family) == AF_INET;
    let expect_family: u32 = if v4 { AF_INET } else { AF_INET6 };

    // Narrow loads from family field
    if LSB!((*ctx).family, 0) != expect_family as u8
        || LSB!((*ctx).family, 1) != 0
        || LSB!((*ctx).family, 2) != 0
        || LSB!((*ctx).family, 3) != 0
    {
        return SK_DROP;
    }
    if LSW!((*ctx).family, 0) != expect_family as u16 {
        return SK_DROP;
    }

    // Narrow loads from protocol field
    if LSB!((*ctx).protocol, 0) != IPPROTO_TCP as u8
        || LSB!((*ctx).protocol, 1) != 0
        || LSB!((*ctx).protocol, 2) != 0
        || LSB!((*ctx).protocol, 3) != 0
    {
        return SK_DROP;
    }
    if LSW!((*ctx).protocol, 0) != IPPROTO_TCP as u16 {
        return SK_DROP;
    }

    // Narrow loads from remote_port field. Expect SRC_PORT.
    if LSB!((*ctx).remote_port, 0) != ((SRC_PORT >> 0) & 0xff) as u8
        || LSB!((*ctx).remote_port, 1) != ((SRC_PORT >> 8) & 0xff) as u8
    {
        return SK_DROP;
    }
    if LSW!((*ctx).remote_port, 0) != SRC_PORT {
        return SK_DROP;
    }

    // NOTE: 4-byte load from bpf_sk_lookup at remote_port offset is
    // quirky. It gets rewritten by the access converter to a 2-byte load
    // for backward compatibility. Treating the load result as a be16
    // value makes the code portable across little- and big-endian
    // platforms.
    let val_u32 =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*ctx).remote_port) as *const u32) };
    if val_u32 != SRC_PORT as u32 {
        return SK_DROP;
    }

    // Narrow loads from local_port field. Expect DST_PORT.
    if LSB!((*ctx).local_port, 0) != ((DST_PORT >> 0) & 0xff) as u8
        || LSB!((*ctx).local_port, 1) != ((DST_PORT >> 8) & 0xff) as u8
        || LSB!((*ctx).local_port, 2) != 0
        || LSB!((*ctx).local_port, 3) != 0
    {
        return SK_DROP;
    }
    if LSW!((*ctx).local_port, 0) != DST_PORT as u16 {
        return SK_DROP;
    }

    // Narrow loads from IPv4 fields
    if v4 {
        // Expect SRC_IP4 in remote_ip4
        if LSB!((*ctx).remote_ip4, 0) != ((SRC_IP4 >> 0) & 0xff) as u8
            || LSB!((*ctx).remote_ip4, 1) != ((SRC_IP4 >> 8) & 0xff) as u8
            || LSB!((*ctx).remote_ip4, 2) != ((SRC_IP4 >> 16) & 0xff) as u8
            || LSB!((*ctx).remote_ip4, 3) != ((SRC_IP4 >> 24) & 0xff) as u8
        {
            return SK_DROP;
        }
        if LSW!((*ctx).remote_ip4, 0) != ((SRC_IP4 >> 0) & 0xffff) as u16
            || LSW!((*ctx).remote_ip4, 1) != ((SRC_IP4 >> 16) & 0xffff) as u16
        {
            return SK_DROP;
        }

        // Expect DST_IP4 in local_ip4
        if LSB!((*ctx).local_ip4, 0) != ((DST_IP4 >> 0) & 0xff) as u8
            || LSB!((*ctx).local_ip4, 1) != ((DST_IP4 >> 8) & 0xff) as u8
            || LSB!((*ctx).local_ip4, 2) != ((DST_IP4 >> 16) & 0xff) as u8
            || LSB!((*ctx).local_ip4, 3) != ((DST_IP4 >> 24) & 0xff) as u8
        {
            return SK_DROP;
        }
        if LSW!((*ctx).local_ip4, 0) != ((DST_IP4 >> 0) & 0xffff) as u16
            || LSW!((*ctx).local_ip4, 1) != ((DST_IP4 >> 16) & 0xffff) as u16
        {
            return SK_DROP;
        }
    } else {
        // Expect 0.0.0.0 IPs when family != AF_INET
        if LSB!((*ctx).remote_ip4, 0) != 0
            || LSB!((*ctx).remote_ip4, 1) != 0
            || LSB!((*ctx).remote_ip4, 2) != 0
            || LSB!((*ctx).remote_ip4, 3) != 0
        {
            return SK_DROP;
        }
        if LSW!((*ctx).remote_ip4, 0) != 0 || LSW!((*ctx).remote_ip4, 1) != 0 {
            return SK_DROP;
        }

        if LSB!((*ctx).local_ip4, 0) != 0
            || LSB!((*ctx).local_ip4, 1) != 0
            || LSB!((*ctx).local_ip4, 2) != 0
            || LSB!((*ctx).local_ip4, 3) != 0
        {
            return SK_DROP;
        }
        if LSW!((*ctx).local_ip4, 0) != 0 || LSW!((*ctx).local_ip4, 1) != 0 {
            return SK_DROP;
        }
    }

    // Narrow loads from IPv6 fields
    if !v4 {
        // Expect SRC_IP6 in remote_ip6
        if LSB!((*ctx).remote_ip6[0], 0) != ((SRC_IP6[0] >> 0) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[0], 1) != ((SRC_IP6[0] >> 8) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[0], 2) != ((SRC_IP6[0] >> 16) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[0], 3) != ((SRC_IP6[0] >> 24) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[1], 0) != ((SRC_IP6[1] >> 0) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[1], 1) != ((SRC_IP6[1] >> 8) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[1], 2) != ((SRC_IP6[1] >> 16) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[1], 3) != ((SRC_IP6[1] >> 24) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[2], 0) != ((SRC_IP6[2] >> 0) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[2], 1) != ((SRC_IP6[2] >> 8) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[2], 2) != ((SRC_IP6[2] >> 16) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[2], 3) != ((SRC_IP6[2] >> 24) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[3], 0) != ((SRC_IP6[3] >> 0) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[3], 1) != ((SRC_IP6[3] >> 8) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[3], 2) != ((SRC_IP6[3] >> 16) & 0xff) as u8
            || LSB!((*ctx).remote_ip6[3], 3) != ((SRC_IP6[3] >> 24) & 0xff) as u8
        {
            return SK_DROP;
        }
        if LSW!((*ctx).remote_ip6[0], 0) != ((SRC_IP6[0] >> 0) & 0xffff) as u16
            || LSW!((*ctx).remote_ip6[0], 1) != ((SRC_IP6[0] >> 16) & 0xffff) as u16
            || LSW!((*ctx).remote_ip6[1], 0) != ((SRC_IP6[1] >> 0) & 0xffff) as u16
            || LSW!((*ctx).remote_ip6[1], 1) != ((SRC_IP6[1] >> 16) & 0xffff) as u16
            || LSW!((*ctx).remote_ip6[2], 0) != ((SRC_IP6[2] >> 0) & 0xffff) as u16
            || LSW!((*ctx).remote_ip6[2], 1) != ((SRC_IP6[2] >> 16) & 0xffff) as u16
            || LSW!((*ctx).remote_ip6[3], 0) != ((SRC_IP6[3] >> 0) & 0xffff) as u16
            || LSW!((*ctx).remote_ip6[3], 1) != ((SRC_IP6[3] >> 16) & 0xffff) as u16
        {
            return SK_DROP;
        }
        // Expect DST_IP6 in local_ip6
        if LSB!((*ctx).local_ip6[0], 0) != ((DST_IP6[0] >> 0) & 0xff) as u8
            || LSB!((*ctx).local_ip6[0], 1) != ((DST_IP6[0] >> 8) & 0xff) as u8
            || LSB!((*ctx).local_ip6[0], 2) != ((DST_IP6[0] >> 16) & 0xff) as u8
            || LSB!((*ctx).local_ip6[0], 3) != ((DST_IP6[0] >> 24) & 0xff) as u8
            || LSB!((*ctx).local_ip6[1], 0) != ((DST_IP6[1] >> 0) & 0xff) as u8
            || LSB!((*ctx).local_ip6[1], 1) != ((DST_IP6[1] >> 8) & 0xff) as u8
            || LSB!((*ctx).local_ip6[1], 2) != ((DST_IP6[1] >> 16) & 0xff) as u8
            || LSB!((*ctx).local_ip6[1], 3) != ((DST_IP6[1] >> 24) & 0xff) as u8
            || LSB!((*ctx).local_ip6[2], 0) != ((DST_IP6[2] >> 0) & 0xff) as u8
            || LSB!((*ctx).local_ip6[2], 1) != ((DST_IP6[2] >> 8) & 0xff) as u8
            || LSB!((*ctx).local_ip6[2], 2) != ((DST_IP6[2] >> 16) & 0xff) as u8
            || LSB!((*ctx).local_ip6[2], 3) != ((DST_IP6[2] >> 24) & 0xff) as u8
            || LSB!((*ctx).local_ip6[3], 0) != ((DST_IP6[3] >> 0) & 0xff) as u8
            || LSB!((*ctx).local_ip6[3], 1) != ((DST_IP6[3] >> 8) & 0xff) as u8
            || LSB!((*ctx).local_ip6[3], 2) != ((DST_IP6[3] >> 16) & 0xff) as u8
            || LSB!((*ctx).local_ip6[3], 3) != ((DST_IP6[3] >> 24) & 0xff) as u8
        {
            return SK_DROP;
        }
        if LSW!((*ctx).local_ip6[0], 0) != ((DST_IP6[0] >> 0) & 0xffff) as u16
            || LSW!((*ctx).local_ip6[0], 1) != ((DST_IP6[0] >> 16) & 0xffff) as u16
            || LSW!((*ctx).local_ip6[1], 0) != ((DST_IP6[1] >> 0) & 0xffff) as u16
            || LSW!((*ctx).local_ip6[1], 1) != ((DST_IP6[1] >> 16) & 0xffff) as u16
            || LSW!((*ctx).local_ip6[2], 0) != ((DST_IP6[2] >> 0) & 0xffff) as u16
            || LSW!((*ctx).local_ip6[2], 1) != ((DST_IP6[2] >> 16) & 0xffff) as u16
            || LSW!((*ctx).local_ip6[3], 0) != ((DST_IP6[3] >> 0) & 0xffff) as u16
            || LSW!((*ctx).local_ip6[3], 1) != ((DST_IP6[3] >> 16) & 0xffff) as u16
        {
            return SK_DROP;
        }
    } else {
        // Expect :: IPs when family != AF_INET6
        if LSB!((*ctx).remote_ip6[0], 0) != 0
            || LSB!((*ctx).remote_ip6[0], 1) != 0
            || LSB!((*ctx).remote_ip6[0], 2) != 0
            || LSB!((*ctx).remote_ip6[0], 3) != 0
            || LSB!((*ctx).remote_ip6[1], 0) != 0
            || LSB!((*ctx).remote_ip6[1], 1) != 0
            || LSB!((*ctx).remote_ip6[1], 2) != 0
            || LSB!((*ctx).remote_ip6[1], 3) != 0
            || LSB!((*ctx).remote_ip6[2], 0) != 0
            || LSB!((*ctx).remote_ip6[2], 1) != 0
            || LSB!((*ctx).remote_ip6[2], 2) != 0
            || LSB!((*ctx).remote_ip6[2], 3) != 0
            || LSB!((*ctx).remote_ip6[3], 0) != 0
            || LSB!((*ctx).remote_ip6[3], 1) != 0
            || LSB!((*ctx).remote_ip6[3], 2) != 0
            || LSB!((*ctx).remote_ip6[3], 3) != 0
        {
            return SK_DROP;
        }
        if LSW!((*ctx).remote_ip6[0], 0) != 0
            || LSW!((*ctx).remote_ip6[0], 1) != 0
            || LSW!((*ctx).remote_ip6[1], 0) != 0
            || LSW!((*ctx).remote_ip6[1], 1) != 0
            || LSW!((*ctx).remote_ip6[2], 0) != 0
            || LSW!((*ctx).remote_ip6[2], 1) != 0
            || LSW!((*ctx).remote_ip6[3], 0) != 0
            || LSW!((*ctx).remote_ip6[3], 1) != 0
        {
            return SK_DROP;
        }

        if LSB!((*ctx).local_ip6[0], 0) != 0
            || LSB!((*ctx).local_ip6[0], 1) != 0
            || LSB!((*ctx).local_ip6[0], 2) != 0
            || LSB!((*ctx).local_ip6[0], 3) != 0
            || LSB!((*ctx).local_ip6[1], 0) != 0
            || LSB!((*ctx).local_ip6[1], 1) != 0
            || LSB!((*ctx).local_ip6[1], 2) != 0
            || LSB!((*ctx).local_ip6[1], 3) != 0
            || LSB!((*ctx).local_ip6[2], 0) != 0
            || LSB!((*ctx).local_ip6[2], 1) != 0
            || LSB!((*ctx).local_ip6[2], 2) != 0
            || LSB!((*ctx).local_ip6[2], 3) != 0
            || LSB!((*ctx).local_ip6[3], 0) != 0
            || LSB!((*ctx).local_ip6[3], 1) != 0
            || LSB!((*ctx).local_ip6[3], 2) != 0
            || LSB!((*ctx).local_ip6[3], 3) != 0
        {
            return SK_DROP;
        }
        // NOTE: the C source checks remote_ip6 (not local_ip6) here too --
        // reproduced verbatim to stay bit-for-bit identical to the oracle.
        if LSW!((*ctx).remote_ip6[0], 0) != 0
            || LSW!((*ctx).remote_ip6[0], 1) != 0
            || LSW!((*ctx).remote_ip6[1], 0) != 0
            || LSW!((*ctx).remote_ip6[1], 1) != 0
            || LSW!((*ctx).remote_ip6[2], 0) != 0
            || LSW!((*ctx).remote_ip6[2], 1) != 0
            || LSW!((*ctx).remote_ip6[3], 0) != 0
            || LSW!((*ctx).remote_ip6[3], 1) != 0
        {
            return SK_DROP;
        }
    }

    // Success, redirect to KEY_SERVER_B
    let sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_B);
    if !sk.is_null() {
        bpf_sk_assign(ctx as *const c_void, sk, 0);
        bpf_sk_release(sk);
    }
    SK_PASS
}

/// Check that sk_assign rejects SERVER_A socket with -ESOCKNOSUPPORT
#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn sk_assign_esocknosupport(ctx: *const bpf_sk_lookup) -> i32 {
    let sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if sk.is_null() {
        return SK_DROP;
    }

    let err = bpf_sk_assign(ctx as *const c_void, sk, 0) as i32;
    if err != -ESOCKTNOSUPPORT {
        log_assign2(err, -ESOCKTNOSUPPORT);
        bpf_sk_release(sk);
        return SK_DROP;
    }

    bpf_sk_release(sk); // Success, pass to regular lookup
    SK_PASS
}

#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn multi_prog_pass1(_ctx: *const bpf_sk_lookup) -> i32 {
    bpf_map_update_elem(&run_map, &KEY_PROG1, &PROG_DONE, BPF_ANY);
    SK_PASS
}

#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn multi_prog_pass2(_ctx: *const bpf_sk_lookup) -> i32 {
    bpf_map_update_elem(&run_map, &KEY_PROG2, &PROG_DONE, BPF_ANY);
    SK_PASS
}

#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn multi_prog_drop1(_ctx: *const bpf_sk_lookup) -> i32 {
    bpf_map_update_elem(&run_map, &KEY_PROG1, &PROG_DONE, BPF_ANY);
    SK_DROP
}

#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn multi_prog_drop2(_ctx: *const bpf_sk_lookup) -> i32 {
    bpf_map_update_elem(&run_map, &KEY_PROG2, &PROG_DONE, BPF_ANY);
    SK_DROP
}

#[inline(always)]
fn select_server_a(ctx: *const bpf_sk_lookup) -> i32 {
    let sk = bpf_map_lookup_elem(&redir_map, &KEY_SERVER_A);
    if sk.is_null() {
        return SK_DROP;
    }

    let err = bpf_sk_assign(ctx as *const c_void, sk, 0);
    bpf_sk_release(sk);
    if err != 0 {
        SK_DROP
    } else {
        SK_PASS
    }
}

#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn multi_prog_redir1(ctx: *const bpf_sk_lookup) -> i32 {
    let _ = select_server_a(ctx);
    bpf_map_update_elem(&run_map, &KEY_PROG1, &PROG_DONE, BPF_ANY);
    SK_PASS
}

#[link_section = "sk_lookup"]
#[no_mangle]
extern "C" fn multi_prog_redir2(ctx: *const bpf_sk_lookup) -> i32 {
    let _ = select_server_a(ctx);
    bpf_map_update_elem(&run_map, &KEY_PROG2, &PROG_DONE, BPF_ANY);
    SK_PASS
}

bpf_object!("Dual BSD/GPL");
