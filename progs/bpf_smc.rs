#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_smc.c,
// bpf-rs-core idiom.
//
// prog_tests/test_bpf_smc.c's test_bpf_smc() calls setup_smc() (netlink UEID
// registration + netns setup) BEFORE ever opening this skeleton; if that
// fails (no SMC subsystem support in the test kernel) it test__skip()s
// without touching the object at all. When it does proceed, test_topo()
// open_and_load + attach()es this object and only inspects the smc_cnt /
// fallback_cnt bss counters plus the smc_policy_ip map -- it never asserts
// on the struct_ops/fmod_ret bodies' internals beyond their externally
// visible effect on those two counters, so a faithful field-for-field
// translation is what the oracle checks.
//
// `struct net___local`/`smc_sock___local`/`smc_hs_ctrl___local` are CO-RE
// flavors of the real kernel `net`/`smc_sock`/`smc_hs_ctrl` types (the
// `___local` suffix is stripped by libbpf before BTF matching); only the
// members this file actually reads are declared, per the crate's field-name
// (not layout) matching convention (see mptcp_sock.rs).
//
// `bpf_core_field_exists(struct net___local, smc)` (a field's existence
// probed independent of any real object) becomes `net_ref.smc().exists()`
// on an actual `net___local` pointer -- functionally identical, since
// `field_exists` never touches memory. The short-circuit `||` in the C
// source is reproduced as two sequential early returns rather than a single
// boolean expression, so the following `byte_offset` relocation for
// `net->smc.hs_ctrl` is only ever compiled into a branch the verifier can
// prove dead when `smc` doesn't exist on the target kernel (same reasoning
// as `Field::as_ptr`'s doc comment: an unresolved relocation only survives
// load if it's unreachable).

use bpf_rs_core::helpers::{bpf_get_current_task_btf, bpf_map_lookup_elem};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object, maps};
use btf_macros::btf;

const BPF_SMC_LISTEN: i32 = 10;
const SMC_HS_CTRL_NAME_MAX: usize = 16;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const SOCK_STREAM: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_SMC: i32 = 256;

const BPF_F_NO_PREALLOC: usize = 1;

// ----------------------------------------------------------- CO-RE mirrors --

#[btf]
struct sock_common {
    skc_state: u8,
    skc_daddr: u32,
    skc_rcv_saddr: u32,
}

#[btf]
struct sock {
    __sk_common: sock_common,
}

#[btf]
struct socket {
    sk: *mut sock,
}

// Opaque terminal: only ever null-checked, never chased further (same
// pattern as bpf_iter_netlink.rs's `socket {}`).
#[btf]
struct smc_sock_kern {}

#[btf]
struct smc_sock___local {
    listen_smc: *mut smc_sock_kern,
}

#[btf]
struct task_struct {
    nsproxy: *mut nsproxy,
}

#[btf]
struct nsproxy {
    net_ns: *mut net___local,
}

// Opaque terminal for netns_smc's `hs_ctrl`: only null-checked here.
#[btf]
struct smc_hs_ctrl_kern {}

#[btf]
struct netns_smc___local {
    hs_ctrl: *mut smc_hs_ctrl_kern,
}

#[btf]
struct net___local {
    smc: netns_smc___local,
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
}

#[btf]
struct request_sock {
    __req_common: sock_common,
}

#[btf]
struct inet_request_sock {
    req: request_sock,
}

// --------------------------------------------------------------- globals --

#[no_mangle]
static mut smc_cnt: i32 = 0;

#[no_mangle]
static mut fallback_cnt: i32 = 0;

#[no_mangle]
static mut default_ip_strat_value: bool = true;

// ------------------------------------------------------------------ maps --

#[allow(non_camel_case_types)]
#[repr(C)]
struct smc_policy_ip_key {
    sip: u32,
    dip: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct smc_policy_ip_value {
    mode: u8,
}

bpf_map! {
    smc_policy_ip {
        r#type: *const [i32; maps::HASH],
        max_entries: *const [i32; 128],
        map_flags: *const [i32; BPF_F_NO_PREALLOC],
        key: *const smc_policy_ip_key,
        value: *const smc_policy_ip_value,
    }
}

fn smc_check(src: u32, dst: u32) -> i32 {
    let key = smc_policy_ip_key { sip: src, dip: dst };
    let value = bpf_map_lookup_elem(&smc_policy_ip, &key) as *const smc_policy_ip_value;
    if !value.is_null() {
        (unsafe { (*value).mode } != 0) as i32
    } else {
        unsafe { default_ip_strat_value as i32 }
    }
}

// -------------------------------------------------------------- programs --

#[link_section = "fentry/smc_release"]
#[no_mangle]
extern "C" fn bpf_smc_release(ctx: *const u64) -> i32 {
    let sock_ptr = arg(ctx, 0) as *const socket;

    let sk = unsafe { *(&*sock_ptr).sk().as_ptr() };
    let skc_state = unsafe { *(&*sk).__sk_common().skc_state().as_ptr() };
    if skc_state as i32 == BPF_SMC_LISTEN {
        return 0;
    }
    unsafe { smc_cnt += 1 };
    0
}

#[link_section = "fentry/smc_switch_to_fallback"]
#[no_mangle]
extern "C" fn bpf_smc_switch_to_fallback(ctx: *const u64) -> i32 {
    let smc = arg(ctx, 0) as *const smc_sock___local;

    if !smc.is_null() {
        let listen_smc = unsafe { *(&*smc).listen_smc().as_ptr() };
        if listen_smc.is_null() {
            unsafe { fallback_cnt += 1 };
        }
    }
    0
}

#[link_section = "fmod_ret/update_socket_protocol"]
#[no_mangle]
extern "C" fn smc_run(ctx: *const u64) -> i32 {
    let family = arg(ctx, 0) as i32;
    let sock_type = arg(ctx, 1) as i32;
    let protocol = arg(ctx, 2) as i32;

    if family != AF_INET && family != AF_INET6 {
        return protocol;
    }
    if (sock_type & 0xf) != SOCK_STREAM {
        return protocol;
    }
    if protocol != 0 && protocol != IPPROTO_TCP {
        return protocol;
    }

    let task = bpf_get_current_task_btf::<task_struct>();
    if task.is_null() {
        return protocol;
    }

    let nsproxy_ptr = unsafe { *(&*task).nsproxy().as_ptr() };
    let net = unsafe { *(&*nsproxy_ptr).net_ns().as_ptr() };
    let net_ref = unsafe { &*net };

    if !net_ref.smc().exists() {
        return protocol;
    }
    let hs_ctrl = unsafe { *net_ref.smc().hs_ctrl().as_ptr() };
    if hs_ctrl.is_null() {
        return protocol;
    }

    IPPROTO_SMC
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_smc_set_tcp_option_cond(ctx: *const u64) -> i32 {
    let ireq = arg(ctx, 1) as *const inet_request_sock;
    let ireq_ref = unsafe { &*ireq };

    let daddr = unsafe { *ireq_ref.req().__req_common().skc_daddr().as_ptr() };
    let rcv_saddr = unsafe { *ireq_ref.req().__req_common().skc_rcv_saddr().as_ptr() };
    smc_check(daddr, rcv_saddr)
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn bpf_smc_set_tcp_option(ctx: *const u64) -> i32 {
    let tp = arg(ctx, 0) as *const tcp_sock;
    let tp_ref = unsafe { &*tp };

    let rcv_saddr = unsafe {
        *tp_ref
            .inet_conn()
            .icsk_inet()
            .sk()
            .__sk_common()
            .skc_rcv_saddr()
            .as_ptr()
    };
    let daddr = unsafe {
        *tp_ref
            .inet_conn()
            .icsk_inet()
            .sk()
            .__sk_common()
            .skc_daddr()
            .as_ptr()
    };
    smc_check(rcv_saddr, daddr)
}

// struct smc_hs_ctrl (net/smc/smc_hs_ctrl.h): only the members this program
// initializes are declared -- libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct smc_hs_ctrl___local {
    name: [u8; SMC_HS_CTRL_NAME_MAX],
    syn_option: extern "C" fn(*const u64) -> i32,
    synack_option: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for smc_hs_ctrl___local {}

#[link_section = ".struct_ops"]
#[no_mangle]
static linkcheck: smc_hs_ctrl___local = smc_hs_ctrl___local {
    name: *b"linkcheck\0\0\0\0\0\0\0",
    syn_option: bpf_smc_set_tcp_option,
    synack_option: bpf_smc_set_tcp_option_cond,
};

bpf_object!("GPL");
