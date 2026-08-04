#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tcp_ca_update.c,
// bpf-rs-core idiom.
//
// tcp_sk(sk) in the C source is a plain pointer reinterpretation: `struct
// sock` sits at offset 0 of `struct tcp_sock` (via inet_connection_sock /
// inet_sock), so the cast collapses to `sk as *const tcp_sock` (same
// container_of-collapse idiom as bpf_iter_netlink.rs's SOCK_INODE()); only
// the `snd_cwnd`/`snd_ssthresh` field offsets need a real CO-RE relocation.
// The kernel's bpf_tcp_ca_btf_struct_access() explicitly whitelists exactly
// this "struct sock reg reinterpreted as struct tcp_sock" access pattern
// for tcp_congestion_ops programs, independent of the local type name used
// on this side of the CO-RE relocation.
//
// ca_update_cong_control's body is empty in the C source, and BPF_PROG's
// positional ctx[i] mapping means the declared `rs` parameter would
// actually alias ctx[1] (the real 2nd arg of cong_control's 4-arg kernel
// prototype is `u32 ack`, not `rs`) -- moot since the C body never reads
// it, so this translation is a plain no-op on ctx.
//
// ca_wrong/ca_no_link intentionally leave `.init` unset in the C source.
// libbpf's struct_ops loader resolves the KERNEL type by the LOCAL type's
// *name* (looks up "bpf_struct_ops_<local type name>"), so every
// ".struct_ops"/".struct_ops.link" instance mapping to tcp_congestion_ops
// must share one Rust struct literally named `tcp_congestion_ops` --
// unlike plain map-value partial mirrors (bpf_tcp_nogpl.rs), per-instance
// differently-named types are not an option here, which rules out
// omitting `init` for just two of the four instances. Rust's fn type also
// forbids a const-evaluated null function pointer. Neither matters
// behaviorally: net/ipv4/tcp_cong.c's tcp_validate_congestion_control()
// (called from register, at attach time) never checks `.init`, and
// tcp_update_congestion_control() (the link-update path) rejects
// ca_wrong purely because its `.name` ("tcp_ca_wrong") doesn't match the
// currently-registered name ("tcp_ca_update") -- `.init` plays no part in
// either check, and neither ca_wrong nor ca_no_link is ever selected as
// the active congestion-control algorithm for a real connection in the
// prog_tests, so their `.init` callback is never invoked either way.
// ca_wrong/ca_no_link therefore point `.init` at `ca_update_1_init`
// instead of leaving it unset. Two constraints rule out the obvious
// alternatives: a dedicated extra no-op function doesn't work because the
// C object's keep-list only names the five real callbacks, so any
// additional symbol gets internalized to LOCAL bind by the opt pass, and
// LLVM then emits an STT_SECTION-relative relocation for it -- which
// bpf_linker's static-link pass (invoked by `bpftool gen skeleton`)
// rejects ("relocation against STT_SECTION in non-exec section"). And
// reusing `ca_update_cong_control` (already GLOBAL, matching signature)
// doesn't work either: the kernel tags each loaded program with the
// struct_ops member index of its *first* use, and rejects reuse of the
// same program at a different member index ("invalid reuse of prog ...
// expected_attach_type != kern_member_idx") -- `ca_update_1_init` is
// already tagged for the `init` slot (via ca_update_1 below), so reusing
// it for `init` elsewhere stays consistent.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

#[no_mangle]
static mut ca1_cnt: i32 = 0;
#[no_mangle]
static mut ca2_cnt: i32 = 0;

#[btf]
struct tcp_sock {
    snd_cwnd: u32,
    snd_ssthresh: u32,
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn ca_update_1_init(_ctx: *const u64) {
    unsafe { ca1_cnt += 1 };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn ca_update_2_init(_ctx: *const u64) {
    unsafe { ca2_cnt += 1 };
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn ca_update_cong_control(_ctx: *const u64) {}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn ca_update_ssthresh(ctx: *const u64) -> u32 {
    let tp = arg(ctx, 0) as *const tcp_sock;
    *unsafe { &*tp }.snd_ssthresh().get().unwrap()
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn ca_update_undo_cwnd(ctx: *const u64) -> u32 {
    let tp = arg(ctx, 0) as *const tcp_sock;
    *unsafe { &*tp }.snd_cwnd().get().unwrap()
}

// struct tcp_congestion_ops (net/tcp.h) partial mirror: only the members
// any instance below sets. Must be named exactly `tcp_congestion_ops` --
// see the block comment above.
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcp_congestion_ops {
    init: extern "C" fn(*const u64),
    cong_control: extern "C" fn(*const u64),
    ssthresh: extern "C" fn(*const u64) -> u32,
    undo_cwnd: extern "C" fn(*const u64) -> u32,
    name: [u8; 16],
}

unsafe impl Sync for tcp_congestion_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static ca_update_1: tcp_congestion_ops = tcp_congestion_ops {
    init: ca_update_1_init,
    cong_control: ca_update_cong_control,
    ssthresh: ca_update_ssthresh,
    undo_cwnd: ca_update_undo_cwnd,
    name: *b"tcp_ca_update\0\0\0",
};

#[link_section = ".struct_ops.link"]
#[no_mangle]
static ca_update_2: tcp_congestion_ops = tcp_congestion_ops {
    init: ca_update_2_init,
    cong_control: ca_update_cong_control,
    ssthresh: ca_update_ssthresh,
    undo_cwnd: ca_update_undo_cwnd,
    name: *b"tcp_ca_update\0\0\0",
};

#[link_section = ".struct_ops.link"]
#[no_mangle]
static ca_wrong: tcp_congestion_ops = tcp_congestion_ops {
    init: ca_update_1_init,
    cong_control: ca_update_cong_control,
    ssthresh: ca_update_ssthresh,
    undo_cwnd: ca_update_undo_cwnd,
    name: *b"tcp_ca_wrong\0\0\0\0",
};

#[link_section = ".struct_ops"]
#[no_mangle]
static ca_no_link: tcp_congestion_ops = tcp_congestion_ops {
    init: ca_update_1_init,
    cong_control: ca_update_cong_control,
    ssthresh: ca_update_ssthresh,
    undo_cwnd: ca_update_undo_cwnd,
    name: *b"tcp_ca_no_link\0\0",
};

bpf_object!("GPL");
