#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/mptcpify.c
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;
use bpf_rs_core::progs::fentry_arg;

const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const SOCK_STREAM: i32 = 1;
const SOCK_TYPE_MASK: i32 = 0xf;
const IPPROTO_TCP: i32 = 6;
const IPPROTO_MPTCP: i32 = 262;

#[no_mangle]
static mut pid: i32 = 0;

#[link_section = "fmod_ret/update_socket_protocol"]
#[no_mangle]
extern "C" fn mptcpify(ctx: *const u64) -> i32 {
    let family = fentry_arg(ctx, 0) as i32;
    let r#type = fentry_arg(ctx, 1) as i32;
    let protocol = fentry_arg(ctx, 2) as i32;

    if (bpf_get_current_pid_tgid() >> 32) as i32 != unsafe { pid } {
        return protocol;
    }

    if (family == AF_INET || family == AF_INET6)
        && (r#type & SOCK_TYPE_MASK) == SOCK_STREAM
        && (protocol == 0 || protocol == IPPROTO_TCP)
    {
        return IPPROTO_MPTCP;
    }

    protocol
}

bpf_object!("GPL");
