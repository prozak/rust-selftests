#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/cgroup_getset_retval_hooks.c
// (bpf-rs-core idiom).
//
// The C source expands BPF_RETVAL_HOOK(name, section, ctx, expected_err)
// via cgroup_getset_retval_hooks.h into one program per cgroup hook type,
// all with the identical body (round-trip the retval) and all placed in a
// SEC("?...") section (leading '?' == not autoloaded by default; the
// userspace test flips autoload on one at a time and checks the load
// result against the hook's expected_err). None of the programs touch
// ctx, so the pointer type is irrelevant to program behavior.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_retval, bpf_set_retval};
use core::ffi::c_void;

macro_rules! retval_hook {
    ($name:ident, $section:literal) => {
        #[link_section = $section]
        #[no_mangle]
        extern "C" fn $name(_ctx: *const c_void) -> i32 {
            bpf_set_retval(bpf_get_retval());
            1
        }
    };
}

retval_hook!(ingress, "?cgroup_skb/ingress");
retval_hook!(egress, "?cgroup_skb/egress");
retval_hook!(sock_create, "?cgroup/sock_create");
retval_hook!(sock_ops, "?sockops");
retval_hook!(dev, "?cgroup/dev");
retval_hook!(bind4, "?cgroup/bind4");
retval_hook!(bind6, "?cgroup/bind6");
retval_hook!(connect4, "?cgroup/connect4");
retval_hook!(connect6, "?cgroup/connect6");
retval_hook!(post_bind4, "?cgroup/post_bind4");
retval_hook!(post_bind6, "?cgroup/post_bind6");
retval_hook!(sendmsg4, "?cgroup/sendmsg4");
retval_hook!(sendmsg6, "?cgroup/sendmsg6");
retval_hook!(sysctl, "?cgroup/sysctl");
retval_hook!(recvmsg4, "?cgroup/recvmsg4");
retval_hook!(recvmsg6, "?cgroup/recvmsg6");
retval_hook!(getsockopt, "?cgroup/getsockopt");
retval_hook!(setsockopt, "?cgroup/setsockopt");
retval_hook!(getpeername4, "?cgroup/getpeername4");
retval_hook!(getpeername6, "?cgroup/getpeername6");
retval_hook!(getsockname4, "?cgroup/getsockname4");
retval_hook!(getsockname6, "?cgroup/getsockname6");
retval_hook!(sock_release, "?cgroup/sock_release");

bpf_object!("GPL");
