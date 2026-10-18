// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_sock_addr.c, translated
// by hand; include!d by the generated progs/verifier_sock_addr.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_getsockopt, bpf_setsockopt};

const SOL_SOCKET: i32 = 1;
const SO_PRIORITY: i32 = 12;

// HAND: get_set_sk_priority -- translate the C below (from bpf_sockopt_helpers.h) (see the file comment)
//   int get_set_sk_priority(void *ctx)
//   {
//       int prio;
//
//       /* Verify that context allows calling bpf_getsockopt and
//        * bpf_setsockopt by reading and writing back socket
//        * priority.
//        */
//
//       if (bpf_getsockopt(ctx, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio)))
//           return 0;
//       if (bpf_setsockopt(ctx, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio)))
//           return 0;
//
//       return 1;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn get_set_sk_priority(ctx: *mut c_void) -> i32 {
    let mut prio = core::mem::MaybeUninit::<i32>::uninit();

    // Verify that context allows calling bpf_getsockopt and
    // bpf_setsockopt by reading and writing back socket
    // priority.

    if bpf_getsockopt(ctx, SOL_SOCKET, SO_PRIORITY, prio.as_mut_ptr() as *mut c_void, 4) != 0 {
        return 0;
    }
    if bpf_setsockopt(ctx, SOL_SOCKET, SO_PRIORITY, prio.as_mut_ptr() as *mut c_void, 4) != 0 {
        return 0;
    }

    1
}

// HAND: recvmsg4_good_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/recvmsg4")
//   __success
//   int recvmsg4_good_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/recvmsg4"]
#[no_mangle]
extern "C" fn recvmsg4_good_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: recvmsg4_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/recvmsg4")
//   __failure __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]")
//   int recvmsg4_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/recvmsg4"]
#[no_mangle]
extern "C" fn recvmsg4_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: recvmsg6_good_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/recvmsg6")
//   __success
//   int recvmsg6_good_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/recvmsg6"]
#[no_mangle]
extern "C" fn recvmsg6_good_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: recvmsg6_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/recvmsg6")
//   __failure __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]")
//   int recvmsg6_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/recvmsg6"]
#[no_mangle]
extern "C" fn recvmsg6_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: recvmsg_unix_good_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/recvmsg_unix")
//   __success
//   int recvmsg_unix_good_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/recvmsg_unix"]
#[no_mangle]
extern "C" fn recvmsg_unix_good_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: recvmsg_unix_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/recvmsg_unix")
//   __failure __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]")
//   int recvmsg_unix_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/recvmsg_unix"]
#[no_mangle]
extern "C" fn recvmsg_unix_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: sendmsg4_good_return_code_0 -- translate the C below (see the file comment)
//   SEC("cgroup/sendmsg4")
//   __success
//   int sendmsg4_good_return_code_0(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/sendmsg4"]
#[no_mangle]
extern "C" fn sendmsg4_good_return_code_0(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: sendmsg4_good_return_code_1 -- translate the C below (see the file comment)
//   SEC("cgroup/sendmsg4")
//   __success
//   int sendmsg4_good_return_code_1(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/sendmsg4"]
#[no_mangle]
extern "C" fn sendmsg4_good_return_code_1(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: sendmsg4_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/sendmsg4")
//   __failure __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]")
//   int sendmsg4_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 2;
//   }
#[link_section = "cgroup/sendmsg4"]
#[no_mangle]
extern "C" fn sendmsg4_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    2
}

// HAND: sendmsg6_good_return_code_0 -- translate the C below (see the file comment)
//   SEC("cgroup/sendmsg6")
//   __success
//   int sendmsg6_good_return_code_0(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/sendmsg6"]
#[no_mangle]
extern "C" fn sendmsg6_good_return_code_0(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: sendmsg6_good_return_code_1 -- translate the C below (see the file comment)
//   SEC("cgroup/sendmsg6")
//   __success
//   int sendmsg6_good_return_code_1(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/sendmsg6"]
#[no_mangle]
extern "C" fn sendmsg6_good_return_code_1(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: sendmsg6_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/sendmsg6")
//   __failure __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]")
//   int sendmsg6_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 2;
//   }
#[link_section = "cgroup/sendmsg6"]
#[no_mangle]
extern "C" fn sendmsg6_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    2
}

// HAND: sendmsg_unix_good_return_code_0 -- translate the C below (see the file comment)
//   SEC("cgroup/sendmsg_unix")
//   __success
//   int sendmsg_unix_good_return_code_0(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/sendmsg_unix"]
#[no_mangle]
extern "C" fn sendmsg_unix_good_return_code_0(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: sendmsg_unix_good_return_code_1 -- translate the C below (see the file comment)
//   SEC("cgroup/sendmsg_unix")
//   __success
//   int sendmsg_unix_good_return_code_1(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/sendmsg_unix"]
#[no_mangle]
extern "C" fn sendmsg_unix_good_return_code_1(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: sendmsg_unix_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/sendmsg_unix")
//   __failure __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]")
//   int sendmsg_unix_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 2;
//   }
#[link_section = "cgroup/sendmsg_unix"]
#[no_mangle]
extern "C" fn sendmsg_unix_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    2
}

// HAND: getpeername4_good_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/getpeername4")
//   __success
//   int getpeername4_good_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/getpeername4"]
#[no_mangle]
extern "C" fn getpeername4_good_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: getpeername4_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/getpeername4")
//   __failure __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]")
//   int getpeername4_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/getpeername4"]
#[no_mangle]
extern "C" fn getpeername4_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: getpeername6_good_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/getpeername6")
//   __success
//   int getpeername6_good_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/getpeername6"]
#[no_mangle]
extern "C" fn getpeername6_good_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: getpeername6_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/getpeername6")
//   __failure __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]")
//   int getpeername6_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/getpeername6"]
#[no_mangle]
extern "C" fn getpeername6_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: getpeername_unix_good_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/getpeername_unix")
//   __success
//   int getpeername_unix_good_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/getpeername_unix"]
#[no_mangle]
extern "C" fn getpeername_unix_good_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: getpeername_unix_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/getpeername_unix")
//   __failure __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]")
//   int getpeername_unix_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/getpeername_unix"]
#[no_mangle]
extern "C" fn getpeername_unix_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: getsockname4_good_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/getsockname4")
//   __success
//   int getsockname4_good_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/getsockname4"]
#[no_mangle]
extern "C" fn getsockname4_good_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: getsockname4_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/getsockname4")
//   __failure __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]")
//   int getsockname4_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/getsockname4"]
#[no_mangle]
extern "C" fn getsockname4_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: getsockname6_good_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/getsockname6")
//   __success
//   int getsockname6_good_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/getsockname6"]
#[no_mangle]
extern "C" fn getsockname6_good_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: getsockname6_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/getsockname6")
//   __failure __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]")
//   int getsockname6_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/getsockname6"]
#[no_mangle]
extern "C" fn getsockname6_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: getsockname_unix_good_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/getsockname_unix")
//   __success
//   int getsockname_unix_good_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/getsockname_unix"]
#[no_mangle]
extern "C" fn getsockname_unix_good_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: getsockname_unix_unix_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/getsockname_unix")
//   __failure __msg("At program exit the register R0 has smin=0 smax=0 should have been in [1, 1]")
//   int getsockname_unix_unix_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/getsockname_unix"]
#[no_mangle]
extern "C" fn getsockname_unix_unix_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: bind4_good_return_code_0 -- translate the C below (see the file comment)
//   SEC("cgroup/bind4")
//   __success
//   int bind4_good_return_code_0(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/bind4"]
#[no_mangle]
extern "C" fn bind4_good_return_code_0(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: bind4_good_return_code_1 -- translate the C below (see the file comment)
//   SEC("cgroup/bind4")
//   __success
//   int bind4_good_return_code_1(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/bind4"]
#[no_mangle]
extern "C" fn bind4_good_return_code_1(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: bind4_good_return_code_2 -- translate the C below (see the file comment)
//   SEC("cgroup/bind4")
//   __success
//   int bind4_good_return_code_2(struct bpf_sock_addr *ctx)
//   {
//       return 2;
//   }
#[link_section = "cgroup/bind4"]
#[no_mangle]
extern "C" fn bind4_good_return_code_2(_ctx: *mut bpf_sock_addr) -> i32 {
    2
}

// HAND: bind4_good_return_code_3 -- translate the C below (see the file comment)
//   SEC("cgroup/bind4")
//   __success
//   int bind4_good_return_code_3(struct bpf_sock_addr *ctx)
//   {
//       return 3;
//   }
#[link_section = "cgroup/bind4"]
#[no_mangle]
extern "C" fn bind4_good_return_code_3(_ctx: *mut bpf_sock_addr) -> i32 {
    3
}

// HAND: bind4_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/bind4")
//   __failure __msg("At program exit the register R0 has smin=4 smax=4 should have been in [0, 3]")
//   int bind4_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 4;
//   }
#[link_section = "cgroup/bind4"]
#[no_mangle]
extern "C" fn bind4_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    4
}

// HAND: bind6_good_return_code_0 -- translate the C below (see the file comment)
//   SEC("cgroup/bind6")
//   __success
//   int bind6_good_return_code_0(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/bind6"]
#[no_mangle]
extern "C" fn bind6_good_return_code_0(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: bind6_good_return_code_1 -- translate the C below (see the file comment)
//   SEC("cgroup/bind6")
//   __success
//   int bind6_good_return_code_1(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/bind6"]
#[no_mangle]
extern "C" fn bind6_good_return_code_1(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: bind6_good_return_code_2 -- translate the C below (see the file comment)
//   SEC("cgroup/bind6")
//   __success
//   int bind6_good_return_code_2(struct bpf_sock_addr *ctx)
//   {
//       return 2;
//   }
#[link_section = "cgroup/bind6"]
#[no_mangle]
extern "C" fn bind6_good_return_code_2(_ctx: *mut bpf_sock_addr) -> i32 {
    2
}

// HAND: bind6_good_return_code_3 -- translate the C below (see the file comment)
//   SEC("cgroup/bind6")
//   __success
//   int bind6_good_return_code_3(struct bpf_sock_addr *ctx)
//   {
//       return 3;
//   }
#[link_section = "cgroup/bind6"]
#[no_mangle]
extern "C" fn bind6_good_return_code_3(_ctx: *mut bpf_sock_addr) -> i32 {
    3
}

// HAND: bind6_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/bind6")
//   __failure __msg("At program exit the register R0 has smin=4 smax=4 should have been in [0, 3]")
//   int bind6_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 4;
//   }
#[link_section = "cgroup/bind6"]
#[no_mangle]
extern "C" fn bind6_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    4
}

// HAND: connect4_good_return_code_0 -- translate the C below (see the file comment)
//   SEC("cgroup/connect4")
//   __success
//   int connect4_good_return_code_0(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/connect4"]
#[no_mangle]
extern "C" fn connect4_good_return_code_0(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: connect4_good_return_code_1 -- translate the C below (see the file comment)
//   SEC("cgroup/connect4")
//   __success
//   int connect4_good_return_code_1(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/connect4"]
#[no_mangle]
extern "C" fn connect4_good_return_code_1(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: connect4_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/connect4")
//   __failure __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]")
//   int connect4_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 2;
//   }
#[link_section = "cgroup/connect4"]
#[no_mangle]
extern "C" fn connect4_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    2
}

// HAND: connect6_good_return_code_0 -- translate the C below (see the file comment)
//   SEC("cgroup/connect6")
//   __success
//   int connect6_good_return_code_0(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/connect6"]
#[no_mangle]
extern "C" fn connect6_good_return_code_0(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: connect6_good_return_code_1 -- translate the C below (see the file comment)
//   SEC("cgroup/connect6")
//   __success
//   int connect6_good_return_code_1(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/connect6"]
#[no_mangle]
extern "C" fn connect6_good_return_code_1(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: connect6_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/connect6")
//   __failure __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]")
//   int connect6_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 2;
//   }
#[link_section = "cgroup/connect6"]
#[no_mangle]
extern "C" fn connect6_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    2
}

// HAND: connect_unix_good_return_code_0 -- translate the C below (see the file comment)
//   SEC("cgroup/connect_unix")
//   __success
//   int connect_unix_good_return_code_0(struct bpf_sock_addr *ctx)
//   {
//       return 0;
//   }
#[link_section = "cgroup/connect_unix"]
#[no_mangle]
extern "C" fn connect_unix_good_return_code_0(_ctx: *mut bpf_sock_addr) -> i32 {
    0
}

// HAND: connect_unix_good_return_code_1 -- translate the C below (see the file comment)
//   SEC("cgroup/connect_unix")
//   __success
//   int connect_unix_good_return_code_1(struct bpf_sock_addr *ctx)
//   {
//       return 1;
//   }
#[link_section = "cgroup/connect_unix"]
#[no_mangle]
extern "C" fn connect_unix_good_return_code_1(_ctx: *mut bpf_sock_addr) -> i32 {
    1
}

// HAND: connect_unix_bad_return_code -- translate the C below (see the file comment)
//   SEC("cgroup/connect_unix")
//   __failure __msg("At program exit the register R0 has smin=2 smax=2 should have been in [0, 1]")
//   int connect_unix_bad_return_code(struct bpf_sock_addr *ctx)
//   {
//       return 2;
//   }
#[link_section = "cgroup/connect_unix"]
#[no_mangle]
extern "C" fn connect_unix_bad_return_code(_ctx: *mut bpf_sock_addr) -> i32 {
    2
}
