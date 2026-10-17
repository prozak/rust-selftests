// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_set_retval.c, translated
// by hand; include!d by the generated progs/verifier_set_retval.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::bpf_set_retval;

// HAND: lsm_cgroup_set_retval_zero_valid -- translate the C below (see the file comment)
//   SEC("lsm_cgroup/socket_create")
//   __description("lsm_cgroup bpf_set_retval success")
//   __success
//   int BPF_PROG(lsm_cgroup_set_retval_zero_valid, int family, int type, int protocol, int kern)
//   {
//       bpf_set_retval(0);
//       return 0;
//   }
// BPF_PROG(lsm_cgroup_set_retval_zero_valid, int family, int type, int protocol, int kern)
#[link_section = "lsm_cgroup/socket_create"]
#[no_mangle]
extern "C" fn lsm_cgroup_set_retval_zero_valid(_ctx: *mut u64) -> i32 {
    bpf_set_retval(0);
    0
}

// HAND: lsm_cgroup_set_retval_negative_valid -- translate the C below (see the file comment)
//   SEC("lsm_cgroup/socket_create")
//   __description("lsm_cgroup bpf_set_retval valid errno")
//   __success
//   int BPF_PROG(lsm_cgroup_set_retval_negative_valid, int family, int type, int protocol, int kern)
//   {
//       bpf_set_retval(-12);
//       return 0;
//   }
// BPF_PROG(lsm_cgroup_set_retval_negative_valid, int family, int type, int protocol, int kern)
#[link_section = "lsm_cgroup/socket_create"]
#[no_mangle]
extern "C" fn lsm_cgroup_set_retval_negative_valid(_ctx: *mut u64) -> i32 {
    bpf_set_retval(-12);
    0
}

// HAND: lsm_cgroup_set_retval_negative_invalid -- translate the C below (see the file comment)
//   SEC("lsm_cgroup/socket_create")
//   __description("lsm_cgroup bpf_set_retval invalid negative value")
//   __failure __msg("should have been in [-4095, 0]")
//   int BPF_PROG(lsm_cgroup_set_retval_negative_invalid, int family, int type, int protocol, int kern)
//   {
//       bpf_set_retval(-4096);
//       return 0;
//   }
// BPF_PROG(lsm_cgroup_set_retval_negative_invalid, int family, int type, int protocol, int kern)
#[link_section = "lsm_cgroup/socket_create"]
#[no_mangle]
extern "C" fn lsm_cgroup_set_retval_negative_invalid(_ctx: *mut u64) -> i32 {
    bpf_set_retval(-4096);
    0
}

// HAND: lsm_cgroup_set_retval_positive_invalid -- translate the C below (see the file comment)
//   SEC("lsm_cgroup/socket_create")
//   __description("lsm_cgroup bpf_set_retval invalid positive value")
//   __failure __msg("should have been in [-4095, 0]")
//   int BPF_PROG(lsm_cgroup_set_retval_positive_invalid, int family, int type, int protocol, int kern)
//   {
//       bpf_set_retval(1);
//       return 0;
//   }
// BPF_PROG(lsm_cgroup_set_retval_positive_invalid, int family, int type, int protocol, int kern)
#[link_section = "lsm_cgroup/socket_create"]
#[no_mangle]
extern "C" fn lsm_cgroup_set_retval_positive_invalid(_ctx: *mut u64) -> i32 {
    bpf_set_retval(1);
    0
}

// HAND: cgroup_dev_set_retval_0 -- translate the C below (see the file comment)
//   SEC("cgroup/dev")
//   __description("cgroup_device bpf_set_retval success")
//   __success
//   int cgroup_dev_set_retval_0(struct bpf_cgroup_dev_ctx *ctx)
//   {
//       bpf_set_retval(0);
//       return 1;
//   }
#[link_section = "cgroup/dev"]
#[no_mangle]
extern "C" fn cgroup_dev_set_retval_0(_ctx: *mut bpf_cgroup_dev_ctx) -> i32 {
    bpf_set_retval(0);
    1
}

// HAND: cgroup_dev_set_retval_neg_maxerrno -- translate the C below (see the file comment)
//   SEC("cgroup/dev")
//   __description("cgroup_device bpf_set_retval valid errno")
//   __success
//   int cgroup_dev_set_retval_neg_maxerrno(struct bpf_cgroup_dev_ctx *ctx)
//   {
//       bpf_set_retval(-4095);
//       return 1;
//   }
#[link_section = "cgroup/dev"]
#[no_mangle]
extern "C" fn cgroup_dev_set_retval_neg_maxerrno(_ctx: *mut bpf_cgroup_dev_ctx) -> i32 {
    bpf_set_retval(-4095);
    1
}

// HAND: cgroup_dev_set_retval_1 -- translate the C below (see the file comment)
//   SEC("cgroup/dev")
//   __description("cgroup_device bpf_set_retval invalid positive value")
//   __failure __msg("should have been in [-4095, 0]")
//   int cgroup_dev_set_retval_1(struct bpf_cgroup_dev_ctx *ctx)
//   {
//       bpf_set_retval(1);
//       return 1;
//   }
#[link_section = "cgroup/dev"]
#[no_mangle]
extern "C" fn cgroup_dev_set_retval_1(_ctx: *mut bpf_cgroup_dev_ctx) -> i32 {
    bpf_set_retval(1);
    1
}

// HAND: cgroup_dev_set_retval_neg_4096 -- translate the C below (see the file comment)
//   SEC("cgroup/dev")
//   __description("cgroup_device bpf_set_retval invalid negative value")
//   __failure __msg("should have been in [-4095, 0]")
//   int cgroup_dev_set_retval_neg_4096(struct bpf_cgroup_dev_ctx *ctx)
//   {
//       bpf_set_retval(-4096);
//       return 1;
//   }
#[link_section = "cgroup/dev"]
#[no_mangle]
extern "C" fn cgroup_dev_set_retval_neg_4096(_ctx: *mut bpf_cgroup_dev_ctx) -> i32 {
    bpf_set_retval(-4096);
    1
}
