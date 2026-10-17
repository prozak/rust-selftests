// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_const.c, translated
// by hand; include!d by the generated progs/verifier_const.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_check_mtu, bpf_copy_from_user, bpf_get_prandom_u32};

const TCX_PASS: i32 = 0;

// HAND: tcx1 -- translate the C below (see the file comment)
//   SEC("tc/ingress")
//   __description("rodata/strtol: write rejected")
//   __failure __msg("write into map forbidden")
//   int tcx1(struct __sk_buff *skb)
//   {
//       char buff[] = { '8', '4', '\0' };
//       bpf_strtol(buff, sizeof(buff), 0, (long *)&foo);
//       return TCX_PASS;
//   }
#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tcx1(_skb: *mut __sk_buff) -> i32 {
    let buff: [i8; 3] = [b'8' as i8, b'4' as i8, 0];
    // bpf_strtol (helper 105)
    let strtol: extern "C" fn(*const c_void, u64, u64, *mut i64) -> i64 = unsafe { core::mem::transmute(105usize) };
    strtol(buff.as_ptr() as *const c_void, 3, 0, core::ptr::addr_of!(foo) as *mut i64);
    TCX_PASS
}

// HAND: tcx2 -- translate the C below (see the file comment)
//   SEC("tc/ingress")
//   __description("bss/strtol: write accepted")
//   __success
//   int tcx2(struct __sk_buff *skb)
//   {
//       char buff[] = { '8', '4', '\0' };
//       bpf_strtol(buff, sizeof(buff), 0, &bar);
//       return TCX_PASS;
//   }
#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tcx2(_skb: *mut __sk_buff) -> i32 {
    let buff: [i8; 3] = [b'8' as i8, b'4' as i8, 0];
    // bpf_strtol (helper 105)
    let strtol: extern "C" fn(*const c_void, u64, u64, *mut i64) -> i64 = unsafe { core::mem::transmute(105usize) };
    strtol(buff.as_ptr() as *const c_void, 3, 0, core::ptr::addr_of_mut!(bar));
    TCX_PASS
}

// HAND: tcx3 -- translate the C below (see the file comment)
//   SEC("tc/ingress")
//   __description("data/strtol: write accepted")
//   __success
//   int tcx3(struct __sk_buff *skb)
//   {
//       char buff[] = { '8', '4', '\0' };
//       bpf_strtol(buff, sizeof(buff), 0, &bart);
//       return TCX_PASS;
//   }
#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tcx3(_skb: *mut __sk_buff) -> i32 {
    let buff: [i8; 3] = [b'8' as i8, b'4' as i8, 0];
    // bpf_strtol (helper 105)
    let strtol: extern "C" fn(*const c_void, u64, u64, *mut i64) -> i64 = unsafe { core::mem::transmute(105usize) };
    strtol(buff.as_ptr() as *const c_void, 3, 0, core::ptr::addr_of_mut!(bart));
    TCX_PASS
}

// HAND: tcx4 -- translate the C below (see the file comment)
//   SEC("tc/ingress")
//   __description("rodata/mtu: write rejected")
//   __failure __msg("write into map forbidden")
//   int tcx4(struct __sk_buff *skb)
//   {
//       bpf_check_mtu(skb, skb->ifindex, (__u32 *)&foo, 0, 0);
//       return TCX_PASS;
//   }
#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tcx4(skb: *mut __sk_buff) -> i32 {
    bpf_check_mtu(skb as *const c_void, unsafe { (*skb).ifindex }, core::ptr::addr_of!(foo) as *mut u32, 0, 0);
    TCX_PASS
}

// HAND: tcx5 -- translate the C below (see the file comment)
//   SEC("tc/ingress")
//   __description("bss/mtu: write accepted")
//   __success
//   int tcx5(struct __sk_buff *skb)
//   {
//       bpf_check_mtu(skb, skb->ifindex, (__u32 *)&bar, 0, 0);
//       return TCX_PASS;
//   }
#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tcx5(skb: *mut __sk_buff) -> i32 {
    bpf_check_mtu(skb as *const c_void, unsafe { (*skb).ifindex }, core::ptr::addr_of_mut!(bar) as *mut u32, 0, 0);
    TCX_PASS
}

// HAND: tcx6 -- translate the C below (see the file comment)
//   SEC("tc/ingress")
//   __description("data/mtu: write accepted")
//   __success
//   int tcx6(struct __sk_buff *skb)
//   {
//       bpf_check_mtu(skb, skb->ifindex, (__u32 *)&bart, 0, 0);
//       return TCX_PASS;
//   }
#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tcx6(skb: *mut __sk_buff) -> i32 {
    bpf_check_mtu(skb as *const c_void, unsafe { (*skb).ifindex }, core::ptr::addr_of_mut!(bart) as *mut u32, 0, 0);
    TCX_PASS
}

// HAND: tcx7 -- translate the C below (see the file comment)
//   SEC("tc/ingress")
//   __description("rodata/mark: write with unknown reg rejected")
//   __failure __msg("write into map forbidden")
//   int tcx7(struct __sk_buff *skb)
//   {
//       write_fixed((void *)&foo, skb->mark);
//       return TCX_PASS;
//   }
#[link_section = "tc/ingress"]
#[no_mangle]
extern "C" fn tcx7(skb: *mut __sk_buff) -> i32 {
    // write_fixed(&foo, skb->mark): a volatile u32 store
    unsafe { core::ptr::write_volatile(core::ptr::addr_of!(foo) as *mut u32, (*skb).mark) };
    TCX_PASS
}

// HAND: bprm -- translate the C below (see the file comment)
//   SEC("lsm.s/bprm_committed_creds")
//   __description("rodata/mark: write with unknown reg rejected")
//   __failure __msg("write into map forbidden")
//   int BPF_PROG(bprm, struct linux_binprm *bprm)
//   {
//       write_dyn((void *)&foo, &bart, bpf_get_prandom_u32() & 3);
//       return 0;
//   }
// BPF_PROG(bprm, struct linux_binprm *bprm)
#[link_section = "lsm.s/bprm_committed_creds"]
#[no_mangle]
extern "C" fn bprm(_ctx: *mut u64) -> i32 {
    // write_dyn(&foo, &bart, bpf_get_prandom_u32() & 3): bpf_copy_from_user
    bpf_copy_from_user(core::ptr::addr_of!(foo) as *mut c_void, bpf_get_prandom_u32() & 3, core::ptr::addr_of!(bart) as *const c_void);
    0
}
