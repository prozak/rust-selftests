// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_subprog_topo.c, translated
// by hand; include!d by the generated progs/verifier_subprog_topo.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::bpf_loop;

// HAND: global_a -- translate the C below (see the file comment)
//   __noinline __used
//   int global_a(int x)
//   {
//       return static_leaf();
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_a(_x: i32) -> i32 {
    static_leaf() as i32
}

// HAND: global_b -- translate the C below (see the file comment)
//   __noinline __used
//   int global_b(int x)
//   {
//       return shared_leaf();
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_b(_x: i32) -> i32 {
    shared_leaf() as i32
}

// HAND: loop_cb -- translate the C below (see the file comment)
//   /* main calls bpf_loop() with loop_cb as the callback */
//   static int loop_cb(int idx, void *ctx)
//   {
//       return 0;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn loop_cb(_idx: u64, _ctx: *mut c_void) -> i64 {
    0
}

// HAND: topo_loop_cb -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __success __log_level(2)
//   __msg("topo_order[0] = loop_cb")
//   __msg("topo_order[1] = topo_loop_cb")
//   int topo_loop_cb(void)
//   {
//       bpf_loop(1, loop_cb, NULL, 0);
//       return 0;
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn topo_loop_cb() -> i32 {
    bpf_loop(1, loop_cb, core::ptr::null_mut::<c_void>(), 0);
    0
}

// HAND: loop_cb2 -- translate the C below (see the file comment)
//   static int loop_cb2(int idx, void *ctx)
//   {
//       return loop_cb2_leaf();
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn loop_cb2(_idx: u64, _ctx: *mut c_void) -> i64 {
    loop_cb2_leaf() as i64
}

// HAND: topo_loop_cb_chain -- translate the C below (see the file comment)
//   SEC("?raw_tp")
//   __success __log_level(2)
//   __msg("topo_order[0] = loop_cb2_leaf")
//   __msg("topo_order[1] = loop_cb2")
//   __msg("topo_order[2] = topo_loop_cb_chain")
//   int topo_loop_cb_chain(void)
//   {
//       bpf_loop(1, loop_cb2, NULL, 0);
//       return 0;
//   }
#[link_section = "?raw_tp"]
#[no_mangle]
extern "C" fn topo_loop_cb_chain() -> i32 {
    bpf_loop(1, loop_cb2, core::ptr::null_mut::<c_void>(), 0);
    0
}
