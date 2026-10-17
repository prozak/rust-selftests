// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_map_in_map.c, translated
// by hand; include!d by the generated progs/verifier_map_in_map.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_get_smp_processor_id, bpf_map_lookup_elem, bpf_ringbuf_reserve_dynptr, bpf_ringbuf_submit_dynptr};

// HAND: __rb_event_submit -- translate the C below (see the file comment)
//   static __noinline void __rb_event_submit(struct rb_ctx *ctx)
//   {
//       if (!ctx->rb)
//           return;
//
//       /* If the verifier (incorrectly) concludes that ctx->rb can be
//        * NULL at this point, we'll get "BPF_EXIT instruction in main
//        * prog would lead to reference leak" error
//        */
//       bpf_ringbuf_submit_dynptr(&ctx->dptr, 0);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn __rb_event_submit(ctx: *mut rb_ctx) {
    unsafe {
        if (*ctx).rb.is_null() {
            return;
        }
        bpf_ringbuf_submit_dynptr(core::ptr::addr_of_mut!((*ctx).dptr) as *mut c_void, 0);
    }
}

// HAND: map_ptr_is_never_null_rb -- translate the C below (see the file comment)
//   SEC("socket")
//   int map_ptr_is_never_null_rb(void *ctx)
//   {
//       struct rb_ctx event_ctx = __rb_event_reserve(256);
//       __rb_event_submit(&event_ctx);
//       return 0;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn map_ptr_is_never_null_rb(_ctx: *mut c_void) -> i32 {
    // __rb_event_reserve(256), always_inline in the C: the ringbuf of this
    // CPU's slot of rb_in_map, a dynptr reserved in it
    let mut event_ctx = rb_ctx { rb: core::ptr::null_mut(), dptr: bpf_dynptr { __opaque: [0; 2] } };
    let cpu = bpf_get_smp_processor_id();
    let rb_slot: u32 = cpu & 1;
    let rb = bpf_map_lookup_elem(&rb_in_map, &rb_slot);
    if !rb.is_null() {
        event_ctx.rb = rb;
        bpf_ringbuf_reserve_dynptr(rb, 256, 0, core::ptr::addr_of_mut!(event_ctx.dptr) as *mut c_void);
    }
    __rb_event_submit(&mut event_ctx);
    0
}
