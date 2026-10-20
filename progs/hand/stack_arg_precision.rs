// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/stack_arg_precision.c, translated
// by hand; include!d by the generated progs/stack_arg_precision.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// HAND: __btf_kfunc_gen -- translate the C below (see the file comment)
//   /* Force kfunc extern BTF generation for inline asm call below.
//    * Uses its own SEC so it's not included as a .text subprog.
//    * The '?' prefix sets autoload=false so libbpf won't load it.
//    */
//   SEC("?tc")
//   int __btf_kfunc_gen(struct __sk_buff *ctx)
//   {
//       char buf[8] = {};
//
//       return bpf_kfunc_call_stack_arg_mem(0, 0, 0, 0, 0, buf, sizeof(buf));
//   }
#[link_section = "?tc"]
#[no_mangle]
extern "C" fn __btf_kfunc_gen(_ctx: *mut __sk_buff) -> i32 {
    let mut buf = [0u8; 8];

    unsafe { bpf_kfunc_call_stack_arg_mem(0, 0, 0, 0, 0, buf.as_mut_ptr() as *mut c_void, 8) as i32 }
}
