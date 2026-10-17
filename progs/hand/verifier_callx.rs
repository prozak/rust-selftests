// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_callx.c, translated
// by hand; include!d by the generated progs/verifier_callx.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::bpf_get_prandom_u32;

/// `typedef int (*op_fn)(int)`.
#[allow(non_camel_case_types)]
type op_fn = extern "C" fn(i32) -> i32;

// HAND: global_add3 -- translate the C below (see the file comment)
//   __noinline __used
//   int global_add3(int x)
//   {
//       return x + 3;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_add3(x: i32) -> i32 {
    x.wrapping_add(3)
}

// HAND: mul3 -- translate the C below (see the file comment)
//   static __noinline int mul3(int x)
//   {
//       return x * 3;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn mul3(x: i32) -> i32 {
    x.wrapping_mul(3)
}

// HAND: sub7 -- translate the C below (see the file comment)
//   static __noinline int sub7(int x)
//   {
//       return x - 7;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn sub7(x: i32) -> i32 {
    x.wrapping_sub(7)
}

// HAND: apply_op -- translate the C below (see the file comment)
//   static __noinline int apply_op(op_fn op, int x)
//   {
//       return op(x);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn apply_op(op: op_fn, x: i32) -> i32 {
    op(x)
}

// HAND: callx_c_fn_as_arg -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(36)
//   int callx_c_fn_as_arg(void *ctx)
//   {
//       /* (5 * 3) + (28 - 7) */
//       return apply_op(mul3, 5) + apply_op(sub7, 28);
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn callx_c_fn_as_arg(_ctx: *mut c_void) -> i32 {
    // the function pointers pass through the stack so the calls stay
    // indirect (callx), as the C object's are
    let ops: [op_fn; 2] = [mul3, sub7];
    let m = unsafe { core::ptr::read_volatile(&ops[0]) };
    let s = unsafe { core::ptr::read_volatile(&ops[1]) };
    apply_op(m, 5).wrapping_add(apply_op(s, 28))
}

// HAND: callx_c_select -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(30)
//   int callx_c_select(void *ctx)
//   {
//       __u32 rnd = bpf_get_prandom_u32() & 1;
//       op_fn op = rnd ? mul3 : sub7;
//       int x = rnd ? 10 : 37;
//
//       /* 10 * 3 or 37 - 7 */
//       return op(x);
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn callx_c_select(_ctx: *mut c_void) -> i32 {
    let rnd = bpf_get_prandom_u32() & 1;
    let op: op_fn = if rnd != 0 { mul3 } else { sub7 };
    let x: i32 = if rnd != 0 { 10 } else { 37 };
    op(x)
}

// HAND: run_ops -- translate the C below (see the file comment)
//   static __noinline int run_ops(const struct ops *ops, int x)
//   {
//       return ops->second(ops->first(x)) + ops->bias;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn run_ops(ops: *mut ops, x: i32) -> i32 {
    unsafe {
        let first: op_fn = core::mem::transmute((*ops).first);
        let second: op_fn = core::mem::transmute((*ops).second);
        second(first(x)).wrapping_add((*ops).bias)
    }
}

// HAND: callx_c_ops_on_stack -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(100)
//   int callx_c_ops_on_stack(void *ctx)
//   {
//       struct ops a, b;
//
//       /* avoid an initializer with function pointers in .rodata */
//       a.first = mul3;
//       a.second = sub7;
//       a.bias = 10;
//       b.first = sub7;
//       b.second = mul3;
//       b.bias = 1;
//
//       /* ((7 * 3) - 7 + 10) + ((32 - 7) * 3 + 1) */
//       return run_ops(&a, 7) + run_ops(&b, 32);
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn callx_c_ops_on_stack(_ctx: *mut c_void) -> i32 {
    let mut a = ops { first: mul3 as op_fn as *mut c_void, second: sub7 as op_fn as *mut c_void, bias: 10 };
    let mut b = ops { first: sub7 as op_fn as *mut c_void, second: mul3 as op_fn as *mut c_void, bias: 1 };
    run_ops(&mut a, 7).wrapping_add(run_ops(&mut b, 32))
}
