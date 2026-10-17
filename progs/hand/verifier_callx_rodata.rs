// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_callx_rodata.c, translated
// by hand; include!d by the generated progs/verifier_callx_rodata.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::bpf_skb_pull_data;

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

// HAND: pull_data -- translate the C below (see the file comment)
//   static __noinline __used int pull_data(struct __sk_buff *skb)
//   {
//       return bpf_skb_pull_data(skb, 0);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn pull_data(skb: *mut c_void) -> i32 {
    bpf_skb_pull_data(skb, 0) as i32
}

// HAND: calls_pull_data -- translate the C below (see the file comment)
//   static __noinline __used int calls_pull_data(struct __sk_buff *skb)
//   {
//       return pull_data(skb) + 1;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn calls_pull_data(skb: *mut c_void) -> i32 {
    pull_data(skb).wrapping_add(1)
}

// HAND: global_calls_pull_data -- translate the C below (see the file comment)
//   __noinline __used int global_calls_pull_data(struct __sk_buff *skb)
//   {
//       return calls_pull_data(skb) + 2;
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn global_calls_pull_data(skb: *mut __sk_buff) -> i32 {
    calls_pull_data(skb as *mut c_void).wrapping_add(2)
}

// HAND: op0 -- translate the C below (see the file comment)
//   (definition of op0 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op0(x: i32) -> i32 {
    x.wrapping_mul(0 + 2).wrapping_add(0)
}

// HAND: op1 -- translate the C below (see the file comment)
//   (definition of op1 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op1(x: i32) -> i32 {
    x.wrapping_mul(1 + 2).wrapping_add(1)
}

// HAND: op2 -- translate the C below (see the file comment)
//   (definition of op2 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op2(x: i32) -> i32 {
    x.wrapping_mul(2 + 2).wrapping_add(2)
}

// HAND: op3 -- translate the C below (see the file comment)
//   (definition of op3 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op3(x: i32) -> i32 {
    x.wrapping_mul(3 + 2).wrapping_add(3)
}

// HAND: op4 -- translate the C below (see the file comment)
//   (definition of op4 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op4(x: i32) -> i32 {
    x.wrapping_mul(4 + 2).wrapping_add(4)
}

// HAND: op5 -- translate the C below (see the file comment)
//   (definition of op5 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op5(x: i32) -> i32 {
    x.wrapping_mul(5 + 2).wrapping_add(5)
}

// HAND: op6 -- translate the C below (see the file comment)
//   (definition of op6 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op6(x: i32) -> i32 {
    x.wrapping_mul(6 + 2).wrapping_add(6)
}

// HAND: op7 -- translate the C below (see the file comment)
//   (definition of op7 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op7(x: i32) -> i32 {
    x.wrapping_mul(7 + 2).wrapping_add(7)
}

// HAND: op8 -- translate the C below (see the file comment)
//   (definition of op8 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op8(x: i32) -> i32 {
    x.wrapping_mul(8 + 2).wrapping_add(8)
}

// HAND: op9 -- translate the C below (see the file comment)
//   (definition of op9 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op9(x: i32) -> i32 {
    x.wrapping_mul(9 + 2).wrapping_add(9)
}

// HAND: op10 -- translate the C below (see the file comment)
//   (definition of op10 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op10(x: i32) -> i32 {
    x.wrapping_mul(10 + 2).wrapping_add(10)
}

// HAND: op11 -- translate the C below (see the file comment)
//   (definition of op11 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op11(x: i32) -> i32 {
    x.wrapping_mul(11 + 2).wrapping_add(11)
}

// HAND: op12 -- translate the C below (see the file comment)
//   (definition of op12 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op12(x: i32) -> i32 {
    x.wrapping_mul(12 + 2).wrapping_add(12)
}

// HAND: op13 -- translate the C below (see the file comment)
//   (definition of op13 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op13(x: i32) -> i32 {
    x.wrapping_mul(13 + 2).wrapping_add(13)
}

// HAND: op14 -- translate the C below (see the file comment)
//   (definition of op14 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op14(x: i32) -> i32 {
    x.wrapping_mul(14 + 2).wrapping_add(14)
}

// HAND: op15 -- translate the C below (see the file comment)
//   (definition of op15 not found in the source)
#[no_mangle]
#[inline(never)]
extern "C" fn op15(x: i32) -> i32 {
    x.wrapping_mul(15 + 2).wrapping_add(15)
}

// HAND: callx_c_table -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(50)
//   int callx_c_table(void *ctx)
//   {
//       unsigned int i = op_idx;
//
//       if (i >= sizeof(ops) / sizeof(ops[0]))
//           return -1;
//       /* op11(3) = 3 * 13 + 11 */
//       return ops[i](3);
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn callx_c_table(_ctx: *mut c_void) -> i32 {
    let i = unsafe { op_idx } as u32;
    if i >= 16 {
        return -1;
    }
    // op11(3) = 3 * 13 + 11
    let op: op_fn = unsafe { *core::ptr::addr_of!(ops).cast::<op_fn>().add(i as usize) };
    op(3)
}

// HAND: callx_c_table_null_check -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(50)
//   int callx_c_table_null_check(void *ctx)
//   {
//       unsigned int i = op_idx;
//       op_fn op;
//
//       if (i >= sizeof(ops) / sizeof(ops[0]))
//           return -1;
//       /* the address of a function is not known until the program is jitted */
//       op = ops[i];
//       if (!op)
//           return -2;
//       return op(3);
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn callx_c_table_null_check(_ctx: *mut c_void) -> i32 {
    let i = unsafe { op_idx } as u32;
    if i >= 16 {
        return -1;
    }
    // the address of a function is not known until the program is jitted
    let op = unsafe { *core::ptr::addr_of!(ops).cast::<usize>().add(i as usize) };
    if op == 0 {
        return -2;
    }
    let op: op_fn = unsafe { core::mem::transmute(op) };
    op(3)
}

// HAND: use_shape -- translate the C below (see the file comment)
//   static __noinline int use_shape(const struct shape_ops *ops, int x)
//   {
//       return ops->area(x) * ops->scale + ops->perimeter(ops->id);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn use_shape(sops: *mut shape_ops, x: i32) -> i32 {
    unsafe {
        let area = (*sops).area;
        let perimeter = (*sops).perimeter;
        (area(x) as i64).wrapping_mul((*sops).scale).wrapping_add(perimeter((*sops).id) as i64) as i32
    }
}

// HAND: callx_c_ops_mixed_with_data -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(433)
//   int callx_c_ops_mixed_with_data(void *ctx)
//   {
//       /*
//        * square: op1(2) * 10 + op2(1) = 7 * 10 + 6 = 76
//        * circle: op3(3) * 20 + op1(2) = 18 * 20 + 7 = 367
//        * minus 10, since op_idx is 11
//        */
//       return use_shape(&square_ops, 2) + use_shape(&circle_ops, 3) - (op_idx == 11 ? 10 : 0);
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn callx_c_ops_mixed_with_data(_ctx: *mut c_void) -> i32 {
    // square: op1(2) * 10 + op2(1) = 7 * 10 + 6 = 76
    // circle: op3(3) * 20 + op1(2) = 18 * 20 + 7 = 367
    // minus 10, since op_idx is 11
    let sq = use_shape(core::ptr::addr_of!(square_ops) as *mut shape_ops, 2);
    let ci = use_shape(core::ptr::addr_of!(circle_ops) as *mut shape_ops, 3);
    sq.wrapping_add(ci).wrapping_sub(if unsafe { op_idx } == 11 { 10 } else { 0 })
}

// HAND: callx_c_ops_selected -- translate the C below (see the file comment)
//   /* the ops are selected at run time */
//   SEC("socket")
//   __success __retval(367)
//   int callx_c_ops_selected(void *ctx)
//   {
//       const struct shape_ops *ops = op_idx == 11 ? &circle_ops : &square_ops;
//
//       return use_shape(ops, 3);
//   }
// the ops are selected at run time
#[link_section = "socket"]
#[no_mangle]
extern "C" fn callx_c_ops_selected(_ctx: *mut c_void) -> i32 {
    let sel = if unsafe { op_idx } == 11 { core::ptr::addr_of!(circle_ops) } else { core::ptr::addr_of!(square_ops) };
    use_shape(sel as *mut shape_ops, 3)
}

// HAND: call_by_switch -- translate the C below (see the file comment)
//   /*
//    * clang-22 with -mcpu=v4 drops the lookup table it builds for this switch
//    * ("Undefined temporary symbol .Lswitch.table.call_by_switch").
//    * Fixed in clang-23 by llvm commit 9fc458a1d95b.
//    *
//    * https://github.com/llvm/llvm-project/commit/9fc458a1d95b
//    */
//   #if __clang_major__ != 22 || __BPF_CPU_VERSION__ < 4
//   /* the compiler might turn the switch into a table that has no symbol */
//   static __noinline int call_by_switch(unsigned int idx, int x)
//   {
//       op_fn op;
//
//       switch (idx) {
//       case 0:
//           op = op8;
//           break;
//       case 1:
//           op = op9;
//           break;
//       case 2:
//           op = op10;
//           break;
//       case 3:
//           op = op11;
//           break;
//       case 4:
//           op = op12;
//           break;
//       case 5:
//           op = op13;
//           break;
//       case 6:
//           op = op14;
//           break;
//       case 7:
//           op = op15;
//           break;
//       default:
//           return -1;
//       }
//       return op(x);
//   }
#[no_mangle]
#[inline(never)]
extern "C" fn call_by_switch(idx: u32, x: i32) -> i32 {
    // the compiler might turn the switch into a table that has no symbol
    let op: op_fn = match idx {
        0 => op8,
        1 => op9,
        2 => op10,
        3 => op11,
        4 => op12,
        5 => op13,
        6 => op14,
        7 => op15,
        _ => return -1,
    };
    op(x)
}

// HAND: callx_c_switch_table -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(50)
//   int callx_c_switch_table(void *ctx)
//   {
//       /* op11(3) = 3 * 13 + 11 */
//       return call_by_switch(op_idx - 8, 3);
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn callx_c_switch_table(_ctx: *mut c_void) -> i32 {
    // op11(3) = 3 * 13 + 11
    call_by_switch((unsafe { op_idx }).wrapping_sub(8) as u32, 3)
}

// HAND: callx_c_packed_struct -- translate the C below (see the file comment)
//   SEC("socket")
//   __success __retval(7)
//   int callx_c_packed_struct(void *ctx)
//   {
//       return packed_ops[op_idx & 1].tag;
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn callx_c_packed_struct(_ctx: *mut c_void) -> i32 {
    unsafe {
        let e = core::ptr::addr_of!(packed_ops).cast::<__anon_type236>().add((op_idx & 1) as usize);
        core::ptr::addr_of!((*e).tag).read_unaligned() as i32
    }
}
