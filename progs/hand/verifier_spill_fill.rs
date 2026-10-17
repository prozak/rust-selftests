// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_spill_fill.c, translated
// by hand; include!d by the generated progs/verifier_spill_fill.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

use bpf_rs_core::helpers::{bpf_dynptr_data, bpf_dynptr_from_mem};

/// `struct bpf_dynptr { __u64 __opaque[2]; }` (uapi), named so in BTF: the
/// verifier recognizes a global subprogram's `struct bpf_dynptr *` argument.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

// HAND: spill_fill_dynptr_subprog -- translate the C below (see the file comment)
//   __noinline int spill_fill_dynptr_subprog(struct bpf_dynptr *dptr)
//   {
//       long *p;
//
//       asm volatile ("*(u64 *)(r10 - 8) = %[dptr];" /* spill the CONST_PTR_TO_DYNPTR argument */
//                 "%[dptr] = *(u64 *)(r10 - 8);"
//                 : [dptr] "+r"(dptr) :: "memory");
//       p = bpf_dynptr_data(dptr, 0, sizeof(*p));
//       if (!p)
//           return 0;
//       return 0;
//   }
// `__noinline int spill_fill_dynptr_subprog(struct bpf_dynptr *dptr)`: a
// global subprogram, its argument typed `struct bpf_dynptr *` in BTF.
#[no_mangle]
#[inline(never)]
extern "C" fn spill_fill_dynptr_subprog(mut dptr: *mut bpf_dynptr) -> i32 {
    unsafe {
        // spill the CONST_PTR_TO_DYNPTR argument and fill it back
        core::arch::asm!(
            "*(u64 *)(r10 - 8) = {dptr};",
            "{dptr} = *(u64 *)(r10 - 8);",
            dptr = inout(reg) dptr,
            options(nostack)
        );
    }
    let p = bpf_dynptr_data(dptr as *const c_void, 0, 8) as *mut i64;
    if p.is_null() {
        return 0;
    }
    0
}

// HAND: spill_fill_const_ptr_to_dynptr -- translate the C below (see the file comment)
//   /* check valid spill/fill, const ptr to dynptr */
//   SEC("socket")
//   __success
//   int spill_fill_const_ptr_to_dynptr(void)
//   {
//       struct bpf_dynptr ptr;
//
//       bpf_dynptr_from_mem(dptr_mem_buf, sizeof(dptr_mem_buf), 0, &ptr);
//       return spill_fill_dynptr_subprog(&ptr);
//   }
#[link_section = "socket"]
#[no_mangle]
extern "C" fn spill_fill_const_ptr_to_dynptr() -> i32 {
    let mut ptr = bpf_dynptr { __opaque: [0; 2] };
    bpf_dynptr_from_mem(
        core::ptr::addr_of_mut!(dptr_mem_buf) as *mut c_void,
        core::mem::size_of_val(unsafe { &*core::ptr::addr_of!(dptr_mem_buf) }) as u64,
        0,
        &mut ptr as *mut bpf_dynptr as *mut c_void,
    );
    spill_fill_dynptr_subprog(&mut ptr)
}
