// SPDX-License-Identifier: GPL-2.0
// The C bodies of tools/testing/selftests/bpf/progs/verifier_btf_array_access.c, translated
// by hand; include!d by the generated progs/verifier_btf_array_access.rs (scripts/naked_gen.py
// --with-c-bodies writes this file once, with stubs, and never overwrites it).

// The C's local types, reached by bpf_obj_new(typeof(*o)) through their
// local BTF ids (`// BTF_TYPE_ID: ... local struct ...`, scripts/type_id.py);
// `bpf_core_cast(p, struct T)` is bpf_rdonly_cast(p, bpf_core_type_id_kernel(T)).
// The C's `typedef int array_element_t; typedef array_element_t array_type_t[4]`
// cannot reach BTF from Rust (a type alias leaves no debug info), so
// typedef_array's member is the plain array.
// BTF_TYPE_ID: outer_id local struct outer
// BTF_TYPE_ID: with_ptrs_id local struct with_ptrs
// BTF_TYPE_ID: nest_id local struct nest
// BTF_TYPE_ID: typedef_array_id local struct typedef_array
// BTF_TYPE_ID: tid_vring_used struct vring_used
// BTF_TYPE_ID: tid_unix_address struct unix_address

use bpf_rs_core::helpers::{bpf_get_current_task_btf, bpf_get_prandom_u32};

extern "C" {
    fn outer_id() -> u64;
    fn with_ptrs_id() -> u64;
    fn nest_id() -> u64;
    fn typedef_array_id() -> u64;
    fn tid_vring_used() -> u64;
    fn tid_unix_address() -> u64;
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct inner {
    a: i32,
    b: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct outer {
    arr: [inner; 8],   // off 0,   stride 8, size 64
    bytes: [u8; 32],   // off 64,  stride 1, size 32
    longs: [i64; 8],   // off 96,  stride 8, size 64
    grid: [[i32; 4]; 4], // off 160, 16 ints,  size 64
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct with_ptrs {
    parr: [*mut inner; 8], // off 0, stride 8 (sizeof ptr), size 64
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct mid {
    arr: [inner; 8], // stride 8, size 64
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct nest {
    pad: i64, // off 0
    m: mid,   // off 8
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct typedef_array {
    values: [i32; 4],
}

/// offsetof(struct task_struct, comm) on this kernel, the constant the C's
/// `"i"(offsetof(...))` asm operand resolves to from vmlinux.h.
const TASK_COMM_OFF: u64 = 0x888;

// HAND: arr_field_in_bounds -- translate the C below (see the file comment)
//   /* arr[i].b, i in [0, 7], 4-byte read: stays within arr. */
//   SEC("syscall")
//   __success
//   int arr_field_in_bounds(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct outer *o;
//       int val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 7;                        \
//       r2 *= 8;                        \
//       r1 += r2;                        \
//       %[val] = *(u32 *)(r1 + 4);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arr_field_in_bounds(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(outer_id()) } as *mut outer;
    if o.is_null() {
        return 0;
    }
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 7",
            "r2 *= 8",
            "r1 += r2",
            "{val} = *(u32 *)(r1 + 4)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}

// HAND: arr_field_out_of_bounds -- translate the C below (see the file comment)
//   /* arr[i].b, i in [0, 15]: max offset runs past the end of arr. */
//   SEC("syscall")
//   __failure
//   __msg("invalid variable offset access into struct outer")
//   int arr_field_out_of_bounds(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct outer *o;
//       int val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 15;                        \
//       r2 *= 8;                        \
//       r1 += r2;                        \
//       %[val] = *(u32 *)(r1 + 4);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arr_field_out_of_bounds(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(outer_id()) } as *mut outer;
    if o.is_null() {
        return 0;
    }
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 15",
            "r2 *= 8",
            "r1 += r2",
            "{val} = *(u32 *)(r1 + 4)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}

// HAND: long_array_in_bounds -- translate the C below (see the file comment)
//   /* longs[i], i in [0, 7], 8-byte read: scalar array with stride 8. */
//   SEC("syscall")
//   __success
//   int long_array_in_bounds(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct outer *o;
//       long val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 7;                        \
//       r2 *= 8;                        \
//       r1 += r2;                        \
//       %[val] = *(u64 *)(r1 + 96);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn long_array_in_bounds(_ctx: *mut c_void) -> i64 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(outer_id()) } as *mut outer;
    if o.is_null() {
        return 0;
    }
    let val: i64;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 7",
            "r2 *= 8",
            "r1 += r2",
            "{val} = *(u64 *)(r1 + 96)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}

// HAND: byte_array_size_spanning -- translate the C below (see the file comment)
//   /*
//    * bytes[i], i in [0, 31], read as 4 bytes: min_off is valid within the array,
//    * but the 4-byte read at max_off runs past the array end. Exercises the
//    * size-aware bound in btf_struct_access().
//    */
//   SEC("syscall")
//   __failure
//   __flag(BPF_F_ANY_ALIGNMENT)
//   __msg("invalid variable offset access into struct outer")
//   int byte_array_size_spanning(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct outer *o;
//       int val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 31;                        \
//       r1 += r2;                        \
//       %[val] = *(u32 *)(r1 + 64);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn byte_array_size_spanning(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(outer_id()) } as *mut outer;
    if o.is_null() {
        return 0;
    }
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 31",
            "r1 += r2",
            "{val} = *(u32 *)(r1 + 64)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}

// HAND: byte_array_in_bounds -- translate the C below (see the file comment)
//   /* bytes[i], i in [0, 31], 1-byte read: step 1 matches the char array stride. */
//   SEC("syscall")
//   __success
//   int byte_array_in_bounds(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct outer *o;
//       int val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 31;                        \
//       r1 += r2;                        \
//       %[val] = *(u8 *)(r1 + 64);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn byte_array_in_bounds(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(outer_id()) } as *mut outer;
    if o.is_null() {
        return 0;
    }
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 31",
            "r1 += r2",
            "{val} = *(u8 *)(r1 + 64)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}

// HAND: arr_unaligned_step -- translate the C below (see the file comment)
//   /*
//    * arr[] accessed with step 4 (half of sizeof(struct inner)): the step is not
//    * a whole number of elements, so no crossed array has a matching stride.
//    */
//   SEC("syscall")
//   __failure
//   __msg("invalid variable offset access into struct outer")
//   int arr_unaligned_step(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct outer *o;
//       int val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 7;                        \
//       r2 *= 4;                        \
//       r1 += r2;                        \
//       %[val] = *(u32 *)(r1 + 0);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn arr_unaligned_step(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(outer_id()) } as *mut outer;
    if o.is_null() {
        return 0;
    }
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 7",
            "r2 *= 4",
            "r1 += r2",
            "{val} = *(u32 *)(r1 + 0)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}

// HAND: grid_outer_dim -- translate the C below (see the file comment)
//   /*
//    * grid[i][0], i in [0, 3]: steps along the outer dimension of a 2D array
//    * (stride 16). __btf_resolve_size() linearizes the array; the step is a
//    * multiple of the innermost element size (4).
//    */
//   SEC("syscall")
//   __success
//   int grid_outer_dim(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct outer *o;
//       int val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 3;                        \
//       r2 *= 16;                        \
//       r1 += r2;                        \
//       %[val] = *(u32 *)(r1 + 160);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn grid_outer_dim(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(outer_id()) } as *mut outer;
    if o.is_null() {
        return 0;
    }
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 3",
            "r2 *= 16",
            "r1 += r2",
            "{val} = *(u32 *)(r1 + 160)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}

// HAND: grid_inner_dim -- translate the C below (see the file comment)
//   /*
//    * grid[0][i], i in [0, 3]: steps along the inner dimension of a 2D array
//    * (stride 4, the innermost element size).
//    */
//   SEC("syscall")
//   __success
//   int grid_inner_dim(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct outer *o;
//       int val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 3;                        \
//       r2 *= 4;                        \
//       r1 += r2;                        \
//       %[val] = *(u32 *)(r1 + 160);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn grid_inner_dim(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(outer_id()) } as *mut outer;
    if o.is_null() {
        return 0;
    }
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 3",
            "r2 *= 4",
            "r1 += r2",
            "{val} = *(u32 *)(r1 + 160)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}

// HAND: ptr_array_in_bounds -- translate the C below (see the file comment)
//   /* parr[i], i in [0, 7], 8-byte read: stays within parr. */
//   SEC("syscall")
//   __success
//   int ptr_array_in_bounds(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct with_ptrs *o;
//       long val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 7;                        \
//       r2 *= 8;                        \
//       r1 += r2;                        \
//       %[val] = *(u64 *)(r1 + 0);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn ptr_array_in_bounds(_ctx: *mut c_void) -> i64 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(with_ptrs_id()) } as *mut with_ptrs;
    if o.is_null() {
        return 0;
    }
    let val: i64;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 7",
            "r2 *= 8",
            "r1 += r2",
            "{val} = *(u64 *)(r1 + 0)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}

// HAND: ptr_array_out_of_bounds -- translate the C below (see the file comment)
//   /*
//    * parr[i], i in [0, 15]: max offset runs past the end of parr. Without the
//    * variable-offset check on the WALK_PTR path this would be wrongly accepted.
//    */
//   SEC("syscall")
//   __failure
//   __msg("invalid variable offset access into struct with_ptrs")
//   int ptr_array_out_of_bounds(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct with_ptrs *o;
//       long val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 15;                        \
//       r2 *= 8;                        \
//       r1 += r2;                        \
//       %[val] = *(u64 *)(r1 + 0);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn ptr_array_out_of_bounds(_ctx: *mut c_void) -> i64 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(with_ptrs_id()) } as *mut with_ptrs;
    if o.is_null() {
        return 0;
    }
    let val: i64;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 15",
            "r2 *= 8",
            "r1 += r2",
            "{val} = *(u64 *)(r1 + 0)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}

// HAND: kernel_btf_array_in_bounds -- translate the C below (see the file comment)
//   /* task->comm[i], i in [0, 15], 1-byte read: stays within comm. */
//   SEC("syscall")
//   __success
//   int kernel_btf_array_in_bounds(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct task_struct *task;
//       int val = 0;
//
//       task = bpf_get_current_task_btf();
//       asm volatile ("                        \
//       r1 = %[task];                        \
//       r1 += %[off];                        \
//       r2 = %[i];                        \
//       r2 &= 15;                        \
//       r1 += r2;                        \
//       %[val] = *(u8 *)(r1 + 0);                \
//   "    : [val] "=r"(val)
//       : [task] "r"(task), [i] "r"(i),
//         [off] "i"(offsetof(struct task_struct, comm))
//       : "r1", "r2");
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn kernel_btf_array_in_bounds(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o: *mut c_void = bpf_get_current_task_btf();
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r1 += {add}",
            "r2 = {i}",
            "r2 &= 15",
            "r1 += r2",
            "{val} = *(u8 *)(r1 + 0)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, add = const TASK_COMM_OFF, out("r1") _, out("r2") _,
            options(nostack),
        );
    }
    val
}

// HAND: kernel_btf_array_out_of_bounds -- translate the C below (see the file comment)
//   /* task->comm[i], i in [0, 31]: max offset runs past comm. */
//   SEC("syscall")
//   __failure
//   __msg("invalid variable offset access into struct task_struct")
//   int kernel_btf_array_out_of_bounds(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct task_struct *task;
//       int val = 0;
//
//       task = bpf_get_current_task_btf();
//       asm volatile ("                        \
//       r1 = %[task];                        \
//       r1 += %[off];                        \
//       r2 = %[i];                        \
//       r2 &= 31;                        \
//       r1 += r2;                        \
//       %[val] = *(u8 *)(r1 + 0);                \
//   "    : [val] "=r"(val)
//       : [task] "r"(task), [i] "r"(i),
//         [off] "i"(offsetof(struct task_struct, comm))
//       : "r1", "r2");
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn kernel_btf_array_out_of_bounds(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o: *mut c_void = bpf_get_current_task_btf();
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r1 += {add}",
            "r2 = {i}",
            "r2 &= 31",
            "r1 += r2",
            "{val} = *(u8 *)(r1 + 0)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, add = const TASK_COMM_OFF, out("r1") _, out("r2") _,
            options(nostack),
        );
    }
    val
}

// HAND: nested_struct_in_bounds -- translate the C below (see the file comment)
//   /* m.arr[i].b, i in [0, 7], 4-byte read: stays within m.arr. */
//   SEC("syscall")
//   __success
//   int nested_struct_in_bounds(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct nest *o;
//       int val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 7;                        \
//       r2 *= 8;                        \
//       r1 += r2;                        \
//       %[val] = *(u32 *)(r1 + 12);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn nested_struct_in_bounds(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(nest_id()) } as *mut nest;
    if o.is_null() {
        return 0;
    }
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 7",
            "r2 *= 8",
            "r1 += r2",
            "{val} = *(u32 *)(r1 + 12)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}

// HAND: nested_struct_out_of_bounds -- translate the C below (see the file comment)
//   /* m.arr[i].b, i in [0, 15]: max offset runs past the end of m.arr. */
//   SEC("syscall")
//   __failure
//   __msg("invalid variable offset access into struct nest")
//   int nested_struct_out_of_bounds(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct nest *o;
//       int val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 15;                        \
//       r2 *= 8;                        \
//       r1 += r2;                        \
//       %[val] = *(u32 *)(r1 + 12);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn nested_struct_out_of_bounds(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(nest_id()) } as *mut nest;
    if o.is_null() {
        return 0;
    }
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 15",
            "r2 *= 8",
            "r1 += r2",
            "{val} = *(u32 *)(r1 + 12)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}

// HAND: flex_array_field -- translate the C below (see the file comment)
//   /* ring[i].len, i in [0, 63], 4-byte read: the flexible array has no upper bound. */
//   SEC("syscall")
//   __success
//   int flex_array_field(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct vring_used *o;
//       int val = 0;
//
//       o = bpf_core_cast(bpf_get_current_task_btf(), struct vring_used);
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 63;                        \
//       r2 *= 8;                        \
//       r1 += r2;                        \
//       %[val] = *(u32 *)(r1 + 8);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn flex_array_field(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_rdonly_cast(bpf_get_current_task_btf::<c_void>() as *mut c_void, tid_vring_used() as u32) };
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 63",
            "r2 *= 8",
            "r1 += r2",
            "{val} = *(u32 *)(r1 + 8)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
    }
    val
}

// HAND: flex_array_unaligned_step -- translate the C below (see the file comment)
//   /*
//    * ring[] accessed with step 4 (half of sizeof(struct vring_used_elem)): the
//    * step is not a whole number of elements, so the flexible array stride does
//    * not match.
//    */
//   SEC("syscall")
//   __failure
//   __msg("invalid variable offset access into struct vring_used")
//   int flex_array_unaligned_step(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct vring_used *o;
//       int val = 0;
//
//       o = bpf_core_cast(bpf_get_current_task_btf(), struct vring_used);
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 7;                        \
//       r2 *= 4;                        \
//       r1 += r2;                        \
//       %[val] = *(u32 *)(r1 + 4);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i)
//       : "r1", "r2");
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn flex_array_unaligned_step(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_rdonly_cast(bpf_get_current_task_btf::<c_void>() as *mut c_void, tid_vring_used() as u32) };
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 7",
            "r2 *= 4",
            "r1 += r2",
            "{val} = *(u32 *)(r1 + 4)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
    }
    val
}

// HAND: flex_array_inner_array_out_of_bounds -- translate the C below (see the file comment)
//   /*
//    * Access either name[0].sun_path[0] or one byte past sun_path.
//    * Step 108 does not match sizeof(struct sockaddr_un), which is 110.
//    * It matches the inner char array's stride, but exceeds its bounds.
//    * The flexible-tail exemption must not apply to that fixed array.
//    */
//   SEC("syscall")
//   __failure
//   __msg("invalid variable offset access into struct unix_address")
//   int flex_array_inner_array_out_of_bounds(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct unix_address *o;
//       int val = 0;
//
//       o = bpf_core_cast(bpf_get_current_task_btf(), struct unix_address);
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 1;                        \
//       r2 *= %[len];                        \
//       r1 += r2;                        \
//       %[val] = *(u8 *)(r1 + %[off]);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i),
//         __imm_const(len, sizeof_field(struct sockaddr_un, sun_path)),
//         __imm_const(off, offsetof(struct unix_address, name) +
//                  offsetof(struct sockaddr_un, sun_path))
//       : "r1", "r2");
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn flex_array_inner_array_out_of_bounds(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_rdonly_cast(bpf_get_current_task_btf::<c_void>() as *mut c_void, tid_unix_address() as u32) };
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 1",
            "r2 *= 108",
            "r1 += r2",
            "{val} = *(u8 *)(r1 + 10)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
    }
    val
}

// HAND: typedef_array_in_bounds -- translate the C below (see the file comment)
//   /*
//    * Resolving values' size crosses both the array and element typedefs.
//    * Record the array ID, not the int ID left by element-type resolution.
//    * values[i], i in [0, 3], must pass the variable-offset array check.
//    */
//   SEC("syscall")
//   __success
//   int typedef_array_in_bounds(void *ctx)
//   {
//       unsigned long i = bpf_get_prandom_u32();
//       struct typedef_array *o;
//       int val = 0;
//
//       o = bpf_obj_new(typeof(*o));
//       if (!o)
//           return 0;
//       asm volatile ("                        \
//       r1 = %[o];                        \
//       r2 = %[i];                        \
//       r2 &= 3;                        \
//       r2 *= %[elem_size];                    \
//       r1 += r2;                        \
//       %[val] = *(u32 *)(r1 + 0);                \
//   "    : [val] "=r"(val)
//       : [o] "r"(o), [i] "r"(i),
//         __imm_const(elem_size, sizeof(array_element_t))
//       : "r1", "r2");
//       bpf_obj_drop(o);
//       return val;
//   }
#[link_section = "syscall"]
#[no_mangle]
extern "C" fn typedef_array_in_bounds(_ctx: *mut c_void) -> i32 {
    let i: u64 = bpf_get_prandom_u32() as u64;
    let o = unsafe { bpf_obj_new(typedef_array_id()) } as *mut typedef_array;
    if o.is_null() {
        return 0;
    }
    let val: i32;
    unsafe {
        core::arch::asm!(
            "r1 = {o}",
            "r2 = {i}",
            "r2 &= 3",
            "r2 *= 4",
            "r1 += r2",
            "{val} = *(u32 *)(r1 + 0)",
            o = in(reg) o, i = in(reg) i, val = out(reg) val, out("r1") _, out("r2") _,
            options(nostack),
        );
        bpf_obj_drop(o as *mut c_void);
    }
    val
}
