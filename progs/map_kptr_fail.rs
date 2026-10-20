// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![allow(named_asm_labels)]

// Translation of progs/map_kptr_fail.c: 22 programs the verifier must reject
// for a specific reason and one it must accept, all about the __kptr /
// __kptr_untrusted fields of a map value (prog_tests/map_kptr.c RUN_TESTS
// the object; map_kptr.rs is the positive sibling). The kptr pointee is a
// #[btf] view of bpf_testmod's struct, with the memb field the C object
// also carries (32 bytes, as the module's).
//
// bpf_core_type_size(struct prog_test_ref_kfunc) is a BPF_CORE_TYPE_SIZE
// relocation this pipeline does not emit (#45); the module struct is 32
// bytes, which is what the test's message names ("at off 32 size 4").
// The C object was built for a BPF CPU without BPF_ST, so the scalar store
// to a kptr in reject_scalar_store_to_kptr goes through a register (the
// store-immediate form is rejected with a different message); the value is
// produced by one asm move so llc cannot fold it into a BPF_ST.
// reject_imprecise_scalar_store_to_kptr is the C's __naked body verbatim.

use core::arch::asm;
use core::ffi::c_void;
use core::ptr::{addr_of_mut, null_mut, write_volatile};

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_get_current_comm, bpf_kptr_xchg, bpf_map_lookup_elem, bpf_this_cpu_ptr,
};
use bpf_rs_core::maps;
use bpf_rs_core::{bpf_map, bpf_object, btf_type_tags};
use btf_macros::btf;

#[btf]
struct prog_test_member1 {
    a: i32,
}

#[btf]
struct prog_test_member {
    m: prog_test_member1,
    c: i32,
}

#[btf]
struct atomic_t {
    counter: i32,
}

#[btf]
struct refcount_struct {
    refs: atomic_t,
}

#[btf]
struct prog_test_ref_kfunc {
    a: i32,
    b: i32,
    memb: prog_test_member,
    next: *mut prog_test_ref_kfunc,
    cnt: refcount_struct,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct map_value {
    buf: [u8; 8],
    unref_ptr: *mut prog_test_ref_kfunc,
    ref_ptr: *mut prog_test_ref_kfunc,
    ref_memb_ptr: *mut prog_test_member,
}

btf_type_tags! {
    map_value.unref_ptr: kptr_untrusted;
    map_value.ref_ptr: kptr;
    map_value.ref_memb_ptr: kptr;
}

bpf_map! {
    array_map {
        r#type: *const [i32; maps::ARRAY],
        key: *const i32,
        value: *const map_value,
        max_entries: *const [i32; 1],
    }
}

extern "C" {
    fn bpf_kfunc_call_test_acquire(scalar_ptr: *mut u64) -> *mut prog_test_ref_kfunc;
    fn bpf_kfunc_call_test_release(p: *mut prog_test_ref_kfunc);
}

// v = bpf_map_lookup_elem(&array_map, &key) with key = 0, as every program
// starts.
#[inline(always)]
unsafe fn lookup() -> *mut map_value {
    let key: i32 = 0;
    bpf_map_lookup_elem(&array_map, &key) as *mut map_value
}

#[inline(always)]
unsafe fn protocol_id(ctx: *mut __sk_buff) -> i32 {
    (*ctx).protocol as i32
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn size_not_bpf_dw(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        *(addr_of_mut!((*v).unref_ptr) as *mut u32) = 0;
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn non_const_var_off(ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        let id = protocol_id(ctx);
        if id < 4 || id > 12 {
            return 0;
        }
        *((v as *mut u8).offset(id as isize) as *mut u64) = 0;
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn non_const_var_off_kptr_xchg(ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        let id = protocol_id(ctx);
        if id < 4 || id > 12 {
            return 0;
        }
        bpf_kptr_xchg((v as *mut u8).offset(id as isize) as *mut c_void, null_mut());
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn misaligned_access_write(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        *((v as *mut u8).add(7) as *mut *mut c_void) = null_mut();
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn misaligned_access_read(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        *((v as *mut u8).add(1) as *mut u64) as i32
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_var_off_store(ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        let mut unref_ptr = (*v).unref_ptr;
        if unref_ptr.is_null() {
            return 0;
        }
        let id = protocol_id(ctx);
        if id < 4 || id > 12 {
            return 0;
        }
        // unref_ptr += id: the #[btf] view type is zero-sized, so the stride
        // is the module struct's 32 bytes spelled out.
        unref_ptr = (unref_ptr as *mut u8).offset(id as isize * 32) as *mut prog_test_ref_kfunc;
        (*v).unref_ptr = unref_ptr;
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_bad_type_match(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        let mut unref_ptr = (*v).unref_ptr;
        if unref_ptr.is_null() {
            return 0;
        }
        unref_ptr = (unref_ptr as *mut u8).add(4) as *mut prog_test_ref_kfunc;
        (*v).unref_ptr = unref_ptr;
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn marked_as_untrusted_or_null(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        bpf_this_cpu_ptr((*v).unref_ptr as *const c_void);
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn correct_btf_id_check_size(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        let p = (*v).unref_ptr;
        if p.is_null() {
            return 0;
        }
        // (void *)p + bpf_core_type_size(struct prog_test_ref_kfunc): 32 (header)
        *((p as *mut u8).add(32) as *mut i32)
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn inherit_untrusted_on_walk(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        let mut unref_ptr = (*v).unref_ptr;
        if unref_ptr.is_null() {
            return 0;
        }
        unref_ptr = *(&*unref_ptr).next().as_ptr();
        bpf_this_cpu_ptr(unref_ptr as *const c_void);
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_kptr_xchg_on_unref(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        bpf_kptr_xchg(addr_of_mut!((*v).unref_ptr).cast(), null_mut());
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn mark_ref_as_untrusted_or_null(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        bpf_this_cpu_ptr((*v).ref_ptr as *const c_void);
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_untrusted_store_to_ref(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        let p = (*v).ref_ptr;
        if p.is_null() {
            return 0;
        }
        /* Checkmate, clang */
        write_volatile(addr_of_mut!((*v).ref_ptr), p);
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_untrusted_xchg(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        let p = (*v).ref_ptr;
        if p.is_null() {
            return 0;
        }
        bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), p.cast());
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_bad_type_xchg(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        let mut zero: u64 = 0;
        let ref_ptr = bpf_kfunc_call_test_acquire(&mut zero);
        if ref_ptr.is_null() {
            return 0;
        }
        bpf_kptr_xchg(addr_of_mut!((*v).ref_memb_ptr).cast(), ref_ptr.cast());
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_member_of_ref_xchg(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        let mut zero: u64 = 0;
        let ref_ptr = bpf_kfunc_call_test_acquire(&mut zero);
        if ref_ptr.is_null() {
            return 0;
        }
        // &ref_ptr->memb: a #[btf] struct view has no address of its own, so
        // the relocated address of its first scalar (memb.m.a, same offset)
        // stands for it.
        bpf_kptr_xchg(
            addr_of_mut!((*v).ref_memb_ptr).cast(),
            (&*ref_ptr).memb().m().a().as_ptr() as *mut c_void,
        );
        0
    }
}

#[link_section = "?syscall"]
#[no_mangle]
extern "C" fn reject_indirect_helper_access(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        bpf_get_current_comm(v as *mut c_void, 8 + 1);
        0
    }
}

// __noinline int write_func(int *p): a global subprogram.
#[no_mangle]
#[inline(never)]
extern "C" fn write_func(p: *mut i32) -> i32 {
    unsafe {
        if !p.is_null() {
            *p = 42;
            42
        } else {
            0
        }
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_indirect_global_func_access(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        write_func((v as *mut u8).add(5) as *mut i32)
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn kptr_xchg_ref_state(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        let mut zero: u64 = 0;
        let p = bpf_kfunc_call_test_acquire(&mut zero);
        if p.is_null() {
            return 0;
        }
        bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), p.cast());
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn kptr_xchg_possibly_null(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        let mut zero: u64 = 0;
        let mut p = bpf_kfunc_call_test_acquire(&mut zero);

        /* PTR_TO_BTF_ID | PTR_MAYBE_NULL passed to bpf_kptr_xchg() */
        p = bpf_kptr_xchg(addr_of_mut!((*v).ref_ptr).cast(), p.cast()) as *mut prog_test_ref_kfunc;
        if !p.is_null() {
            bpf_kfunc_call_test_release(p);
        }
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
extern "C" fn reject_scalar_store_to_kptr(_ctx: *mut __sk_buff) -> i32 {
    unsafe {
        let v = lookup();
        if v.is_null() {
            return 0;
        }
        // *(volatile u64 *)&v->unref_ptr = 0xBADC0DE; through a register (header)
        let val: u64;
        asm!("{0} = 0xBADC0DE", out(reg) val, options(nomem, nostack));
        write_volatile(addr_of_mut!((*v).unref_ptr) as *mut u64, val);
        0
    }
}

#[link_section = "?tc"]
#[no_mangle]
#[inline(never)]
// BPF_NAKED: reject_imprecise_scalar_store_to_kptr
extern "C" fn reject_imprecise_scalar_store_to_kptr() {
    unsafe {
        asm!(
            "r0 = 0;",
            "*(u32 *)(r10 - 4) = r0;",
            "r2 = r10;",
            "r2 += -4;",
            "r1 = {array_map} ll;",
            "call 1;",
            "if r0 == 0 goto l2_reject_imprecise_scalar_store_to_kptr;",
            "r6 = r0;",
            "r9 = *(u64 *)(r6 + 0);",
            "if r9 != 0 goto l0_reject_imprecise_scalar_store_to_kptr;",
            "r7 = 0;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "goto l1_reject_imprecise_scalar_store_to_kptr;",
            "l0_reject_imprecise_scalar_store_to_kptr:",
            "r7 = 0x4141414141414141 ll;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "r5 = 1;",
            "l1_reject_imprecise_scalar_store_to_kptr:",
            "*(u64 *)(r6 + 8) = r7;",
            "l2_reject_imprecise_scalar_store_to_kptr:",
            "r0 = 0;",
            "exit;",
            array_map = sym array_map,
            options(nostack)
        );
    }
}

bpf_rs_core::test_tags! {
    size_not_bpf_dw: __failure, __msg("kptr access size must be BPF_DW");
    non_const_var_off: __failure, __msg("kptr access cannot have variable offset");
    non_const_var_off_kptr_xchg: __failure, __msg("R1 doesn't have constant offset. kptr has to be");
    misaligned_access_write: __failure, __msg("kptr access misaligned expected=8 off=7");
    misaligned_access_read: __failure, __msg("kptr access misaligned expected=8 off=1");
    reject_var_off_store: __failure, __msg("variable untrusted_ptr_ access var_off=(0x0; 0x1e0)");
    reject_bad_type_match: __failure, __msg("invalid kptr access, R1 type=untrusted_ptr_prog_test_ref_kfunc");
    marked_as_untrusted_or_null: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    correct_btf_id_check_size: __failure, __msg("access beyond struct prog_test_ref_kfunc at off 32 size 4");
    inherit_untrusted_on_walk: __failure, __msg("R1 type=untrusted_ptr_ expected=percpu_ptr_");
    reject_kptr_xchg_on_unref: __failure, __msg("off=8 kptr isn't referenced kptr");
    mark_ref_as_untrusted_or_null: __failure, __msg("Possibly NULL pointer passed to trusted R1");
    reject_untrusted_store_to_ref: __failure, __msg("store to referenced kptr disallowed");
    reject_untrusted_xchg: __failure, __msg("release function bpf_kptr_xchg expects referenced PTR_TO_BTF_ID passed to R2");
    reject_bad_type_xchg: __failure, __msg("invalid kptr access, R2 type=trusted_ptr_prog_test_ref_kfunc expected=ptr_prog_test_member");
    reject_member_of_ref_xchg: __failure, __msg("R2 must have zero offset when passed to release func");
    reject_indirect_helper_access: __failure, __msg("kptr cannot be accessed indirectly by helper");
    reject_indirect_global_func_access: __failure, __msg("kptr cannot be accessed indirectly by helper");
    kptr_xchg_ref_state: __failure, __msg("Unreleased reference id=4 alloc_insn=");
    kptr_xchg_possibly_null: __success;
    reject_scalar_store_to_kptr: __failure, __msg("invalid kptr access, R");
    reject_imprecise_scalar_store_to_kptr: __description("reject imprecise scalar store to kptr after state pruning"), __failure, __msg("invalid kptr access, R7 type=scalar");
}

bpf_object!("GPL");
