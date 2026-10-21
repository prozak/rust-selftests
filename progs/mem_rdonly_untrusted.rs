// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]
#![feature(linkage)]

// Translation of progs/mem_rdonly_untrusted.c: how the verifier types the
// memory behind bpf_rdonly_cast() (rdonly_untrusted_mem) and merges it
// with ringbuf / map value / stack / PTR_TO_BTF_ID pointers reaching the
// same load. The C's `asm volatile` blocks are the match targets of the
// __log_level(2) __msg lines, so they are kept instruction for instruction
// (r7/r8/r9 clobbered as in the C, the inputs in compiler-chosen regs).
//
// bpf_core_type_id_kernel(struct sock) is the BTF_TYPE_ID extern below
// (scripts/type_id.py), bpf_core_enum_value_exists(enum bpf_features,
// BPF_FEAT_RDONLY_CAST_TO_VOID) the BTF_ENUM_VALUE one (an ENUMVAL_EXISTS
// relocation on the C object's copy of the enum).
// BTF_TYPE_ID: tid_sock struct sock
// BTF_ENUM_VALUE: feat_rdonly_cast_to_void_exists exists enum bpf_features BPF_FEAT_RDONLY_CAST_TO_VOID

use core::arch::asm;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr::{addr_of, addr_of_mut, null, null_mut};
use core::sync::atomic::{AtomicI32, AtomicI64, Ordering};

use bpf_rs_core::helpers::{
    bpf_copy_from_user, bpf_dynptr_from_mem, bpf_get_current_task_btf, bpf_get_prandom_u32,
    bpf_map_lookup_elem, bpf_ringbuf_discard, bpf_ringbuf_reserve,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;

#[btf]
struct nameidata {
    pathname: *const u8,
    flags: u32,
}

#[btf]
struct task_struct {
    nameidata: *mut nameidata,
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_dynptr {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C, align(8))]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

extern "C" {
    fn tid_sock() -> u64;
    fn feat_rdonly_cast_to_void_exists() -> u64;
    fn bpf_rdonly_cast(obj: *const c_void, btf_id: u32) -> *mut c_void;
    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
    fn bpf_dynptr_slice(
        ptr: *const bpf_dynptr,
        offset: u32,
        buffer__opt: *mut c_void,
        buffer__szk: u32,
    ) -> *mut c_void;
    fn bpf_kfunc_trusted_num_test(ptr: *mut i32);
}

bpf_map! {
    ringbuf {
        r#type: *const [i32; maps::RINGBUF],
        max_entries: *const [i32; 4096],
    }
}

#[link_section = ".maps"]
#[no_mangle]
static array: BpfMap<u32, u64, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut dynptr_data: [u8; 8] = [0; 8];

#[no_mangle]
static mut zero: i32 = 0;

// __attribute__((__aligned__(8))) u8 global[] = { ... }: the only .data
// symbol, so its runtime address is the mmap'ed section start (page
// aligned), as the C's.
#[no_mangle]
static mut global: [u8; 9] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn btf_id_to_ptr_mem(_ctx: *const c_void) -> i32 {
    unsafe {
        let task: *mut task_struct = bpf_get_current_task_btf();
        let idata: *mut nameidata = *(&*task).nameidata().as_ptr();
        // bpf_core_field_offset(struct nameidata, pathname): the relocated
        // field address minus the base leaves the pure offset.
        let off: u64 = (&*idata).pathname().as_ptr() as u64 - idata as u64;
        let ret: u64;
        /*
         * asm block to have reliable match target for __msg, equivalent of:
         *   ret = task->nameidata->pathname[0];
         */
        asm!(
            "r7 = {idata}",
            "r7 += {off}",
            "r8 = *(u64 *)(r7 + 0)",
            "r9 = *(u8 *)(r8 + 0)",
            "{ret} = r9",
            ret = out(reg) ret,
            idata = in(reg) idata,
            off = in(reg) off,
            out("r7") _,
            out("r8") _,
            out("r9") _,
        );
        ret as i32
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn ldx_is_ok_bad_addr(_ctx: *const c_void) -> i32 {
    unsafe {
        if feat_rdonly_cast_to_void_exists() == 0 {
            return 42;
        }
        let p = bpf_rdonly_cast(null(), 0) as *const i8;
        *p.add(0x7fff) as i32
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn ldx_is_ok_good_addr(_ctx: *const c_void) -> i32 {
    unsafe {
        let v: i32 = 1;
        let p = bpf_rdonly_cast(addr_of!(v) as *const c_void, 0) as *const i32;
        *p
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn offset_not_tracked(_ctx: *const c_void) -> i32 {
    unsafe {
        let mut p = bpf_rdonly_cast(null(), 0) as *const i32;
        let mut s: i32 = 0;
        let mut it = bpf_iter_num { __opaque: [0; 1] };
        // bpf_for(i, 0, 1000 * 1000 * 1000)
        bpf_iter_num_new(&mut it, 0, 1000 * 1000 * 1000);
        loop {
            let i = bpf_iter_num_next(&mut it);
            if i.is_null() {
                break;
            }
            p = p.add(1);
            s = s.wrapping_add(*p);
        }
        bpf_iter_num_destroy(&mut it);
        s
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn stx_not_ok(_ctx: *const c_void) -> i32 {
    unsafe {
        let v: i32 = 1;
        let p = bpf_rdonly_cast(addr_of!(v) as *const c_void, 0) as *mut i32;
        *p = 1;
        0
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn atomic_not_ok(_ctx: *const c_void) -> i32 {
    unsafe {
        let v: i32 = 1;
        let p = bpf_rdonly_cast(addr_of!(v) as *const c_void, 0) as *const AtomicI32;
        // __sync_fetch_and_add(p, 1)
        (*p).fetch_add(1, Ordering::SeqCst);
        0
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn atomic_rmw_not_ok(_ctx: *const c_void) -> i32 {
    unsafe {
        let v: i64 = 1;
        let p = bpf_rdonly_cast(addr_of!(v) as *const c_void, 0) as *const AtomicI64;
        // return __sync_val_compare_and_swap(p, 0, 42);
        match (*p).compare_exchange(0, 42, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(old) | Err(old) => old as i32,
        }
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn kfunc_param_not_ok(_ctx: *const c_void) -> i32 {
    unsafe {
        let p = bpf_rdonly_cast(null(), 0) as *mut i32;
        bpf_kfunc_trusted_num_test(p);
        0
    }
}

#[link_section = "?fentry.s/__x64_sys_getpgid"]
#[no_mangle]
extern "C" fn helper_param_not_ok(_ctx: *const c_void) -> i32 {
    unsafe {
        let p = bpf_rdonly_cast(null(), 0);
        /*
         * Any helper with ARG_MEM_SIZE_OR_ZERO constraint will do,
         * the most permissive constraint
         */
        bpf_copy_from_user(p, 0, 42 as *const c_void);
        0
    }
}

// static __noinline u64 *get_some_addr(void)
#[inline(never)]
fn get_some_addr() -> *mut u64 {
    unsafe {
        if bpf_get_prandom_u32() != 0 {
            bpf_rdonly_cast(null(), tid_sock() as u32) as *mut u64
        } else {
            bpf_rdonly_cast(null(), 0) as *mut u64
        }
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn mixed_mem_type(_ctx: *const c_void) -> i32 {
    unsafe {
        /* Try to avoid compiler hoisting load to if branches by using __noinline func. */
        let p = get_some_addr();
        *p as i32
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn mixed_mem_untrusted_btf_id_type(_ctx: *const c_void) -> i32 {
    unsafe {
        let p = bpf_ringbuf_reserve(&ringbuf, 8, 0) as *mut u64;
        if p.is_null() {
            return 1;
        }
        *p = 42;
        let q = bpf_rdonly_cast(null(), tid_sock() as u32) as *mut u64;
        /*
         * The load below is reached with PTR_TO_MEM | MEM_RINGBUF on one
         * path and with PTR_TO_BTF_ID | PTR_UNTRUSTED on the other. The
         * merged type has to keep the BPF_PROBE_MEM rewrite, otherwise
         * the NULL deref taken at runtime panics the kernel instead of
         * returning 0.
         */
        let v: u64;
        asm!(
            "r7 = {p}",
            "if {zero} != 0 goto +1",
            "r7 = {q}",
            "r8 = *(u64 *)(r7 + 0)",
            "{v} = r8",
            v = out(reg) v,
            p = in(reg) p,
            q = in(reg) q,
            zero = in(reg) zero,
            out("r7") _,
            out("r8") _,
        );
        bpf_ringbuf_discard(p as *mut c_void, 0);
        v as i32
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn mixed_mem_btf_id_type(_ctx: *const c_void) -> i32 {
    unsafe {
        let p = bpf_ringbuf_reserve(&ringbuf, 4, 0) as *mut u32;
        if p.is_null() {
            return 1;
        }
        *p = 42;
        let task: *mut task_struct = bpf_get_current_task_btf();
        /*
         * A plain BTF pointer walk yields a bare PTR_TO_BTF_ID, and
         * task->nameidata is NULL unless the task currently is in the
         * middle of a path lookup.
         */
        let nd: *mut nameidata = *(&*task).nameidata().as_ptr();
        let q = (&*nd).flags().as_ptr() as *const u32;
        /*
         * Same as above, except that the other path yields a bare
         * PTR_TO_BTF_ID. Merging it with PTR_TO_MEM used to drop the
         * BPF_PROBE_MEM rewrite the bare PTR_TO_BTF_ID would have
         * gotten on its own.
         */
        let v: u64;
        asm!(
            "r7 = {p}",
            "if {zero} != 0 goto +1",
            "r7 = {q}",
            "r8 = *(u32 *)(r7 + 0)",
            "{v} = r8",
            v = out(reg) v,
            p = in(reg) p,
            q = in(reg) q,
            zero = in(reg) zero,
            out("r7") _,
            out("r8") _,
        );
        bpf_ringbuf_discard(p as *mut c_void, 0);
        v as i32
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn mixed_rdonly_mem_btf_id_type(_ctx: *const c_void) -> i32 {
    unsafe {
        let mut dptr = MaybeUninit::<bpf_dynptr>::uninit();
        let mut buf = MaybeUninit::<[u8; 4]>::uninit();

        if bpf_dynptr_from_mem(
            addr_of_mut!(dynptr_data) as *mut c_void,
            8,
            0,
            dptr.as_mut_ptr() as *mut c_void,
        ) != 0
        {
            return 1;
        }
        let p = bpf_dynptr_slice(dptr.as_ptr(), 0, buf.as_mut_ptr() as *mut c_void, 4) as *mut u32;
        if p.is_null() {
            return 1;
        }
        let task: *mut task_struct = bpf_get_current_task_btf();
        let nd: *mut nameidata = *(&*task).nameidata().as_ptr();
        let q = (&*nd).flags().as_ptr() as *const u32;
        /*
         * Same as above, except that the PTR_TO_MEM side already carries
         * MEM_RDONLY. Merging it with a bare PTR_TO_BTF_ID used to yield
         * PTR_TO_MEM | MEM_RDONLY, which is not rewritten either since
         * only its PTR_UNTRUSTED variant is.
         */
        let v: u64;
        asm!(
            "r7 = {p}",
            "if {zero} != 0 goto +1",
            "r7 = {q}",
            "r8 = *(u32 *)(r7 + 0)",
            "{v} = r8",
            v = out(reg) v,
            p = in(reg) p,
            q = in(reg) q,
            zero = in(reg) zero,
            out("r7") _,
            out("r8") _,
        );
        v as i32
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn mixed_mem_mem_type(_ctx: *const c_void) -> i32 {
    unsafe {
        let p = bpf_ringbuf_reserve(&ringbuf, 8, 0) as *mut u64;
        if p.is_null() {
            return 1;
        }
        *p = 42;
        let q = bpf_rdonly_cast(null(), 0) as *mut u64;
        /*
         * Both paths are PTR_TO_MEM based, so they used to not trip the
         * type mismatch check and skipped the merge altogether, leaving
         * the insn with the PTR_TO_MEM | MEM_RINGBUF recorded first and
         * hence without the BPF_PROBE_MEM rewrite the other path needs.
         */
        let v: u64;
        asm!(
            "r7 = {q}",
            "if {zero} == 0 goto +1",
            "r7 = {p}",
            "r8 = *(u64 *)(r7 + 0)",
            "{v} = r8",
            v = out(reg) v,
            p = in(reg) p,
            q = in(reg) q,
            zero = in(reg) zero,
            out("r7") _,
            out("r8") _,
        );
        bpf_ringbuf_discard(p as *mut c_void, 0);
        v as i32
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn mixed_map_value_mem_type(_ctx: *const c_void) -> i32 {
    unsafe {
        let key: u32 = 0;
        let p = bpf_map_lookup_elem(&array, &key) as *mut u64;
        if p.is_null() {
            return 1;
        }
        let q = bpf_rdonly_cast(null(), 0) as *mut u64;
        /*
         * PTR_TO_MAP_VALUE is neither PTR_TO_MEM nor PTR_TO_BTF_ID based,
         * so it cannot be merged into a type which keeps the BPF_PROBE_MEM
         * rewrite the PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED of the other
         * path needs. Both bases were mismatch ok, hence the load used to be
         * accepted with the PTR_TO_MAP_VALUE recorded and the NULL deref on
         * the second path panicked the kernel.
         */
        let v: u64;
        asm!(
            "r7 = {q}",
            "if {zero} == 0 goto +1",
            "r7 = {p}",
            "r8 = *(u64 *)(r7 + 0)",
            "{v} = r8",
            v = out(reg) v,
            p = in(reg) p,
            q = in(reg) q,
            zero = in(reg) zero,
            out("r7") _,
            out("r8") _,
        );
        v as i32
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn mixed_stack_mem_type(_ctx: *const c_void) -> i32 {
    unsafe {
        let p = bpf_rdonly_cast(null(), 0) as *mut u64;
        let s: u64 = 42;
        /*
         * Same as above, but for a PTR_TO_STACK on the other path.
         */
        let v: u64;
        asm!(
            "r7 = {p}",
            "if {zero} == 0 goto +1",
            "r7 = {s}",
            "r8 = *(u64 *)(r7 + 0)",
            "{v} = r8",
            v = out(reg) v,
            p = in(reg) p,
            s = in(reg) addr_of!(s),
            zero = in(reg) zero,
            out("r7") _,
            out("r8") _,
        );
        v as i32
    }
}

// __always_inline static u64 combine(void *p): the four loads read the same
// bytes, so LLVM folds them into the one u64 load clang also emits.
#[inline(always)]
unsafe fn combine(p: *const u8) -> u64 {
    let mut acc: u64 = 0;
    acc |= (*(p as *const u64) >> 56) << 24;
    acc |= ((*(p as *const u32) >> 24) as u64) << 16;
    acc |= ((*(p as *const u16) >> 8) as u64) << 8;
    acc |= *p as u64;
    acc
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn diff_size_access(_ctx: *const c_void) -> i32 {
    unsafe { combine(bpf_rdonly_cast(addr_of!(global) as *const c_void, 0) as *const u8) as i32 }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn misaligned_access(_ctx: *const c_void) -> i32 {
    unsafe {
        combine((bpf_rdonly_cast(addr_of!(global) as *const c_void, 0) as *const u8).add(1)) as i32
    }
}

// __weak int return_one(void)
#[no_mangle]
#[inline(never)]
#[linkage = "weak"]
extern "C" fn return_one() -> i32 {
    1
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn null_check(_ctx: *const c_void) -> i32 {
    unsafe {
        let p = bpf_rdonly_cast(null(), 0) as *const i32;
        if p.is_null() {
            /* make this a function call to avoid compiler
             * moving r0 assignment before check.
             */
            return return_one();
        }
        0
    }
}

#[link_section = "socket"]
#[no_mangle]
extern "C" fn ldx_is_ok_commuted_addr(_ctx: *const c_void) -> i32 {
    unsafe {
        let v: i32 = 1;
        let p = bpf_rdonly_cast(addr_of!(v) as *const c_void, 0) as *const i32;
        let derived: *const i32;
        asm!(
            "{dst} = 0",
            "{dst} += {src}",
            dst = out(reg) derived,
            src = in(reg) p,
        );
        *derived
    }
}

bpf_rs_core::test_tags! {
    btf_id_to_ptr_mem: __success, __log_level("2"), __msg("r8 = *(u64 *)(r7 +0)          ; R7=ptr_nameidata(imm={{[0-9]+}}) R8=rdonly_untrusted_mem(sz=0)"), __msg("r9 = *(u8 *)(r8 +0)           ; R8=rdonly_untrusted_mem(sz=0) R9=scalar");
    ldx_is_ok_bad_addr: __success, __retval("0");
    ldx_is_ok_good_addr: __success, __retval("1");
    offset_not_tracked: __success;
    stx_not_ok: __failure, __msg("cannot write into rdonly_untrusted_mem");
    atomic_not_ok: __failure, __msg("cannot write into rdonly_untrusted_mem");
    atomic_rmw_not_ok: __failure, __msg("cannot write into rdonly_untrusted_mem");
    kfunc_param_not_ok: __failure, __msg("R1 type=rdonly_untrusted_mem expected=fp");
    helper_param_not_ok: __failure, __msg("R1 type=rdonly_untrusted_mem expected=");
    mixed_mem_type: __success, __retval("0");
    mixed_mem_untrusted_btf_id_type: __success, __log_level("2"), __msg("r8 = *(u64 *)(r7 +0){{.*}}R7=untrusted_ptr_sock"), __msg("r8 = *(u64 *)(r7 +0){{.*}}R7=ringbuf_mem"), __retval("0");
    mixed_mem_btf_id_type: __success, __log_level("2"), __msg("r8 = *(u32 *)(r7 +0){{.*}}R7=ptr_nameidata"), __msg("r8 = *(u32 *)(r7 +0){{.*}}R7=ringbuf_mem"), __retval("0");
    mixed_rdonly_mem_btf_id_type: __success, __log_level("2"), __msg("r8 = *(u32 *)(r7 +0){{.*}}R7=ptr_nameidata"), __msg("r8 = *(u32 *)(r7 +0){{.*}}R7=rdonly_mem"), __retval("0");
    mixed_mem_mem_type: __success, __log_level("2"), __msg("r8 = *(u64 *)(r7 +0){{.*}}R7=ringbuf_mem"), __msg("r8 = *(u64 *)(r7 +0){{.*}}R7=rdonly_untrusted_mem"), __retval("0");
    mixed_map_value_mem_type: __failure, __msg("same insn cannot be used with different pointers");
    mixed_stack_mem_type: __failure, __msg("same insn cannot be used with different pointers");
    diff_size_access: __retval("0x88442211");
    misaligned_access: __retval("0x99553322");
    null_check: __success, __retval("1");
    ldx_is_ok_commuted_addr: __success, __retval("1");
}

bpf_object!("GPL");
