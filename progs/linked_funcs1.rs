// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]
#![feature(linkage)]
#![feature(asm_experimental_arch)]
#![allow(non_upper_case_globals)]

// Direct translation of tools/testing/selftests/bpf/progs/linked_funcs1.c
// (bpf-rs-core idiom). Half of linked_funcs.skel.h (Makefile.skel:
// `linked_funcs.skel.h-deps := linked_funcs1.bpf.o linked_funcs2.bpf.o`):
// prog_tests/linked_funcs.c sets my_tid/syscall_id, enables both halves'
// `?raw_tp` handlers, attaches them and triggers one getpgid syscall; each
// handler calls the OTHER half's global functions (set_output_val2 and
// set_output_ctx2 from here) and the weak set_output_weak, whose
// definition from this half wins. Expected: output_val1 = 4000,
// output_ctx1 = SYS_getpgid, output_weak1 = 42, output_weak2 = 0.
//
// Cross-object pieces: `// BTF_EXTERN:` externs (scripts/ksym_vars.py
// mirrors the C object's extern FUNC prototypes for the static linker),
// the `.hidden` directive on set_output_ctx2 (the C's `__hidden extern`:
// libbpf marks the linked function static, as it reads the raw_tp ctx),
// `#[linkage = "weak"]` for the weak my_tid/syscall_id globals and the weak
// set_output_weak (connect4_prog.rs); the static subprog both halves define
// with different formulas is folded into its caller by clang, and by rustc.
// bpf_cast_to_kern_ctx is the kfunc both halves declare (the C's
// declaration is weak: `// BTF_WEAK_KFUNC:`); kfunc_gen1 only exists to put
// its FUNC in BTF for the linker's duplicate-extern test, like the C.
//
// The C stores `bpf_core_type_size(struct task_struct)` into the
// function-local `static volatile int whatever` of set_output_weak and
// handler1 to make sure CO-RE relocations in a weak function and in the
// main program survive the static linker. That is a TYPE_SIZE relocation
// this pipeline cannot emit (test_core_reloc_type_based.rs), and nothing
// reads the value back: TASK_STRUCT_SIZE is the pinned kernel's
// `struct task_struct` size from its BTF (6272, what libbpf patches the C's
// `r1 = 0x1880` to), the one constant here that does not adapt to the
// target. The statics keep the C's symbol names; `__sink` is a
// `asm volatile("" : "+r"(x))`: a read_volatile through black_box written
// back (lesson 39). The C names its license global
// `LICENSE` (bpftool_ringbuf.rs).
// BTF_WEAK_KFUNC: bpf_cast_to_kern_ctx

use core::ffi::c_void;
use core::hint::black_box;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;

/// `bpf_core_type_size(struct task_struct)` against the pinned kernel's BTF.
const TASK_STRUCT_SIZE: i32 = 6272;

/* weak and shared between two files */
#[linkage = "weak"]
#[link_section = ".rodata"]
#[no_mangle]
static my_tid: u32 = 0;
#[linkage = "weak"]
#[no_mangle]
static mut syscall_id: i64 = 0;

#[no_mangle]
static mut output_val1: i32 = 0;
#[no_mangle]
static mut output_ctx1: i32 = 0;
#[no_mangle]
static mut output_weak1: i32 = 0;

/* same "subprog" name in all files, but it's ok because they all are static */
// clang folds the C's `static __noinline` subprog into its only caller (the
// C object has no subprog symbol): left inlineable here for the same shape.
fn subprog(x: i32) -> i32 {
    /* but different formula */
    x.wrapping_mul(1)
}

/* Global functions can't be void */
#[no_mangle]
pub extern "C" fn set_output_val1(x: i32) -> i32 {
    unsafe { output_val1 = x.wrapping_add(subprog(x)) };
    x
}

/* This function can't be verified as global, as it assumes raw_tp/sys_enter
 * context and accesses syscall id (second argument). So we mark it as
 * __hidden, so that libbpf will mark it as static in the final object file,
 * right before verifying it in the kernel.
 *
 * But we don't mark it as __hidden here, rather at extern site. __hidden is
 * "contaminating" visibility, so it will get propagated from either extern or
 * actual definition (including from the losing __weak definition).
 */
#[no_mangle]
pub extern "C" fn set_output_ctx1(ctx: *mut u64) {
    unsafe { output_ctx1 = *ctx.add(1) as i32 }; /* long id, same as in BPF_PROG below */
}

// C: `static volatile int whatever;` inside set_output_weak
#[export_name = "set_output_weak.whatever"]
static mut set_output_weak_whatever: i32 = 0;

/* this weak instance should win because it's the first one */
#[inline(never)]
#[linkage = "weak"]
#[no_mangle]
pub extern "C" fn set_output_weak(x: i32) -> i32 {
    unsafe {
        /* make sure we use CO-RE relocations in a weak function, this used to
         * cause problems for BPF static linker
         */
        write_volatile(addr_of_mut!(set_output_weak_whatever), TASK_STRUCT_SIZE);
        write_volatile(
            addr_of_mut!(set_output_weak_whatever),
            black_box(read_volatile(addr_of!(set_output_weak_whatever))),
        );

        output_weak1 = x;
    }
    x
}

// BTF_EXTERN: set_output_val2
// BTF_EXTERN: set_output_ctx2
extern "C" {
    fn set_output_val2(x: i32) -> i32;
    /* here we'll force set_output_ctx2() to be __hidden in the final obj file */
    fn set_output_ctx2(ctx: *mut u64);

    fn bpf_cast_to_kern_ctx(obj: *mut c_void) -> *mut c_void;
}
core::arch::global_asm!(".hidden set_output_ctx2");

// C: `static volatile int whatever;` inside BPF_PROG(handler1)
#[export_name = "____handler1.whatever"]
static mut handler1_whatever: i32 = 0;

#[link_section = "?raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler1(ctx: *mut u64) -> i32 {
    unsafe {
        let id = *ctx.add(1) as i64;

        if read_volatile(addr_of!(my_tid)) != bpf_get_current_pid_tgid() as u32 || id != syscall_id {
            return 0;
        }

        /* make sure we have CO-RE relocations in main program */
        write_volatile(addr_of_mut!(handler1_whatever), TASK_STRUCT_SIZE);
        write_volatile(addr_of_mut!(handler1_whatever), black_box(read_volatile(addr_of!(handler1_whatever))));

        set_output_val2(1000);
        set_output_ctx2(ctx); /* ctx definition is hidden in BPF_PROG macro */

        /* keep input value the same across both files to avoid dependency on
         * handler call order; differentiate by output_weak1 vs output_weak2.
         */
        set_output_weak(42);
    }

    0
}

/* Generate BTF FUNC record and test linking with duplicate extern functions */
#[no_mangle]
pub extern "C" fn kfunc_gen1() {
    unsafe { bpf_cast_to_kern_ctx(core::ptr::null_mut()) };
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = bpf_rs_core::__lic_bytes::<4>("GPL");

bpf_object!("GPL");
