#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of
// tools/testing/selftests/bpf/progs/tailcall_bpf2bpf_hierarchy3.c
// (bpf-rs-core idiom).
//
// jmp_table0/jmp_table1 statically pre-populate their single prog-array slot
// via a designated initializer on a flexible array member
// (`__array(values, void (void))`, `.values = { [0] = (void *)&classifier_0 }`).
// That asks the map's BTF to call `values` a ZERO-length array -- libbpf's
// parse_btf_map_def rejects anything else -- while its `.maps` storage is one
// pointer wide, because bpf_object__collect_map_relos derives the slot index
// from the RELOCATION offset against that storage. clang gets both by widening
// the LLVM global's codegen type past its debuginfo type; a Rust static's IR
// type and DIType always come from the same declaration.
//
// Declaring `[ClassifierFn; 1]` gets the half rustc can give: the built object's
// .maps section and .rel.maps entries are byte-identical to clang's. The BTF
// half is rewritten by scripts/btf_map_slots.py, which repoints the `values`
// member at an appended zero-length ARRAY. The tail-call chaining below is
// therefore live, and __retval(33) below actually runs it.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_strtoul, bpf_tail_call};
use bpf_rs_core::{bpf_object, maps, test_tags};
use core::ffi::c_void;

#[no_mangle]
static mut count: i32 = 0;

// A fixed-size array-literal copy here gets MemCpyOpt-recognized and
// rewritten to an unresolvable bpf_arena_memcpy kfunc call; a volatile-byte
// loop is the one pattern the optimizer can't merge into a memcpy.
#[inline(always)]
unsafe fn vcopy(dst: *mut u8, src: *const u8, len: usize) {
    let mut i = 0usize;
    while i < len {
        core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
}

// C's clobber_regs_stack(): clobber as many native registers and stack
// slots as possible via a real helper call over a stack buffer.
#[inline(always)]
fn clobber_regs_stack() {
    const SRC: [u8; 10] = *b"123456789\0";
    let mut tmp_str = [0u8; 10];
    unsafe { vcopy(tmp_str.as_mut_ptr(), SRC.as_ptr(), tmp_str.len()) };
    let mut tmp: u64 = 0;
    bpf_strtoul(
        tmp_str.as_ptr() as *const c_void,
        tmp_str.len() as u64,
        0,
        &mut tmp as *mut u64 as *mut c_void,
    );
    unsafe {
        core::arch::asm!("{0} = {0}", inout(reg) tmp, options(nostack, preserves_flags));
    }
}

// A zero-insn `sink_val`-style barrier collapses its .BTF.ext line_info
// onto the next real insn's offset and the kernel rejects the duplicate
// entry ("Invalid line_info[N].insn_off"); self-move (as `helpers::sink`
// does for pointers) emits exactly one real insn instead.
#[inline(always)]
fn barrier_i32(mut v: i32) -> i32 {
    unsafe {
        core::arch::asm!("{0} = {0}", inout(reg) v, options(nostack, preserves_flags));
    }
    v
}

#[inline(never)]
fn subprog_tail<M>(skb: *const __sk_buff, jmp_table: *const M) -> i32 {
    let ret: i32 = 0;
    bpf_tail_call(skb as *const c_void, jmp_table, 0);
    barrier_i32(ret)
}

type ClassifierFn = extern "C" fn(*const __sk_buff) -> i32;

#[repr(C)]
struct jmp_table0 {
    r#type: *const [i32; maps::PROG_ARRAY],
    max_entries: *const [i32; 1],
    key_size: *const [i32; 4],
    values: [ClassifierFn; 1],
}
unsafe impl Sync for jmp_table0 {}

#[link_section = ".maps"]
#[no_mangle]
static jmp_table0: jmp_table0 = jmp_table0 {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [classifier_0],
};

#[repr(C)]
struct jmp_table1 {
    r#type: *const [i32; maps::PROG_ARRAY],
    max_entries: *const [i32; 1],
    key_size: *const [i32; 4],
    values: [ClassifierFn; 1],
}
unsafe impl Sync for jmp_table1 {}

#[link_section = ".maps"]
#[no_mangle]
static jmp_table1: jmp_table1 = jmp_table1 {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key_size: core::ptr::null(),
    values: [classifier_0],
};

test_tags! {
    classifier_0:                 __auxiliary;
    tailcall_bpf2bpf_hierarchy_3: __success, __retval(33);
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_0(skb: *const __sk_buff) -> i32 {
    unsafe { count += 1 };
    subprog_tail(skb, &jmp_table0);
    subprog_tail(skb, &jmp_table1);
    unsafe { count }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tailcall_bpf2bpf_hierarchy_3(skb: *const __sk_buff) -> i32 {
    let ret: i32 = 0;
    clobber_regs_stack();
    bpf_tail_call(skb as *const c_void, &jmp_table0, 0);
    barrier_i32(ret)
}

bpf_object!("GPL");
