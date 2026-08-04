#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of
// tools/testing/selftests/bpf/progs/tailcall_bpf2bpf_hierarchy2.c,
// bpf-rs-core idiom.
//
// jmp_table has explicit key_size/value_size (not key/value types), so it
// needs the bpf_map! escape hatch, same idiom as tailcall3.rs/tailcall4.rs.
// bpf_tail_call_static's constant-slot asm is a JIT-poke optimization, not
// behavioral; the regular bpf_tail_call thunk with a literal index is
// functionally equivalent for this test (see tailcall3.rs).
//
// C's `.values = {[0] = &classifier_0, [1] = &classifier_1}` static
// prog-array initializer is unfixable here (see
// [[prog-array-static-values-init-unfixable]]): rustc can't diverge a
// static's codegen type from its debug type the way Clang's flexible-array
// trick does, so the map is declared with plain key_size/value_size and an
// empty runtime-populated slot layout, same as tailcall_bpf2bpf_hierarchy1.
// This is consumed via test_loader.c's RUN_TESTS/__success/__retval
// mechanism, but rustc emits no BTF_KIND_DECL_TAG at all, so every SEC("tc")
// function here (classifier_0, classifier_1, and the main entry) becomes an
// untagged, non-auxiliary, non-executing subtest that only needs to load
// successfully (see [[negative-verifier-tests-need-loadable-translation]]) —
// the unpopulated tail-call slot doesn't affect verification.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_strtoul, bpf_tail_call, sink_val};
use bpf_rs_core::{bpf_map, bpf_object, maps};

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 2],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[no_mangle]
static mut count0: i32 = 0;
#[no_mangle]
static mut count1: i32 = 0;

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
        tmp_str.as_ptr() as *const core::ffi::c_void,
        tmp_str.len() as u64,
        0,
        &mut tmp as *mut u64 as *mut core::ffi::c_void,
    );
    // Self-move (not a comment-only asm): a zero-real-insn barrier can
    // duplicate a .BTF.ext line_info insn_off and get rejected at load
    // (see [[empty-inline-asm-breaks-btf-ext-line-info]]).
    unsafe {
        core::arch::asm!("{0} = {0}", inout(reg) tmp, options(nostack, preserves_flags));
    }
}

#[inline(never)]
fn subprog_tail0(skb: *const __sk_buff) -> i32 {
    let mut ret: i32 = 0;

    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 0);
    unsafe {
        core::arch::asm!("{0} = {0}", inout(reg) ret, options(nostack, preserves_flags));
    }
    ret
}

#[inline(never)]
fn subprog_tail1(skb: *const __sk_buff) -> i32 {
    let mut ret: i32 = 0;

    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 1);
    unsafe {
        core::arch::asm!("{0} = {0}", inout(reg) ret, options(nostack, preserves_flags));
    }
    ret
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_0(skb: *const __sk_buff) -> i32 {
    unsafe { count0 += 1 };
    subprog_tail0(skb);
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn classifier_1(skb: *const __sk_buff) -> i32 {
    unsafe { count1 += 1 };
    let ret = subprog_tail1(skb);
    sink_val(ret);
    0
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn tailcall_bpf2bpf_hierarchy_2(skb: *const __sk_buff) -> i32 {
    clobber_regs_stack();

    let ret1 = subprog_tail0(skb);
    let ret2 = subprog_tail1(skb);
    sink_val(ret1);
    sink_val(ret2);

    unsafe { (count1 << 16) | count0 }
}

bpf_object!("GPL");
