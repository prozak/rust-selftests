#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Direct translation of
// tools/testing/selftests/bpf/progs/tailcall_bpf2bpf_hierarchy1.c,
// bpf-rs-core idiom.
//
// jmp_table has explicit key_size/value_size (not key/value types), so it
// needs the bpf_map! escape hatch, same idiom as tailcall3.rs/tailcall4.rs.
// bpf_tail_call_static's constant-slot asm is a JIT-poke optimization, not
// behavioral; the regular bpf_tail_call thunk with a literal index is
// functionally equivalent for this test (see tailcall3.rs).

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_strtoul, bpf_tail_call, sink_val};
use bpf_rs_core::{bpf_map, bpf_object, maps};

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

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
fn subprog_tail(skb: *const __sk_buff) -> i32 {
    let mut ret: i32 = 0;

    bpf_tail_call(skb as *const core::ffi::c_void, &jmp_table, 0);
    unsafe {
        core::arch::asm!("{0} = {0}", inout(reg) ret, options(nostack, preserves_flags));
    }
    ret
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn entry(skb: *const __sk_buff) -> i32 {
    let ret: i32 = 1;

    clobber_regs_stack();

    unsafe { count += 1 };
    let ret1 = subprog_tail(skb);
    let ret2 = subprog_tail(skb);
    sink_val(ret1);
    sink_val(ret2);

    ret
}

bpf_object!("GPL");
