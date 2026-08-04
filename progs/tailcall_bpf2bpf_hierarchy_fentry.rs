#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/tailcall_bpf2bpf_hierarchy_fentry.c
// (bpf-rs-core idiom).
//
// `fentry` is attached (attach target overridden by userspace via
// bpf_program__set_attach_target, replacing the placeholder SEC("fentry/
// dummy")) to another program's "entry" function; jmp_table[0] is filled in
// by userspace with this program's own prog fd, so subprog_tail's tail call
// re-enters `fentry` itself, recursing until the kernel's tail-call-count
// limit is hit.
//
// jmp_table has explicit key_size/value_size (not key/value types), so it
// needs the bpf_map! escape hatch (same pattern as tailcall_bpf2bpf2.rs).
//
// clobber_regs_stack() (from bpf_test_utils.h) is translated inline: it
// exists purely to add register/stack pressure ahead of the tail calls, its
// result is discarded via __sink either way.

use bpf_rs_core::helpers::{barrier_var, bpf_strtoul, bpf_tail_call, sink_val};
use bpf_rs_core::{bpf_map, bpf_object, maps};
use core::ffi::c_void;

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

#[inline(never)]
fn clobber_regs_stack() {
    // Byte-by-byte volatile copy, not an array-literal copy-assign: LLVM's
    // MemCpyOpt can rewrite a plain array-to-array copy into an
    // unresolvable bpf_arena_memcpy kfunc call (see copy-nonoverlapping-
    // becomes-arena-memcpy-kfunc). Volatile reads/writes are never merged
    // into a memcpy.
    let src: &[u8; 10] = b"123456789\0";
    let mut tmp_str: [u8; 10] = [0; 10];
    let src_ptr = src.as_ptr();
    let dst_ptr = tmp_str.as_mut_ptr();
    for i in 0..10usize {
        unsafe {
            let b = core::ptr::read_volatile(src_ptr.add(i));
            core::ptr::write_volatile(dst_ptr.add(i), b);
        }
    }
    let mut tmp: u64 = 0;
    unsafe {
        bpf_strtoul(
            tmp_str.as_ptr() as *const c_void,
            tmp_str.len() as u64,
            0,
            &mut tmp as *mut u64 as *mut c_void,
        );
    }
    sink_val(tmp as i32);
}

#[inline(never)]
extern "C" fn subprog_tail(ctx: *const c_void) -> i32 {
    let mut ret: usize = 0;
    bpf_tail_call(ctx, &jmp_table, 0);
    barrier_var(&mut ret);
    ret as i32
}

#[link_section = "fentry/dummy"]
#[no_mangle]
extern "C" fn fentry(ctx: *const u64) -> i32 {
    clobber_regs_stack();

    unsafe {
        count += 1;
    }
    let ret1 = subprog_tail(ctx as *const c_void);
    let ret2 = subprog_tail(ctx as *const c_void);
    sink_val(ret1);
    sink_val(ret2);

    0
}

bpf_object!("GPL");
