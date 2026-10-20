// SPDX-License-Identifier: GPL-2.0-only
#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

// Translation of tools/testing/selftests/bpf/progs/test_global_func15.c,
// bpf-rs-core idiom.
//
// Two NEGATIVE verifier tests on a cgroup_skb/ingress program's return
// range [0, 1]: global_func15 returns a value a global subprogram may have
// set to anything (bpf_get_prandom_u32), and global_func15_tricky_pruning
// is the C's `__naked` program, carried as a `// BPF_NAKED:` body that
// matches the C object instruction by instruction (its log-level-2
// mark_precise messages name instruction indices). Like the other
// test_global_func*.c files the C object has no license section.

use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::bpf_get_prandom_u32;
use bpf_rs_core::test_tags;

test_tags! {
    global_func15: __failure, __msg("At program exit the register R0 has ");
    global_func15_tricky_pruning: __log_level(2), __flag(BPF_F_TEST_STATE_FREQ), __failure, __msg("mark_precise: frame0: regs=r0 stack= before 2: (b7) r0 = 1"), __msg("mark_precise: frame0: regs=r0 stack= before 0: (85) call bpf_get_prandom_u32#7"), __msg("At program exit the register R0 has ");
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn foo(v: *mut u32) -> i32 {
    if !v.is_null() {
        unsafe { *v = bpf_get_prandom_u32() };
    }

    0
}

#[link_section = "cgroup_skb/ingress"]
#[no_mangle]
pub extern "C" fn global_func15(_skb: *const __sk_buff) -> i32 {
    let mut v: u32 = 1;

    foo(&mut v);

    v as i32
}

/* check that fallthrough code path marks r0 as precise;
 * check that branch code path marks r0 as precise */
#[no_mangle]
#[inline(never)]
#[link_section = "cgroup_skb/ingress"]
// BPF_NAKED: global_func15_tricky_pruning
extern "C" fn global_func15_tricky_pruning() -> i32 {
    unsafe { core::arch::asm!("call 7;if r0 s> 1000 goto +1;r0 = 1;goto +0;exit;", options(noreturn)); }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
