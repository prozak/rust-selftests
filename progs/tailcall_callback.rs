#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

use bpf_rs_core::{ctx::__sk_buff, helpers::{bpf_strtoul, bpf_tail_call, bpf_loop, sink_val}};
use core::ffi::c_void;

type ClassifierFn = extern "C" fn(*const __sk_buff) -> i32;
#[repr(C)]
struct JumpTable {
    r#type: *const [i32; 3], max_entries: *const [i32; 1],
    key_size: *const [i32; 4], values: [ClassifierFn; 1],
}
unsafe impl Sync for JumpTable {}
#[no_mangle]
#[link_section = ".maps"]
static jmp_table: JumpTable = JumpTable {
    r#type: core::ptr::null(), max_entries: core::ptr::null(),
    key_size: core::ptr::null(), values: [classifier_0],
};
#[no_mangle]
#[link_section = "tc"]
extern "C" fn classifier_0(_skb: *const __sk_buff) -> i32 { 0 }

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
extern "C" fn callback_loop(_index: u64, cb_ctx: *mut *const __sk_buff) -> i64 {
    let mut ret = subprog_tail0(unsafe { *cb_ctx });
    unsafe { core::arch::asm!("{0} = {0}", inout(reg) ret); }
    (ret != 0) as i64
}
#[inline(never)]
extern "C" fn callback_empty(_index: u64, _data: *mut c_void) -> i64 { 0 }

#[no_mangle]
#[link_section = "tc"]
extern "C" fn tailcall_callback_1(mut skb: *const __sk_buff) -> i32 {
    clobber_regs_stack();
    bpf_loop(1, callback_loop, &mut skb, 0);
    0
}
#[no_mangle]
#[link_section = "tc"]
extern "C" fn tailcall_callback_2(skb: *const __sk_buff) -> i32 {
    clobber_regs_stack();
    let ret = subprog_tail0(skb);
    sink_val(ret);
    bpf_loop(1, callback_empty, core::ptr::null_mut(), 0);
    0
}

bpf_rs_core::test_tags! {
    classifier_0: __auxiliary;
    tailcall_callback_1: __failure, __msg("cannot tail call within callback");
    tailcall_callback_2: __success, __retval(0);
}
#[no_mangle]
#[link_section = "license"]
static __license: [u8; 4] = *b"GPL\0";
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
