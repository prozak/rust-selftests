// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// BTF_C_CHAR: u8

// Direct translation of tools/testing/selftests/bpf/progs/test_snprintf.c
// (bpf-rs-core idiom): bpf_snprintf() with every supported conversion into
// `char` output arrays the userspace test string-compares.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_snprintf};
use core::ffi::c_void;

#[no_mangle]
static mut pid: u32 = 0;

// The C original types these as `char foo[N]`: byte storage is u8 and the
// `// BTF_C_CHAR: u8` marker makes scripts/btf_rename.py call it plain `char`
// in BTF, which the skeleton and the userspace test's ASSERT_STREQ need
// under -Werror=pointer-sign (neither `unsigned char` nor `signed char`
// is pointer-sign-compatible with `char`).
#[no_mangle]
static mut num_out: [u8; 64] = [0; 64];
#[no_mangle]
static mut num_ret: i64 = 0;

#[no_mangle]
static mut ip_out: [u8; 64] = [0; 64];
#[no_mangle]
static mut ip_ret: i64 = 0;

#[no_mangle]
static mut sym_out: [u8; 64] = [0; 64];
#[no_mangle]
static mut sym_ret: i64 = 0;

#[no_mangle]
static mut addr_out: [u8; 64] = [0; 64];
#[no_mangle]
static mut addr_ret: i64 = 0;

#[no_mangle]
static mut str_out: [u8; 64] = [0; 64];
#[no_mangle]
static mut str_ret: i64 = 0;

#[no_mangle]
static mut over_out: [u8; 6] = [0; 6];
#[no_mangle]
static mut over_ret: i64 = 0;

#[no_mangle]
static mut pad_out: [u8; 10] = [0; 10];
#[no_mangle]
static mut pad_ret: i64 = 0;

#[no_mangle]
static mut noarg_out: [u8; 64] = [0; 64];
#[no_mangle]
static mut noarg_ret: i64 = 0;

#[no_mangle]
static mut nobuf_ret: i64 = 0;

// `extern const void schedule __ksym;` in the C original is a DATA ksym
// (address-only use for %ps/%pS/%pB); rustc emits no BTF VAR for extern
// statics so that form can never resolve. Declare it as an extern
// FUNCTION instead: add_ksyms.py tags `declare`d externs with a BTF FUNC
// entry mirrored from vmlinux (kernel/sched/core.c's `schedule`, a real
// FUNC_PROTO void(void) in vmlinux BTF), which libbpf resolves as a
// func-kind ksym via BPF_PSEUDO_BTF_ID even though we only take its
// address here rather than calling it.
extern "C" {
    fn schedule();
}

#[link_section = ".rodata"]
#[no_mangle]
static num_fmt: [u8; 22] = *b"%d %u %x %li %llu %lX\0";
#[link_section = ".rodata"]
#[no_mangle]
static ip_fmt: [u8; 11] = *b"%pi4 %pI6\0\0";
#[link_section = ".rodata"]
#[no_mangle]
static sym_fmt: [u8; 12] = *b"%ps %pS %pB\0";
#[link_section = ".rodata"]
#[no_mangle]
static addr_fmt: [u8; 15] = *b"%pK %px %p\0\0\0\0\0";
#[link_section = ".rodata"]
#[no_mangle]
static str_fmt: [u8; 33] = *b"%s % 9c %+2c %-3c %04c %0c %+05s\0";
#[link_section = ".rodata"]
#[no_mangle]
static over_fmt: [u8; 11] = *b"%%overflow\0";
#[link_section = ".rodata"]
#[no_mangle]
static pad_fmt: [u8; 14] = *b"%5d %0900000X\0";
#[link_section = ".rodata"]
#[no_mangle]
static noarg_fmt: [u8; 12] = *b"simple case\0";
#[link_section = ".rodata"]
#[no_mangle]
static nobuf_fmt: [u8; 29] = *b"only interested in length %d\0";

#[link_section = "raw_tp/sys_enter"]
#[no_mangle]
extern "C" fn handler(_ctx: *const c_void) -> i32 {
    // C's local `char str1[] = "str1"` etc.: a stack array literal gets
    // MemCpyOpt-rewritten into an unresolvable bpf_arena_memcpy kfunc call
    // (bind6_prog.rs), so the fixed bytes live in .rodata statics.
    static EX_IPV4: [u8; 4] = [127, 0, 0, 1];
    static EX_IPV6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    static STR1: [u8; 5] = *b"str1\0";
    static LONGSTR: [u8; 8] = *b"longstr\0";
    let ex_ipv4 = &EX_IPV4;
    let ex_ipv6 = &EX_IPV6;
    let str1 = &STR1;
    let longstr = &LONGSTR;

    if bpf_get_current_pid_tgid() as u32 != unsafe { pid } {
        return 0;
    }

    // Integer types.
    let num_args: [u64; 6] = [
        (-8i32) as i64 as u64,
        9u32 as u64,
        150i32 as u64,
        (-424242i32) as i64 as u64,
        1337u64,
        0xDABBAD00u32 as u64,
    ];
    unsafe {
        num_ret = bpf_snprintf(
            core::ptr::addr_of_mut!(num_out) as *mut c_void,
            core::mem::size_of_val(&num_out) as u32,
            core::ptr::addr_of!(num_fmt) as *const c_void,
            num_args.as_ptr() as *const c_void,
            core::mem::size_of_val(&num_args) as u32,
        );
    }

    // IP addresses.
    let ip_args: [u64; 2] = [ex_ipv4.as_ptr() as u64, ex_ipv6.as_ptr() as u64];
    unsafe {
        ip_ret = bpf_snprintf(
            core::ptr::addr_of_mut!(ip_out) as *mut c_void,
            core::mem::size_of_val(&ip_out) as u32,
            core::ptr::addr_of!(ip_fmt) as *const c_void,
            ip_args.as_ptr() as *const c_void,
            core::mem::size_of_val(&ip_args) as u32,
        );
    }

    // Symbol lookup formatting.
    let sym_args: [u64; 3] = {
        let s = schedule as usize as u64;
        [s, s, s]
    };
    unsafe {
        sym_ret = bpf_snprintf(
            core::ptr::addr_of_mut!(sym_out) as *mut c_void,
            core::mem::size_of_val(&sym_out) as u32,
            core::ptr::addr_of!(sym_fmt) as *const c_void,
            sym_args.as_ptr() as *const c_void,
            core::mem::size_of_val(&sym_args) as u32,
        );
    }

    // Kernel pointers.
    let addr_args: [u64; 3] = [0u64, 0xFFFF00000ADD4E55u64, 0xFFFF00000ADD4E55u64];
    unsafe {
        addr_ret = bpf_snprintf(
            core::ptr::addr_of_mut!(addr_out) as *mut c_void,
            core::mem::size_of_val(&addr_out) as u32,
            core::ptr::addr_of!(addr_fmt) as *const c_void,
            addr_args.as_ptr() as *const c_void,
            core::mem::size_of_val(&addr_args) as u32,
        );
    }

    // Strings and single-byte character embedding.
    let str_args: [u64; 7] = [
        str1.as_ptr() as u64,
        b'a' as u64,
        b'b' as u64,
        b'c' as u64,
        b'd' as u64,
        b'e' as u64,
        longstr.as_ptr() as u64,
    ];
    unsafe {
        str_ret = bpf_snprintf(
            core::ptr::addr_of_mut!(str_out) as *mut c_void,
            core::mem::size_of_val(&str_out) as u32,
            core::ptr::addr_of!(str_fmt) as *const c_void,
            str_args.as_ptr() as *const c_void,
            core::mem::size_of_val(&str_args) as u32,
        );
    }

    // Overflow.
    unsafe {
        over_ret = bpf_snprintf(
            core::ptr::addr_of_mut!(over_out) as *mut c_void,
            core::mem::size_of_val(&over_out) as u32,
            core::ptr::addr_of!(over_fmt) as *const c_void,
            core::ptr::null(),
            0,
        );
    }

    // Padding of fixed width numbers.
    let pad_args: [u64; 2] = [4u64, 4u64];
    unsafe {
        pad_ret = bpf_snprintf(
            core::ptr::addr_of_mut!(pad_out) as *mut c_void,
            core::mem::size_of_val(&pad_out) as u32,
            core::ptr::addr_of!(pad_fmt) as *const c_void,
            pad_args.as_ptr() as *const c_void,
            core::mem::size_of_val(&pad_args) as u32,
        );
    }

    // No args.
    unsafe {
        noarg_ret = bpf_snprintf(
            core::ptr::addr_of_mut!(noarg_out) as *mut c_void,
            core::mem::size_of_val(&noarg_out) as u32,
            core::ptr::addr_of!(noarg_fmt) as *const c_void,
            core::ptr::null(),
            0,
        );
    }

    // No buffer.
    let nobuf_args: [u64; 1] = [60u64];
    unsafe {
        nobuf_ret = bpf_snprintf(
            core::ptr::null_mut(),
            0,
            core::ptr::addr_of!(nobuf_fmt) as *const c_void,
            nobuf_args.as_ptr() as *const c_void,
            core::mem::size_of_val(&nobuf_args) as u32,
        );
    }

    0
}

bpf_object!("GPL");
