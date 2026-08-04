#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_iter_ksym.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_seq_printf;
use btf_macros::btf;
use core::ffi::c_void;

const KSYM_NAME_LEN: usize = 512;
const MODULE_NAME_LEN: usize = 56;

#[repr(C)]
struct bpf_iter_meta {
    seq: *mut c_void,
    session_id: u64,
    seq_num: u64,
}

#[repr(C)]
struct bpf_iter__ksym {
    meta: *mut bpf_iter_meta,
    ksym: *mut kallsym_iter,
}

#[btf]
struct kallsym_iter {
    pos: i64,
    pos_mod_end: i64,
    pos_ftrace_mod_end: i64,
    pos_bpf_end: i64,
    value: u64,
    r#type: u8,
    name: [u8; KSYM_NAME_LEN],
    module_name: [u8; MODULE_NAME_LEN],
    exported: i32,
    show_value: i32,
}

#[no_mangle]
static mut last_sym_value: usize = 0;

fn to_lower(c: u8) -> u8 {
    if c >= b'A' && c <= b'Z' {
        c + (b'a' - b'A')
    } else {
        c
    }
}

fn to_upper(c: u8) -> u8 {
    if c >= b'a' && c <= b'z' {
        c - (b'a' - b'A')
    } else {
        c
    }
}

#[link_section = "iter/ksym"]
#[no_mangle]
extern "C" fn dump_ksym(ctx: *const bpf_iter__ksym) -> i32 {
    let ctx = unsafe { &*ctx };
    let iter = ctx.ksym;
    if iter.is_null() {
        return 0;
    }
    let meta = unsafe { &*ctx.meta };
    let seq = meta.seq;
    let iter_ref = unsafe { &*iter };

    if meta.seq_num == 0 {
        static FMT0: [u8; 42] = *b"ADDR TYPE NAME MODULE_NAME KIND MAX_SIZE\n\0";
        bpf_seq_printf(
            seq,
            FMT0.as_ptr() as *const c_void,
            FMT0.len() as u32,
            core::ptr::null(),
            0,
        );
        return 0;
    }

    let iter_value = unsafe { *iter_ref.value().as_ptr() };

    if unsafe { last_sym_value } != 0 {
        static FMT1: [u8; 6] = *b"0x%x\n\0";
        let diff = iter_value.wrapping_sub(unsafe { last_sym_value } as u64);
        let params: [u64; 1] = [diff];
        bpf_seq_printf(
            seq,
            FMT1.as_ptr() as *const c_void,
            FMT1.len() as u32,
            params.as_ptr() as *const c_void,
            core::mem::size_of_val(&params) as u32,
        );
    } else {
        static FMT2: [u8; 2] = *b"\n\0";
        bpf_seq_printf(
            seq,
            FMT2.as_ptr() as *const c_void,
            FMT2.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    let show_value = unsafe { *iter_ref.show_value().as_ptr() };
    let value: u64 = if show_value != 0 { iter_value } else { 0 };

    unsafe { last_sym_value = value as usize };

    let mut ty = unsafe { *iter_ref.r#type().as_ptr() };

    let module_name_ptr = iter_ref.module_name().as_ptr() as *const u8;
    let module_first = unsafe { *module_name_ptr };
    let name_ptr = iter_ref.name().as_ptr() as *const u8;

    if module_first != 0 {
        let exported = unsafe { *iter_ref.exported().as_ptr() };
        ty = if exported != 0 { to_upper(ty) } else { to_lower(ty) };

        static FMT3: [u8; 21] = *b"0x%llx %c %s [ %s ] \0";
        let params: [u64; 4] = [value, ty as u64, name_ptr as u64, module_name_ptr as u64];
        bpf_seq_printf(
            seq,
            FMT3.as_ptr() as *const c_void,
            FMT3.len() as u32,
            params.as_ptr() as *const c_void,
            core::mem::size_of_val(&params) as u32,
        );
    } else {
        static FMT4: [u8; 14] = *b"0x%llx %c %s \0";
        let params: [u64; 3] = [value, ty as u64, name_ptr as u64];
        bpf_seq_printf(
            seq,
            FMT4.as_ptr() as *const c_void,
            FMT4.len() as u32,
            params.as_ptr() as *const c_void,
            core::mem::size_of_val(&params) as u32,
        );
    }

    let pos = unsafe { *iter_ref.pos().as_ptr() };
    let pos_mod_end = unsafe { *iter_ref.pos_mod_end().as_ptr() };
    let pos_ftrace_mod_end = unsafe { *iter_ref.pos_ftrace_mod_end().as_ptr() };
    let pos_bpf_end = unsafe { *iter_ref.pos_bpf_end().as_ptr() };

    if pos_mod_end == 0 || pos_mod_end > pos {
        static FMT5: [u8; 5] = *b"MOD \0";
        bpf_seq_printf(
            seq,
            FMT5.as_ptr() as *const c_void,
            FMT5.len() as u32,
            core::ptr::null(),
            0,
        );
    } else if pos_ftrace_mod_end == 0 || pos_ftrace_mod_end > pos {
        static FMT6: [u8; 12] = *b"FTRACE_MOD \0";
        bpf_seq_printf(
            seq,
            FMT6.as_ptr() as *const c_void,
            FMT6.len() as u32,
            core::ptr::null(),
            0,
        );
    } else if pos_bpf_end == 0 || pos_bpf_end > pos {
        static FMT7: [u8; 5] = *b"BPF \0";
        bpf_seq_printf(
            seq,
            FMT7.as_ptr() as *const c_void,
            FMT7.len() as u32,
            core::ptr::null(),
            0,
        );
    } else {
        static FMT8: [u8; 8] = *b"KPROBE \0";
        bpf_seq_printf(
            seq,
            FMT8.as_ptr() as *const c_void,
            FMT8.len() as u32,
            core::ptr::null(),
            0,
        );
    }

    0
}

bpf_object!("GPL");
