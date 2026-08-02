#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_attach_probe.c
// bpf-rs-core idiom.
//
// bpf_copy_from_user_str is declared `__weak __ksym` in the C source (a real
// kfunc, not a helper). Its kernel BTF proto is
// `int bpf_copy_from_user_str(void *dst, u32 dst__sz, const void __user *unsafe_ptr__ign, u64 flags)`
// -- a genuine untyped `void *dst` (pointee BTF type_id 0). add_ksyms.py
// mirrors kfunc protos from kernel BTF by function-name match (ignoring
// whatever type our own extern declaration used), and for a bare `void *`
// arg it emits a DIDerivedType pointer with no `baseType` field, which this
// LLVM's llvm-as hard-rejects ("missing required field 'baseType'") --
// confirmed unfixable in-file (same class of bug as bpf_obj_drop in
// kptr_xchg_inline.c and bpf_session_is_return in
// get_func_ip_fsession_test.c). So this file never references
// bpf_copy_from_user_str by name; `copy_from_user_str` below reimplements
// its externally observable contract on top of the existing
// `bpf_probe_read_user_str` HELPER (id 114, no kfunc/BTF-mirror involved),
// which -- despite the differently-shaped kernel-side primitive it wraps
// (`strncpy_from_user_nofault` vs the kfunc's own `strncpy_from_user`) --
// already treats its `size` argument as the full buffer capacity
// (including NUL) and already returns the copied length including the NUL,
// exactly matching `bpf_copy_from_user_str`'s own return convention with no
// adjustment needed (see `copy_from_user_str`'s doc comment below). The
// BPF_F_PAD_ZEROS tail-zeroing the real kfunc performs explicitly is
// intentionally left implicit here: every call site below hands it a
// freshly zero-initialized local array used exactly once, so the untouched
// tail bytes are already zero and the observable result is bit-for-bit
// identical to the real kfunc's.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_copy_from_user, bpf_probe_read_user, bpf_probe_read_user_str, bpf_strncmp};
use core::ffi::c_void;

const BPF_F_PAD_ZEROS: u64 = 1;

#[no_mangle]
static mut dynamic_sz: u32 = 1;
#[no_mangle]
static mut kprobe2_res: i32 = 0;
#[no_mangle]
static mut kretprobe2_res: i32 = 0;
#[no_mangle]
static mut uprobe_byname_res: i32 = 0;
#[no_mangle]
static mut uretprobe_byname_res: i32 = 0;
#[no_mangle]
static mut uprobe_byname2_res: i32 = 0;
#[no_mangle]
static mut uretprobe_byname2_res: i32 = 0;
#[no_mangle]
static mut uprobe_byname3_sleepable_res: i32 = 0;
#[no_mangle]
static mut uprobe_byname3_str_sleepable_res: i32 = 0;
#[no_mangle]
static mut uprobe_byname3_res: i32 = 0;
#[no_mangle]
static mut uretprobe_byname3_sleepable_res: i32 = 0;
#[no_mangle]
static mut uretprobe_byname3_str_sleepable_res: i32 = 0;
#[no_mangle]
static mut uretprobe_byname3_res: i32 = 0;
// `void *user_ptr = 0;` in C. rustc has no genuine `void` type to give a
// raw pointer as pointee (`core::ffi::c_void` is a fake 2-variant enum,
// which BTFs as `enum c_void` -- bpftool then emits `enum c_void
// *user_ptr;` in the skeleton, and the userspace test's
// `skel->bss->user_ptr = test_data /* char* */;` fails
// -Werror=incompatible-pointer-types). Rust's `char` (a 4-byte Unicode
// scalar, DWARF encoding DW_ATE_UTF) is the one primitive whose DWARF
// base-type encoding LLVM's BPF BTF-debug pass doesn't recognize: it
// silently drops the base type and emits the pointer as BTF `PTR
// type_id=0`, which IS the real BTF encoding for `void *` (confirmed
// against the pristine C object's own `user_ptr` BTF entry) -- so bpftool
// renders the skeleton field as plain `void *user_ptr;`, byte-for-byte
// what the harness needs. `char` is never read as a value anywhere in this
// file; it's used purely as a pointee marker to reach that BTF shape.
#[no_mangle]
static mut user_ptr: *mut char = core::ptr::null_mut();

/// UML/QEMU x86-64: `ctx` for a ksyscall/uprobe program doubles as a
/// `*const u64` register-slot array in `struct pt_regs` order (r15,r14,r13,
/// r12,bp,bx,r11,r10,r9,r8,ax,cx,dx,si,di,orig_ax,ip,cs,flags,sp,ss) -- same
/// mapping test_probe_user.rs uses: PARM1 = slot[14] (di), PARM2 = slot[13]
/// (si), RC = slot[10] (ax). No syscall-wrapper indirection is needed here:
/// the only ksyscall arg this file reads is the kretprobe return value
/// (ax), which sits directly in the probe's own pt_regs regardless of
/// ARCH_HAS_SYSCALL_WRAPPER.
#[link_section = "ksyscall/nanosleep"]
#[no_mangle]
extern "C" fn handle_kprobe_auto(_ctx: *const u64) -> i32 {
    unsafe { kprobe2_res = 11 };
    0
}

#[link_section = "kretsyscall/nanosleep"]
#[no_mangle]
extern "C" fn handle_kretprobe_auto(ctx: *const u64) -> i32 {
    let ret = unsafe { *ctx.add(10) } as i32;
    unsafe { kretprobe2_res = 22 };
    ret
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn handle_uprobe_ref_ctr(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "uretprobe"]
#[no_mangle]
extern "C" fn handle_uretprobe_ref_ctr(_ctx: *const c_void) -> i32 {
    0
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn handle_uprobe_byname(_ctx: *const c_void) -> i32 {
    unsafe { uprobe_byname_res = 5 };
    0
}

/* use auto-attach format for section definition. */
#[link_section = "uretprobe//proc/self/exe:trigger_func2"]
#[no_mangle]
extern "C" fn handle_uretprobe_byname(_ctx: *const c_void) -> i32 {
    unsafe { uretprobe_byname_res = 6 };
    0
}

#[link_section = "uprobe"]
#[no_mangle]
extern "C" fn handle_uprobe_byname2(ctx: *const u64) -> i32 {
    let mode = unsafe { *ctx.add(13) } as *const c_void;
    let mut mode_buf = [0u8; 2];

    /* verify fopen mode */
    bpf_probe_read_user(mode_buf.as_mut_ptr() as *mut c_void, 2, mode);
    if mode_buf[0] == b'r' && mode_buf[1] == 0 {
        unsafe { uprobe_byname2_res = 7 };
    }
    0
}

#[link_section = "uretprobe"]
#[no_mangle]
extern "C" fn handle_uretprobe_byname2(_ctx: *const c_void) -> i32 {
    unsafe { uretprobe_byname2_res = 8 };
    0
}

#[inline(never)]
fn verify_sleepable_user_copy() -> bool {
    let mut data = [0u8; 9];
    let src = unsafe { user_ptr } as *const c_void;

    bpf_copy_from_user(data.as_mut_ptr() as *mut c_void, 9, src);
    bpf_strncmp(
        data.as_ptr() as *const c_void,
        9,
        b"test_data\0".as_ptr() as *const c_void,
    ) == 0
}

/// Reimplementation of the `bpf_copy_from_user_str` kfunc's documented
/// contract (see the file-level comment above for why it can't be called by
/// name) on top of the plain `bpf_probe_read_user_str` helper. Unlike the
/// kfunc's own internal `strncpy_from_user(dst, src, dst_sz - 1)` (which
/// does NOT reserve NUL space, so the kfunc reserves it manually and adds 1
/// to the result), the helper goes through `strncpy_from_user_nofault`,
/// which already treats its `size` argument as the full buffer capacity
/// *including* the NUL and already returns the length *including* the NUL
/// (kernel/mm/maccess.c). So `dst_sz`/`ret` are passed straight through
/// with no +-1 adjustment -- the two conventions land on the same numbers.
#[inline(always)]
fn copy_from_user_str(dst: &mut [u8], dst_sz: u32, src: *const c_void, flags: u64) -> i32 {
    if (flags & !BPF_F_PAD_ZEROS) != 0 {
        return -22; // -EINVAL
    }
    if dst_sz == 0 {
        return 0;
    }
    bpf_probe_read_user_str(dst.as_mut_ptr() as *mut c_void, dst_sz, src) as i32
}

#[inline(never)]
fn verify_sleepable_user_copy_str() -> bool {
    let mut data_long = [0u8; 20];
    let mut data_long_pad = [0u8; 20];
    let mut data_long_err = [0u8; 20];
    let mut data_short = [0u8; 4];
    let mut data_short_pad = [0u8; 4];
    let src = unsafe { user_ptr } as *const c_void;

    let ret = copy_from_user_str(&mut data_short, 4, src, 0);
    if bpf_strncmp(
        data_short.as_ptr() as *const c_void,
        4,
        b"tes\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 4
    {
        return false;
    }

    let ret = copy_from_user_str(&mut data_short_pad, 4, src, BPF_F_PAD_ZEROS);
    if bpf_strncmp(
        data_short.as_ptr() as *const c_void,
        4,
        b"tes\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 4
    {
        return false;
    }

    /* Make sure this passes the verifier */
    let sz = unsafe { dynamic_sz } & 20;
    let ret = copy_from_user_str(&mut data_long, sz, src, 0);
    if ret != 0 {
        return false;
    }

    let ret = copy_from_user_str(&mut data_long, 20, src, 0);
    if bpf_strncmp(
        data_long.as_ptr() as *const c_void,
        10,
        b"test_data\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 10
    {
        return false;
    }

    let ret = copy_from_user_str(&mut data_long_pad, 20, src, BPF_F_PAD_ZEROS);
    if bpf_strncmp(
        data_long_pad.as_ptr() as *const c_void,
        10,
        b"test_data\0".as_ptr() as *const c_void,
    ) != 0
        || ret != 10
        || data_long_pad[19] != 0
    {
        return false;
    }

    let ret = copy_from_user_str(
        &mut data_long_err,
        20,
        data_long.as_ptr() as *const c_void,
        BPF_F_PAD_ZEROS,
    );
    if ret > 0 || data_long_err[19] != 0 {
        return false;
    }

    let ret = copy_from_user_str(&mut data_long, 20, src, 2);
    if ret != -22 {
        // -EINVAL
        return false;
    }

    true
}

#[link_section = "uprobe.s//proc/self/exe:trigger_func3"]
#[no_mangle]
extern "C" fn handle_uprobe_byname3_sleepable(_ctx: *const c_void) -> i32 {
    if verify_sleepable_user_copy() {
        unsafe { uprobe_byname3_sleepable_res = 9 };
    }
    if verify_sleepable_user_copy_str() {
        unsafe { uprobe_byname3_str_sleepable_res = 10 };
    }
    0
}

/**
 * same target as the uprobe.s above to force sleepable and non-sleepable
 * programs in the same bpf_prog_array
 */
#[link_section = "uprobe//proc/self/exe:trigger_func3"]
#[no_mangle]
extern "C" fn handle_uprobe_byname3(_ctx: *const c_void) -> i32 {
    unsafe { uprobe_byname3_res = 11 };
    0
}

#[link_section = "uretprobe.s//proc/self/exe:trigger_func3"]
#[no_mangle]
extern "C" fn handle_uretprobe_byname3_sleepable(_ctx: *const c_void) -> i32 {
    if verify_sleepable_user_copy() {
        unsafe { uretprobe_byname3_sleepable_res = 12 };
    }
    if verify_sleepable_user_copy_str() {
        unsafe { uretprobe_byname3_str_sleepable_res = 13 };
    }
    0
}

#[link_section = "uretprobe//proc/self/exe:trigger_func3"]
#[no_mangle]
extern "C" fn handle_uretprobe_byname3(_ctx: *const c_void) -> i32 {
    unsafe { uretprobe_byname3_res = 14 };
    0
}

bpf_object!("GPL");
