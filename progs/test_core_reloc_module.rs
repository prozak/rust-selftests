#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_core_reloc_module.c, bpf-rs-core
// idiom.
//
// Two programs attach to the `bpf_testmod_test_read` tracepoint defined by
// the kernel module test_kmods/bpf_testmod.ko (needs_testmod=true in
// prog_tests/core_reloc.c's MODULES_CASE): `test_core_module_probed` via
// raw_tp (args are plain u64s, so the C source reads task/read_ctx fields
// through BPF_CORE_READ == a CO-RE-relocated offset + bpf_probe_read_kernel)
// and `test_core_module_direct` via tp_btf (args are trusted BTF pointers,
// so the C source dereferences task->field / read_ctx->field directly).
//
// `struct bpf_testmod_test_read_ctx` in the C source deliberately declares
// its fields in a different order than the real module struct
// (`{ char *buf; loff_t off; size_t len; }` in bpf_testmod.h) to prove CO-RE
// matches by field name, not position -- this translation's #[btf] struct
// mirrors that same reordering for fidelity, and it's equally immaterial
// here since #[btf]'s byte_offset/field_exists relocations are also
// name-keyed (see rust-bpf/bpf-postproc's FieldRelocPass).
//
// `out->read_ctx_sz`/`out->read_ctx_exists` use `bpf_core_type_size()` /
// `bpf_core_type_exists()` -- whole-TYPE CO-RE queries, not field queries.
// btf-macros/rust-bpf only implement the two field-level relocation kinds
// (FIELD_BYTE_OFFSET, FIELD_EXISTS -- see btf/src/lib.rs); there is no
// TYPE_SIZE/TYPE_EXISTS mechanism exposed to progs/*.rs (same gap noted in
// the test_core_reloc_size.c translation). Unlike that test, this one always
// resolves against the one real, live bpf_testmod.ko BTF (btf_src_file is
// NULL -- "find in kernel module BTFs" -- and the run_btfgen variant skips
// module cases outright since btf_src_file is unset), so there is no varying
// target flavor to track: `struct bpf_testmod_test_read_ctx` is always
// exactly `{ char *buf; loff_t off; size_t len; }`, 24 bytes on the x86_64
// target this repo builds/runs on. `ReadCtxLayout` below exists solely to
// name that known-fixed size at compile time instead of hardcoding a bare
// `24`; `read_ctx_exists` is unconditionally `true` for the same reason (if
// the module's BTF didn't have this type, the byte-offset relocations used
// for `len`/`off`/`buf` below would already have failed the object load).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str,
};
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;
use core::ffi::c_void;

#[btf]
struct task_struct {
    pid: i32,
    tgid: i32,
    comm: [u8; 16],
}

#[btf]
struct bpf_testmod_test_read_ctx {
    len: u64,
    buf: *mut u8,
    off: i64,
}

#[repr(C)]
struct ReadCtxLayout {
    buf: *mut u8,
    off: i64,
    len: u64,
}

#[repr(C)]
struct Data {
    in_: [u8; 256],
    out: [u8; 256],
    skip: bool,
    my_pid_tgid: u64,
}

#[no_mangle]
static mut data: Data = Data {
    in_: [0; 256],
    out: [0; 256],
    skip: false,
    my_pid_tgid: 0,
};

#[repr(C)]
struct ModuleOutput {
    len: i64,
    off: i64,
    read_ctx_sz: i32,
    read_ctx_exists: bool,
    buf_exists: bool,
    len_exists: bool,
    off_exists: bool,
    comm: [u8; 12],
    comm_len: i32,
}

#[inline(always)]
unsafe fn write_common(
    out: *mut ModuleOutput,
    len: i64,
    off: i64,
    buf_exists: bool,
    len_exists: bool,
    off_exists: bool,
    task: *mut task_struct,
) {
    unsafe {
        (*out).len = len;
        (*out).off = off;
        (*out).read_ctx_sz = core::mem::size_of::<ReadCtxLayout>() as i32;
        (*out).read_ctx_exists = true;
        (*out).buf_exists = buf_exists;
        (*out).len_exists = len_exists;
        (*out).off_exists = off_exists;
    }

    let comm_src = unsafe { &*task }.comm().as_ptr() as *const c_void;
    let comm_dst = unsafe { core::ptr::addr_of_mut!((*out).comm) } as *mut c_void;
    let comm_len = bpf_probe_read_kernel_str(comm_dst, 12, comm_src);
    unsafe { (*out).comm_len = comm_len as i32 };
}

#[inline(never)]
fn do_module_probed(ctx: *const u64) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let real_tgid = (pid_tgid >> 32) as i32;
    let real_pid = pid_tgid as i32;

    if unsafe { data.my_pid_tgid } != pid_tgid {
        return 0;
    }

    let task = arg(ctx, 0) as *mut task_struct;
    let read_ctx = arg(ctx, 1) as *mut bpf_testmod_test_read_ctx;
    let task_view = unsafe { &*task };
    let read_ctx_view = unsafe { &*read_ctx };

    let mut task_pid: i32 = 0;
    let mut task_tgid: i32 = 0;
    bpf_probe_read_kernel(
        &mut task_pid,
        4,
        task_view.pid().as_ptr() as *const c_void,
    );
    bpf_probe_read_kernel(
        &mut task_tgid,
        4,
        task_view.tgid().as_ptr() as *const c_void,
    );
    if task_pid != real_pid || task_tgid != real_tgid {
        return 0;
    }

    let mut len_val: u64 = 0;
    let mut off_val: i64 = 0;
    bpf_probe_read_kernel(
        &mut len_val,
        8,
        read_ctx_view.len().as_ptr() as *const c_void,
    );
    bpf_probe_read_kernel(
        &mut off_val,
        8,
        read_ctx_view.off().as_ptr() as *const c_void,
    );

    let buf_exists = read_ctx_view.buf().exists();
    let off_exists = read_ctx_view.off().exists();
    let len_exists = read_ctx_view.len().exists();

    let out = unsafe { core::ptr::addr_of_mut!(data.out) } as *mut ModuleOutput;
    unsafe {
        write_common(
            out,
            len_val as i64,
            off_val,
            buf_exists,
            len_exists,
            off_exists,
            task,
        )
    };

    0
}

#[inline(never)]
fn do_module_direct(ctx: *const u64) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let real_tgid = (pid_tgid >> 32) as i32;
    let real_pid = pid_tgid as i32;

    if unsafe { data.my_pid_tgid } != pid_tgid {
        return 0;
    }

    let task = arg(ctx, 0) as *mut task_struct;
    let read_ctx = arg(ctx, 1) as *mut bpf_testmod_test_read_ctx;
    let task_view = unsafe { &*task };
    let read_ctx_view = unsafe { &*read_ctx };

    let task_pid = *task_view.pid().get().unwrap();
    let task_tgid = *task_view.tgid().get().unwrap();
    if task_pid != real_pid || task_tgid != real_tgid {
        return 0;
    }

    let len_val = *read_ctx_view.len().get().unwrap();
    let off_val = *read_ctx_view.off().get().unwrap();

    let buf_exists = read_ctx_view.buf().exists();
    let off_exists = read_ctx_view.off().exists();
    let len_exists = read_ctx_view.len().exists();

    let out = unsafe { core::ptr::addr_of_mut!(data.out) } as *mut ModuleOutput;
    unsafe {
        write_common(
            out,
            len_val as i64,
            off_val,
            buf_exists,
            len_exists,
            off_exists,
            task,
        )
    };

    0
}

#[link_section = "raw_tp/bpf_testmod_test_read"]
#[no_mangle]
extern "C" fn test_core_module_probed(ctx: *const u64) -> i32 {
    do_module_probed(ctx)
}

#[link_section = "tp_btf/bpf_testmod_test_read"]
#[no_mangle]
extern "C" fn test_core_module_direct(ctx: *const u64) -> i32 {
    do_module_direct(ctx)
}

bpf_object!("GPL");
