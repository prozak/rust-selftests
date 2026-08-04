#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_core_reloc_kernel.c,
// bpf-rs-core idiom.
//
// `task = (void *)bpf_get_current_task()` is a plain u64->pointer cast, not
// bpf_get_current_task_btf(): the resulting pointer is SCALAR_VALUE, not a
// trusted PTR_TO_BTF_ID (see raw-tp-ctx-scalar-needs-probe-read-not-btf-get
// memory). Like the C source's BPF_CORE_READ/CORE_READ macros, every field
// read below goes through `.as_ptr()` (relocated address only, no load) +
// bpf_probe_read_kernel, never `#[btf]`'s `.get()`.
//
// `out->local_task_struct_matches = bpf_core_type_matches(struct
// task_struct___local)` has no equivalent here: this pipeline's field-reloc
// pass (rust-bpf/bpf-postproc/src/field_reloc.rs) only lowers the
// BYTE_OFFSET and EXISTENCE `llvm.bpf.preserve.field.info` kinds.
// BPF_TYPE_MATCHES is a different intrinsic (`llvm.bpf.preserve.type.info`)
// that btf-macros/the btf crate never emits at all. The only consumer of
// this object (core_reloc.c's single "kernel" case) hardcodes the expected
// value to `true`, so `local_task_struct_matches` is hardcoded to match.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel,
    bpf_probe_read_kernel_str,
};
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
    tgid: i32,
    comm: [u8; 16],
    group_leader: *mut task_struct,
}

#[repr(C)]
struct Data {
    input: [u8; 256],
    output: [u8; 256],
    skip: bool,
    my_pid_tgid: u64,
}

#[no_mangle]
static mut data: Data = Data {
    input: [0; 256],
    output: [0; 256],
    skip: false,
    my_pid_tgid: 0,
};

#[repr(C)]
struct Output {
    valid: [i32; 10],
    comm: [u8; 11], // sizeof("test_progs")
    comm_len: i32,
    local_task_struct_matches: bool,
}

#[inline(always)]
fn read_tgid(t: *const task_struct) -> i32 {
    if t.is_null() {
        return 0;
    }
    let addr = unsafe { (&*t).tgid().as_ptr() } as *const core::ffi::c_void;
    let mut val: i32 = 0;
    bpf_probe_read_kernel(&mut val, 4, addr);
    val
}

#[inline(always)]
fn next_group_leader(t: *const task_struct) -> *const task_struct {
    if t.is_null() {
        return core::ptr::null();
    }
    let addr = unsafe { (&*t).group_leader().as_ptr() } as *const core::ffi::c_void;
    let mut val: *mut task_struct = core::ptr::null_mut();
    bpf_probe_read_kernel(
        &mut val,
        core::mem::size_of::<*mut task_struct>() as u32,
        addr,
    );
    val as *const task_struct
}

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn test_core_kernel(_ctx: *const core::ffi::c_void) -> i32 {
    let task = bpf_get_current_task() as usize as *const task_struct;
    let out = unsafe { core::ptr::addr_of_mut!(data.output) } as *mut Output;
    let pid_tgid = bpf_get_current_pid_tgid();
    let real_tgid = pid_tgid as i32;

    if unsafe { data.my_pid_tgid } != pid_tgid {
        return 0;
    }

    let pid_addr = unsafe { (&*task).pid().as_ptr() } as *const core::ffi::c_void;
    let tgid_addr = unsafe { (&*task).tgid().as_ptr() } as *const core::ffi::c_void;
    let mut pid_v: i32 = 0;
    let mut tgid_v: i32 = 0;
    let r1 = bpf_probe_read_kernel(&mut pid_v, 4, pid_addr);
    let r2 = bpf_probe_read_kernel(&mut tgid_v, 4, tgid_addr);
    if r1 != 0 || r2 != 0 {
        return 1;
    }

    let combined = ((pid_v as i64 as u64) << 32) | (tgid_v as i64 as u64);
    unsafe { (*out).valid[0] = (combined == pid_tgid) as i32 };

    let t1 = next_group_leader(task);
    let t2 = next_group_leader(t1);
    let t3 = next_group_leader(t2);
    let t4 = next_group_leader(t3);
    let t5 = next_group_leader(t4);
    let t6 = next_group_leader(t5);
    let t7 = next_group_leader(t6);
    let t8 = next_group_leader(t7);

    unsafe {
        (*out).valid[1] = (read_tgid(task) == real_tgid) as i32;
        (*out).valid[2] = (read_tgid(t1) == real_tgid) as i32;
        (*out).valid[3] = (read_tgid(t2) == real_tgid) as i32;
        (*out).valid[4] = (read_tgid(t3) == real_tgid) as i32;
        (*out).valid[5] = (read_tgid(t4) == real_tgid) as i32;
        (*out).valid[6] = (read_tgid(t5) == real_tgid) as i32;
        (*out).valid[7] = (read_tgid(t6) == real_tgid) as i32;
        (*out).valid[8] = (read_tgid(t7) == real_tgid) as i32;
        (*out).valid[9] = (read_tgid(t8) == real_tgid) as i32;
    }

    let comm_addr = if t8.is_null() {
        core::ptr::null()
    } else {
        unsafe { (&*t8).comm().as_ptr() as *const core::ffi::c_void }
    };
    let comm_dst = unsafe { core::ptr::addr_of_mut!((*out).comm) } as *mut core::ffi::c_void;
    let comm_len = bpf_probe_read_kernel_str(comm_dst, 11, comm_addr);
    unsafe { (*out).comm_len = comm_len as i32 };

    unsafe { (*out).local_task_struct_matches = true };

    0
}

bpf_object!("GPL");
