#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bprm_opts.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::bpf_map;
use bpf_rs_core::helpers::{bpf_bprm_opts_set, bpf_get_current_task_btf, bpf_task_storage_get};
use bpf_rs_core::progs::fentry_arg as arg;

const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;
const BPF_F_BPRM_SECUREEXEC: u64 = 1;
const BPF_MAP_TYPE_TASK_STORAGE: i32 = 29;

bpf_map! {
    secure_exec_task_map {
        r#type: *const [i32; BPF_MAP_TYPE_TASK_STORAGE as usize],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const i32,
    }
}

struct task_struct;
struct linux_binprm;

#[link_section = "lsm/bprm_creds_for_exec"]
#[no_mangle]
extern "C" fn secure_exec(ctx: *const u64) -> i32 {
    let bprm = arg(ctx, 0) as *mut linux_binprm;

    let task: *mut task_struct = bpf_get_current_task_btf();
    let secureexec = bpf_task_storage_get(
        &secure_exec_task_map,
        task,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    ) as *mut i32;

    if !secureexec.is_null() && unsafe { *secureexec } != 0 {
        bpf_bprm_opts_set(bprm, BPF_F_BPRM_SECUREEXEC);
    }

    0
}

bpf_object!("GPL");
