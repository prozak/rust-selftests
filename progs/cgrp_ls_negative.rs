#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cgrp_ls_negative.c,
// bpf-rs-core idiom.
//
// This is a load-time negative test: it passes a `struct task_struct *`
// (from bpf_get_current_task_btf) to bpf_cgrp_storage_get, which expects a
// `struct cgroup *`. The verifier's ARG_PTR_TO_BTF_ID check compares the
// register's actual BTF id, not any source-level cast, so keeping the
// pointer's real BTF type as task_struct reproduces the C source's
// `(struct cgroup *)task` type mismatch and the object fails to load.

use bpf_rs_core::helpers::{bpf_cgrp_storage_get, bpf_get_current_task_btf};
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;

#[btf]
struct task_struct {
    pid: i32,
}

const BPF_LOCAL_STORAGE_GET_F_CREATE: u64 = 1;
const BPF_MAP_TYPE_CGRP_STORAGE: i32 = 32;

bpf_map! {
    map_a {
        r#type: *const [i32; BPF_MAP_TYPE_CGRP_STORAGE as usize],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        key: *const i32,
        value: *const isize,
    }
}

#[link_section = "tp_btf/sys_enter"]
#[no_mangle]
extern "C" fn on_enter(_ctx: *const u64) -> i32 {
    let task: *mut task_struct = bpf_get_current_task_btf();
    bpf_cgrp_storage_get(
        &map_a,
        task,
        core::ptr::null_mut(),
        BPF_LOCAL_STORAGE_GET_F_CREATE,
    );
    0
}

bpf_object!("GPL");
