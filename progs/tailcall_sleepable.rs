#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/tailcall_sleepable.c,
// bpf-rs-core idiom.

use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_tail_call};
use bpf_rs_core::{bpf_map, bpf_object, maps};

bpf_map! {
    jmp_table {
        r#type: *const [i32; maps::PROG_ARRAY],
        max_entries: *const [i32; 1],
        key_size: *const [i32; 4],
        value_size: *const [i32; 4],
    }
}

#[link_section = "?uprobe"]
#[no_mangle]
extern "C" fn uprobe_normal(ctx: *const core::ffi::c_void) -> i32 {
    bpf_tail_call(ctx, &jmp_table, 0);
    0
}

#[link_section = "?uprobe.s"]
#[no_mangle]
extern "C" fn uprobe_sleepable_1(ctx: *const core::ffi::c_void) -> i32 {
    bpf_tail_call(ctx, &jmp_table, 0);
    0
}

#[no_mangle]
static mut executed: i32 = 0;
#[no_mangle]
static mut my_pid: i32 = 0;

#[link_section = "?uprobe.s"]
#[no_mangle]
extern "C" fn uprobe_sleepable_2(_ctx: *const core::ffi::c_void) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as i32;

    if unsafe { pid != my_pid } {
        return 0;
    }

    unsafe { executed += 1 };
    0
}

bpf_object!("GPL");
