#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_perf_buffer.c, bpf-rs-core idiom.
//
// perf_buf_map has no max_entries in the C source (libbpf sizes a
// PERF_EVENT_ARRAY to the number of CPUs when it is 0), so its BTF map
// struct carries only type/key/value members — bpf_map! escape hatch.

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_get_smp_processor_id, bpf_map_lookup_elem,
    bpf_perf_event_output,
};
use bpf_rs_core::{bpf_map, bpf_object};

bpf_map! {
    my_pid_map {
        r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY = 2
        key: *const i32,
        value: *const i32,
        max_entries: *const [i32; 1],
    }
}

bpf_map! {
    perf_buf_map {
        r#type: *const [i32; 4], // BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
        key: *const i32,
        value: *const i32,
    }
}

const BPF_F_CURRENT_CPU: u64 = 0xffffffff;

#[link_section = "tp/raw_syscalls/sys_enter"]
#[no_mangle]
extern "C" fn handle_sys_enter(ctx: *const core::ffi::c_void) -> i32 {
    let zero: i32 = 0;
    let cpu: i32 = bpf_get_smp_processor_id() as i32;

    let my_pid = bpf_map_lookup_elem(&my_pid_map, &zero);
    if my_pid.is_null() {
        return 1;
    }

    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    if cur_pid != unsafe { *(my_pid as *const i32) } {
        return 1;
    }

    bpf_perf_event_output(
        ctx,
        &perf_buf_map,
        BPF_F_CURRENT_CPU,
        &cpu,
        core::mem::size_of::<i32>() as u64,
    );
    1
}

bpf_object!("GPL");
