#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_mmap.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_map_update_elem};

// BPF_MAP_TYPE_ARRAY = 2, BPF_F_RDONLY_PROG = 1<<7, BPF_F_MMAPABLE = 1<<10.
// max_entries deliberately omitted: the C source's anonymous struct has no
// __uint(max_entries, ...) either — the userspace test sets it dynamically
// via bpf_map__set_max_entries() before load.
bpf_map! {
    rdonly_map {
        r#type: *const [i32; 2],    // BPF_MAP_TYPE_ARRAY
        map_flags: *const [i32; 1152], // BPF_F_MMAPABLE | BPF_F_RDONLY_PROG
        key: *const u32,
        value: *const i8, // char
    }
}

bpf_map! {
    data_map {
        r#type: *const [i32; 2],    // BPF_MAP_TYPE_ARRAY
        map_flags: *const [i32; 1024], // BPF_F_MMAPABLE
        key: *const u32,
        value: *const u64,
    }
}

#[no_mangle]
static mut in_val: u64 = 0;
#[no_mangle]
static mut out_val: u64 = 0;

#[link_section = "raw_tracepoint/sys_enter"]
#[no_mangle]
extern "C" fn test_mmap(_ctx: *const core::ffi::c_void) -> i32 {
    let zero: u32 = 0;
    let one: u32 = 1;
    let two: u32 = 2;
    let far: u32 = 1500;

    let cur_in_val = unsafe { in_val };
    unsafe { out_val = cur_in_val };

    // data_map[2] = in_val;
    bpf_map_update_elem(&data_map, &two, &cur_in_val, 0);

    // data_map[1] = data_map[0] * 2;
    let p = bpf_map_lookup_elem(&data_map, &zero) as *const u64;
    if !p.is_null() {
        let val = unsafe { *p } * 2;
        bpf_map_update_elem(&data_map, &one, &val, 0);
    }

    // data_map[far] = in_val * 3;
    let val = cur_in_val * 3;
    bpf_map_update_elem(&data_map, &far, &val, 0);

    0
}

bpf_object!("GPL");
