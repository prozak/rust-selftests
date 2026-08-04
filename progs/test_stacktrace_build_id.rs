#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_stacktrace_build_id.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_stack, bpf_get_stackid, bpf_map_lookup_elem, bpf_map_update_elem,
};
use bpf_rs_core::maps::{self, BpfMap};

const PERF_MAX_STACK_DEPTH: usize = 127;

const BPF_F_USER_STACK: u64 = 1 << 8;
const BPF_F_USER_BUILD_ID: u64 = 1 << 11;

// struct bpf_stack_build_id { __s32 status; unsigned char build_id[20];
// union { __u64 offset; __u64 ip; }; };  (union collapses to one u64 field)
#[repr(C)]
struct bpf_stack_build_id {
    status: i32,
    build_id: [u8; 20],
    offset: u64,
}

#[allow(non_camel_case_types)]
type stack_trace_t = [bpf_stack_build_id; PERF_MAX_STACK_DEPTH];

#[link_section = ".maps"]
#[no_mangle]
static control_map: BpfMap<u32, u32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static stackid_hmap: BpfMap<u32, u32, { maps::HASH }, 16384> = BpfMap::new();

bpf_map! {
    // BPF_MAP_TYPE_STACK_TRACE, map_flags = BPF_F_STACK_BUILD_ID (1 << 5)
    stackmap {
        r#type: *const [i32; maps::STACK_TRACE],
        max_entries: *const [i32; 128],
        map_flags: *const [i32; 32],
        key: *const u32,
        value: *const stack_trace_t,
    }
}

#[link_section = ".maps"]
#[no_mangle]
static stack_amap: BpfMap<u32, stack_trace_t, { maps::ARRAY }, 128> = BpfMap::new();

#[link_section = "kprobe/urandom_read_iter"]
#[no_mangle]
extern "C" fn oncpu(ctx: *const core::ffi::c_void) -> i32 {
    let max_len: u32 =
        core::mem::size_of::<bpf_stack_build_id>() as u32 * PERF_MAX_STACK_DEPTH as u32;
    let key0: u32 = 0;
    let val: u32 = 0;

    let value_p = bpf_map_lookup_elem(&control_map, &key0);
    if !value_p.is_null() && unsafe { *(value_p as *const u32) } != 0 {
        return 0; // skip if non-zero *value_p
    }

    // The size of stackmap and stackid_hmap should be the same
    let ret = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
    let key = ret as u32;
    if (key as i32) >= 0 {
        bpf_map_update_elem(&stackid_hmap, &key, &val, 0);
        let stack_p = bpf_map_lookup_elem(&stack_amap, &key);
        if !stack_p.is_null() {
            bpf_get_stack(
                ctx,
                stack_p,
                max_len,
                BPF_F_USER_STACK | BPF_F_USER_BUILD_ID,
            );
        }
    }

    0
}

bpf_object!("GPL");
