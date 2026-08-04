#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_xdp_bpf2bpf.c
// (bpf-rs-core idiom).
//
// perf_buf_map has no max_entries in the C source (libbpf sizes a
// PERF_EVENT_ARRAY to the number of CPUs when it is 0), so its BTF map
// struct carries only type/key/value members — bpf_map! escape hatch (same
// pattern as test_perf_buffer.rs's perf_buf_map).

use bpf_rs_core::helpers::{bpf_xdp_get_buff_len, bpf_xdp_output};
use bpf_rs_core::progs::fentry_arg as arg;
use bpf_rs_core::{bpf_map, bpf_object};
use btf_macros::btf;

// Minimal local CO-RE view of the kernel's real structs, matching the C
// source's own local `preserve_access_index` re-declarations (only the
// fields actually walked: xdp->rxq->dev->ifindex).
#[btf]
struct net_device {
    ifindex: i32,
}

#[btf]
struct xdp_rxq_info {
    dev: *mut net_device,
}

#[btf]
struct xdp_buff {
    rxq: *mut xdp_rxq_info,
}

#[repr(C)]
struct Meta {
    ifindex: i32,
    pkt_len: i32,
}

bpf_map! {
    perf_buf_map {
        r#type: *const [i32; 4], // BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
        key: *const i32,
        value: *const i32,
    }
}

const BPF_F_CURRENT_CPU: u64 = 0xffffffff;

#[no_mangle]
static mut test_result_fentry: u64 = 0;

#[link_section = "fentry/FUNC"]
#[no_mangle]
extern "C" fn trace_on_entry(ctx: *const u64) -> i32 {
    let xdp = arg(ctx, 0) as *const xdp_buff;
    let xdp_ref = unsafe { &*xdp };

    let rxq = *xdp_ref.rxq().get().unwrap();
    let rxq_ref = unsafe { &*rxq };
    let dev = *rxq_ref.dev().get().unwrap();
    let dev_ref = unsafe { &*dev };
    let ifindex = *dev_ref.ifindex().get().unwrap();

    let pkt_len = bpf_xdp_get_buff_len(xdp) as i32;

    let meta = Meta { ifindex, pkt_len };
    bpf_xdp_output(
        xdp,
        &perf_buf_map,
        ((pkt_len as i64 as u64) << 32) | BPF_F_CURRENT_CPU,
        &meta,
        core::mem::size_of::<Meta>() as u64,
    );

    unsafe { test_result_fentry = ifindex as i64 as u64 };
    0
}

#[no_mangle]
static mut test_result_fexit: u64 = 0;

#[link_section = "fexit/FUNC"]
#[no_mangle]
extern "C" fn trace_on_exit(ctx: *const u64) -> i32 {
    let ret = arg(ctx, 1) as i32;
    unsafe { test_result_fexit = ret as i64 as u64 };
    0
}

bpf_object!("GPL");
