#![no_std]
#![no_main]

use bpf_rs_core::helpers::bpf_perf_event_read_value;
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::bpf_map;

#[repr(C)]
struct bpf_perf_event_value {
    counter: u64,
    enabled: u64,
    running: u64,
}

#[link_section = ".maps"]
#[no_mangle]
static array_1: BpfMap<i32, i32, { maps::PERF_EVENT_ARRAY }, 1> = BpfMap::new();

bpf_map! {
    array_2 {
        r#type: *const [i32; maps::PERF_EVENT_ARRAY],
        max_entries: *const [i32; 1],
        key: *const i32,
        value: *const i32,
        map_flags: *const [i32; 2048], // BPF_F_PRESERVE_ELEMS = 1 << 11
    }
}

#[link_section = "raw_tp/sched_switch"]
#[no_mangle]
extern "C" fn read_array_1(_ctx: *const core::ffi::c_void) -> i32 {
    let mut val = bpf_perf_event_value {
        counter: 0,
        enabled: 0,
        running: 0,
    };
    bpf_perf_event_read_value(&array_1, 0, &mut val, core::mem::size_of::<bpf_perf_event_value>() as u32) as i32
}

#[link_section = "raw_tp/task_rename"]
#[no_mangle]
extern "C" fn read_array_2(_ctx: *const core::ffi::c_void) -> i32 {
    let mut val = bpf_perf_event_value {
        counter: 0,
        enabled: 0,
        running: 0,
    };
    bpf_perf_event_read_value(&array_2, 0, &mut val, core::mem::size_of::<bpf_perf_event_value>() as u32) as i32
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
