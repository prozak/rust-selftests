#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_legacy_printk.c (bpf-rs-core
// idiom). Neither program dereferences its tracepoint ctx, so it stays
// opaque (`*const c_void`).

use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_map_lookup_elem, bpf_trace_printk1};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

#[link_section = ".maps"]
#[no_mangle]
static my_pid_map: BpfMap<i32, i32, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static res_map: BpfMap<i32, i32, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut my_pid_var: i32 = 0;
#[no_mangle]
static mut res_var: i32 = 0;

#[link_section = "tp/raw_syscalls/sys_enter"]
#[no_mangle]
extern "C" fn handle_legacy(_ctx: *const c_void) -> i32 {
    let zero: i32 = 0;

    let my_pid = bpf_map_lookup_elem(&my_pid_map, &zero) as *mut i32;
    if my_pid.is_null() {
        return 1;
    }

    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    if cur_pid != unsafe { *my_pid } {
        return 1;
    }

    let my_res = bpf_map_lookup_elem(&res_map, &zero) as *mut i32;
    if my_res.is_null() {
        return 1;
    }

    if unsafe { *my_res } == 0 {
        // use bpf_printk() in combination with BPF_NO_GLOBAL_DATA to force
        // .rodata.str1.1 section that previously caused problems on old
        // kernels due to libbpf always tried to create a global data map
        // for it
        static FMT: [u8; 37] = *b"Legacy-case bpf_printk test, pid %d\n\0";
        bpf_trace_printk1(
            FMT.as_ptr() as *const c_void,
            FMT.len() as u32,
            cur_pid as u64,
        );
    }
    unsafe {
        *my_res = 1;
        *my_res
    }
}

#[link_section = "tp/raw_syscalls/sys_enter"]
#[no_mangle]
extern "C" fn handle_modern(_ctx: *const c_void) -> i32 {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    if cur_pid != unsafe { my_pid_var } {
        return 1;
    }

    if unsafe { res_var } == 0 {
        // we need bpf_printk() to validate libbpf logic around unused
        // global maps and legacy kernels; see comment in handle_legacy()
        static FMT: [u8; 37] = *b"Modern-case bpf_printk test, pid %d\n\0";
        bpf_trace_printk1(
            FMT.as_ptr() as *const c_void,
            FMT.len() as u32,
            cur_pid as u64,
        );
    }
    unsafe {
        res_var = 1;
        res_var
    }
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
