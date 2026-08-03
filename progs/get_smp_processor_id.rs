#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_smp_processor_id;

#[no_mangle]
static mut cpu_nr_result: u64 = 0;

#[link_section = "raw_tp"]
#[no_mangle]
extern "C" fn call_bpf_get_smp_processor_id(_ctx: *const core::ffi::c_void) -> i32 {
    let r0 = bpf_get_smp_processor_id() as u64;
    unsafe {
        cpu_nr_result = r0;
    }
    0
}

bpf_object!("GPL");
