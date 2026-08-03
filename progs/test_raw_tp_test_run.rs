#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_smp_processor_id;
use bpf_rs_core::progs::fentry_arg;

#[no_mangle]
static mut count: u32 = 0;

#[no_mangle]
static mut on_cpu: u32 = 0xffffffff;

#[link_section = "raw_tp/task_rename"]
#[no_mangle]
extern "C" fn rename(ctx: *const u64) -> i32 {
    let task = fentry_arg(ctx, 0);
    let comm = fentry_arg(ctx, 1);

    unsafe {
        count += 1;
    }

    if task == 0x1234 && comm == 0x5678 {
        unsafe {
            on_cpu = bpf_get_smp_processor_id();
        }
        return (task as i64 + comm as i64) as i32;
    }

    0
}

bpf_object!("GPL");
