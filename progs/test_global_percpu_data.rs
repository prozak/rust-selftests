#![no_std]
#![no_main]
// BTF_C_CHAR: u8
// BTF_ANON: PerCpuData

use core::{ffi::c_void, ptr::{addr_of, addr_of_mut, read_volatile}};
use bpf_rs_core::helpers::{bpf_get_smp_processor_id, bpf_strncmp, bpf_snprintf, bpf_trace_printk1};

#[no_mangle]
#[link_section = ".percpu.looooooooong"]
static mut loong: i32 = 0;
#[no_mangle]
#[link_section = ".data.percpu"]
static mut data3: i32 = 0;
#[no_mangle]
#[link_section = ".percpu.data"]
static mut data2: i32 = 0;
#[no_mangle]
#[link_section = ".percpu.arr"]
static mut arr: [i32; 1] = [0];
#[no_mangle]
static mut arr_sum: i32 = 0;
#[no_mangle]
static mut run: i32 = 0;
#[no_mangle]
#[link_section = ".percpu"]
static mut cpu_id: i32 = 0;
#[no_mangle]
#[link_section = ".percpu"]
static mut data: i32 = -1;
#[no_mangle]
#[link_section = ".percpu"]
static mut nums: [i32; 7] = [0; 7];
#[no_mangle]
#[link_section = ".percpu"]
static mut set: u8 = 0;
#[repr(C)]
struct PerCpuData { set: u8, _pad: [u8; 3], i: i32, nums: [i32; 7] }
#[no_mangle]
#[link_section = ".percpu"]
static mut struct_data: PerCpuData = PerCpuData { set: 0, _pad: [0; 3], i: -1, nums: [0; 7] };

#[no_mangle]
#[link_section = "raw_tp/task_rename"]
extern "C" fn update_percpu_data(_ctx: *const c_void) -> i32 {
    unsafe {
        struct_data.nums[6] = 0xc0de;
        struct_data.set = 1;
        struct_data.i = 1;
        nums[6] = 0xc0de;
        data = 1;
        run = run.wrapping_add(1);
        set = 1;
        cpu_id = bpf_get_smp_processor_id() as i32;
        arr_sum = arr_sum.wrapping_add(arr[0]);
    }
    0
}
#[link_section = ".percpu.fmt"]
#[no_mangle]
static fmt: [u8; 9] = *b"data %d\n\0";

#[no_mangle]
#[link_section = "?kprobe"]
extern "C" fn verifier_strncmp(_ctx: *const c_void) -> i32 {
    bpf_strncmp(b"test\0".as_ptr().cast(), 5, addr_of!(fmt).cast()) as i32
}
#[no_mangle]
#[link_section = "?kprobe"]
extern "C" fn verifier_snprintf(_ctx: *const c_void) -> i32 {
    let args = [unsafe { data } as i64 as u64];
    let mut buf = core::mem::MaybeUninit::<[u8; 128]>::uninit();
    let len = bpf_snprintf(buf.as_mut_ptr().cast(), 128, addr_of!(fmt).cast(), args.as_ptr().cast(), 8) as i32;
    if len > 0 {
        bpf_trace_printk1(b"snprintf: %s\n\0".as_ptr().cast(), 14, buf.as_mut_ptr() as u64);
    }
    0
}
#[no_mangle]
#[link_section = ".rodata"]
static num_cpus: u32 = 0;
#[no_mangle]
#[link_section = ".rodata"]
static num_off: i32 = 0;
#[no_mangle]
#[link_section = ".rodata"]
static elem_sz: i32 = 0;
#[no_mangle]
static mut sum: u32 = 0;
#[no_mangle]
static mut run_iter: u8 = 0;

#[repr(C)]
struct bpf_iter__bpf_map_elem {
    meta: *mut c_void, map: *mut c_void, key: *mut c_void, value: *mut c_void,
}
#[no_mangle]
#[link_section = "iter/bpf_map_elem"]
extern "C" fn dump_percpu_data(ctx: *const bpf_iter__bpf_map_elem) -> i32 {
    unsafe {
        let mut pptr = (*ctx).value as *mut u8;
        if pptr.is_null() { return 0; }
        run_iter = 1;
        let mut i = 0i32;
        while (i as u32) < read_volatile(addr_of!(num_cpus)) {
            sum = sum.wrapping_add(*(pptr.wrapping_offset(read_volatile(addr_of!(num_off)) as isize) as *const i32) as u32);
            pptr = pptr.wrapping_offset(read_volatile(addr_of!(elem_sz)) as isize);
            i = i.wrapping_add(1);
        }
    }
    0
}
bpf_rs_core::bpf_object!("GPL");
bpf_rs_core::test_tags! {
    update_percpu_data: __auxiliary;
    verifier_strncmp: __failure, __msg("R{{[0-9]+}} points to percpu_array map which cannot be used as const string");
    verifier_snprintf: __failure, __msg("R{{[0-9]+}} points to percpu_array map which cannot be used as const string");
    dump_percpu_data: __auxiliary;
}
