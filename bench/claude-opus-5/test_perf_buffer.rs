#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_perf_buffer.c.
//
// prog_tests/perf_buffer.c pins itself to each online CPU in turn and
// expects exactly one sample per CPU carrying that CPU's id, so the
// payload must stay a single `int` written with BPF_F_CURRENT_CPU.
// perf_buf_map deliberately has no max_entries: libbpf fills it in with
// the possible-CPU count, which is what perf_buffer__new() relies on.

use core::ffi::c_void;

#[allow(non_camel_case_types)]
#[repr(C)]
struct my_pid_map_def {
    r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY = 2
    key: *const i32,
    value: *const i32,
    max_entries: *const [i32; 1],
}
unsafe impl Sync for my_pid_map_def {}

#[link_section = ".maps"]
#[no_mangle]
static my_pid_map: my_pid_map_def = my_pid_map_def {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    max_entries: core::ptr::null(),
};

#[allow(non_camel_case_types)]
#[repr(C)]
struct perf_buf_map_def {
    r#type: *const [i32; 4], // BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
    key: *const i32,
    value: *const i32,
}
unsafe impl Sync for perf_buf_map_def {}

#[link_section = ".maps"]
#[no_mangle]
static perf_buf_map: perf_buf_map_def = perf_buf_map_def {
    r#type: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
};

const BPF_F_CURRENT_CPU: u64 = 0xffffffff;

#[inline(always)]
fn bpf_get_smp_processor_id() -> u32 {
    let f: extern "C" fn() -> u32 = unsafe { core::mem::transmute(8usize) };
    f()
}

#[inline(always)]
fn bpf_get_current_pid_tgid() -> u64 {
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(14usize) };
    f()
}

#[inline(always)]
fn bpf_map_lookup_elem(map: *const my_pid_map_def, key: *const c_void) -> *mut c_void {
    let f: extern "C" fn(*const my_pid_map_def, *const c_void) -> *mut c_void =
        unsafe { core::mem::transmute(1usize) };
    f(map, key)
}

#[inline(always)]
fn bpf_perf_event_output(
    ctx: *const c_void,
    map: *const perf_buf_map_def,
    flags: u64,
    data: *const c_void,
    size: u64,
) -> i64 {
    let f: extern "C" fn(*const c_void, *const perf_buf_map_def, u64, *const c_void, u64) -> i64 =
        unsafe { core::mem::transmute(25usize) };
    f(ctx, map, flags, data, size)
}

#[link_section = "tp/raw_syscalls/sys_enter"]
#[no_mangle]
extern "C" fn handle_sys_enter(ctx: *const c_void) -> i32 {
    let zero: i32 = 0;
    let cpu: i32 = bpf_get_smp_processor_id() as i32;

    let my_pid = bpf_map_lookup_elem(&my_pid_map, &zero as *const i32 as *const c_void) as *const i32;
    if my_pid.is_null() {
        return 1;
    }

    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    if cur_pid != unsafe { *my_pid } {
        return 1;
    }

    bpf_perf_event_output(
        ctx,
        &perf_buf_map,
        BPF_F_CURRENT_CPU,
        &cpu as *const i32 as *const c_void,
        core::mem::size_of::<i32>() as u64,
    );
    1
}

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
