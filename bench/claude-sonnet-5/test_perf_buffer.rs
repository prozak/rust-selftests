#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_perf_buffer.c.
//
// perf_buf_map has no max_entries in the C source (libbpf sizes a
// PERF_EVENT_ARRAY to the number of CPUs when it is 0), so its BTF map
// struct carries only type/key/value members.

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
fn bpf_map_lookup_elem<K>(map: *const my_pid_map_def, key: &K) -> *mut core::ffi::c_void {
    let f: extern "C" fn(
        *const my_pid_map_def,
        *const core::ffi::c_void,
    ) -> *mut core::ffi::c_void = unsafe { core::mem::transmute(1usize) };
    f(map, key as *const K as *const core::ffi::c_void)
}

#[inline(always)]
fn bpf_perf_event_output<T>(
    ctx: *const core::ffi::c_void,
    map: *const perf_buf_map_def,
    flags: u64,
    data: &T,
    size: u64,
) -> i64 {
    let f: extern "C" fn(
        *const core::ffi::c_void,
        *const perf_buf_map_def,
        u64,
        *const core::ffi::c_void,
        u64,
    ) -> i64 = unsafe { core::mem::transmute(25usize) };
    f(ctx, map, flags, data as *const T as *const core::ffi::c_void, size)
}

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

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
