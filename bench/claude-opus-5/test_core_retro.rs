#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_core_retro.c.
//
// The C source declares a minimal local `struct task_struct { int tgid; }`
// carrying preserve_access_index, and reads the field with BPF_CORE_READ —
// i.e. a bpf_probe_read_kernel from the CO-RE-relocated field address. The
// relocation is what makes the test "retro": the local one-field struct has
// nothing to do with the running kernel's task_struct layout, so the offset
// must come from the target BTF.
//
// The pointer returned by bpf_get_current_task() is a plain scalar, not a
// BTF-typed pointer, so a direct load through it would be rejected by the
// verifier; probe_read_kernel is mandatory here, matching the C.
//
// `#[btf]` reproduces the local BTF struct and `.tgid().as_ptr()` yields the
// relocated address without emitting a load (unlike `.get()`, which would
// dereference it).

use btf_macros::btf;

#[btf]
struct task_struct {
    tgid: i32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct exp_tgid_map_def {
    r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY = 2
    max_entries: *const [i32; 1],
    key: *const i32,
    value: *const i32,
}
unsafe impl Sync for exp_tgid_map_def {}

#[link_section = ".maps"]
#[no_mangle]
static exp_tgid_map: exp_tgid_map_def = exp_tgid_map_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
};

#[allow(non_camel_case_types)]
#[repr(C)]
struct results_def {
    r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY = 2
    max_entries: *const [i32; 1],
    key: *const i32,
    value: *const i32,
}
unsafe impl Sync for results_def {}

#[link_section = ".maps"]
#[no_mangle]
static results: results_def = results_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
};

#[inline(always)]
fn bpf_get_current_task() -> u64 {
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(35usize) };
    f()
}

#[inline(always)]
fn bpf_get_current_pid_tgid() -> u64 {
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(14usize) };
    f()
}

#[inline(always)]
fn bpf_probe_read_kernel<T>(dst: &mut T, size: u32, src: *const core::ffi::c_void) -> i64 {
    let f: extern "C" fn(*mut core::ffi::c_void, u32, *const core::ffi::c_void) -> i64 =
        unsafe { core::mem::transmute(113usize) };
    f(dst as *mut T as *mut core::ffi::c_void, size, src)
}

#[inline(always)]
fn bpf_map_lookup_elem<K>(map: *const exp_tgid_map_def, key: &K) -> *mut core::ffi::c_void {
    let f: extern "C" fn(
        *const exp_tgid_map_def,
        *const core::ffi::c_void,
    ) -> *mut core::ffi::c_void = unsafe { core::mem::transmute(1usize) };
    f(map, key as *const K as *const core::ffi::c_void)
}

#[inline(always)]
fn bpf_map_update_elem<K, V>(map: *const results_def, key: &K, value: &V, flags: u64) -> i64 {
    let f: extern "C" fn(
        *const results_def,
        *const core::ffi::c_void,
        *const core::ffi::c_void,
        u64,
    ) -> i64 = unsafe { core::mem::transmute(2usize) };
    f(
        map,
        key as *const K as *const core::ffi::c_void,
        value as *const V as *const core::ffi::c_void,
        flags,
    )
}

#[link_section = "tp/raw_syscalls/sys_enter"]
#[no_mangle]
extern "C" fn handle_sys_enter(_ctx: *const core::ffi::c_void) -> i32 {
    let task = bpf_get_current_task() as *const task_struct;
    // BPF_CORE_READ(task, tgid)
    let mut tgid: i32 = 0;
    bpf_probe_read_kernel(
        &mut tgid,
        core::mem::size_of::<i32>() as u32,
        unsafe { &*task }.tgid().as_ptr() as *const core::ffi::c_void,
    );

    let zero: i32 = 0;
    let real_tgid = (bpf_get_current_pid_tgid() >> 32) as i32;
    let exp_tgid = bpf_map_lookup_elem(&exp_tgid_map, &zero);

    // only pass through sys_enters from test process
    if exp_tgid.is_null() || unsafe { *(exp_tgid as *const i32) } != real_tgid {
        return 0;
    }

    bpf_map_update_elem(&results, &zero, &tgid, 0);

    0
}

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
