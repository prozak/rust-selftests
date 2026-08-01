#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_lookup_and_delete.c.
//
// prog_tests/lookup_and_delete.c reopens the skeleton and rewrites the map
// type (HASH / PERCPU_HASH / LRU_HASH / LRU_PERCPU_HASH) and max_entries
// before load, so only the BTF key/value types below are load-bearing; the
// declared type=HASH/max_entries=2 must still match the C source since the
// hash subtest never overrides them with different values.

#[allow(non_camel_case_types)]
#[repr(C)]
struct hash_map_def {
    r#type: *const [i32; 1], // BPF_MAP_TYPE_HASH = 1
    max_entries: *const [i32; 2],
    key: *const u64,
    value: *const u64,
}
unsafe impl Sync for hash_map_def {}

#[link_section = ".maps"]
#[no_mangle]
static hash_map: hash_map_def = hash_map_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
};

// bss globals the userspace test writes before attaching the tracepoint.
#[no_mangle]
static mut set_pid: u32 = 0;
#[no_mangle]
static mut set_key: u64 = 0;
#[no_mangle]
static mut set_value: u64 = 0;

const BPF_NOEXIST: u64 = 1;

#[inline(always)]
fn bpf_get_current_pid_tgid() -> u64 {
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(14usize) };
    f()
}

#[inline(always)]
fn bpf_map_update_elem(
    map: *const hash_map_def,
    key: *const u64,
    value: *const u64,
    flags: u64,
) -> i64 {
    let f: extern "C" fn(
        *const hash_map_def,
        *const core::ffi::c_void,
        *const core::ffi::c_void,
        u64,
    ) -> i64 = unsafe { core::mem::transmute(2usize) };
    f(
        map,
        key as *const core::ffi::c_void,
        value as *const core::ffi::c_void,
        flags,
    )
}

#[link_section = "tp/syscalls/sys_enter_getpgid"]
#[no_mangle]
extern "C" fn bpf_lookup_and_delete_test(_ctx: *const core::ffi::c_void) -> i32 {
    // C: if (set_pid == bpf_get_current_pid_tgid() >> 32) — set_pid (__u32)
    // is promoted to __u64 for the comparison.
    let pid = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(set_pid)) };
    if pid as u64 == bpf_get_current_pid_tgid() >> 32 {
        bpf_map_update_elem(
            &hash_map,
            core::ptr::addr_of!(set_key),
            core::ptr::addr_of!(set_value),
            BPF_NOEXIST,
        );
    }

    0
}

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
