#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/test_lookup_and_delete.c.
//
// Establishes two idioms for the rust2bpf pipeline:
//
// 1. BPF map definitions. libbpf reads map definitions purely from BTF: a
//    VAR in DATASEC ".maps" whose struct members encode parameters as
//    pointer types (`__uint(type, V)` in C is `int (*type)[V]`, `__type(key,
//    T)` is `T *key`). The Rust struct below produces identical BTF via
//    debuginfo; the section bytes themselves (nulls) are never read.
//
// 2. Helper calls. Like C's bpf_helpers.h, a call through a function
//    pointer whose value is the constant helper ID; LLVM folds it into the
//    direct BPF helper-call instruction.

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
fn bpf_map_update_elem<K, V>(map: *const hash_map_def, key: &K, value: &V, flags: u64) -> i64 {
    let f: extern "C" fn(
        *const hash_map_def,
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

#[link_section = "tp/syscalls/sys_enter_getpgid"]
#[no_mangle]
extern "C" fn bpf_lookup_and_delete_test(_ctx: *const core::ffi::c_void) -> i32 {
    unsafe {
        if set_pid as u64 == bpf_get_current_pid_tgid() >> 32 {
            bpf_map_update_elem(&hash_map, &set_key, &set_value, BPF_NOEXIST);
        }
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
