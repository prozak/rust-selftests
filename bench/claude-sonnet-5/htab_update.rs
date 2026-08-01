#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/htab_update.c.
//
// The map value embeds a `struct bpf_timer`, a BTF-managed field the
// kernel identifies by matching the member struct's BTF name, so it must
// be redeclared here with the exact UAPI name and layout.

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct val {
    t: bpf_timer,
    payload: u64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct htab_def {
    r#type: *const [i32; 1],  // BPF_MAP_TYPE_HASH = 1
    max_entries: *const [i32; 1],
    key: *const u32,
    value: *const val,
}
unsafe impl Sync for htab_def {}

#[link_section = ".maps"]
#[no_mangle]
static htab: htab_def = htab_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
};

#[no_mangle]
static mut pid: i32 = 0;

#[no_mangle]
static mut update_err: i32 = 0;

#[inline(always)]
fn bpf_get_current_pid_tgid() -> u64 {
    let f: extern "C" fn() -> u64 = unsafe { core::mem::transmute(14usize) };
    f()
}

#[inline(always)]
fn bpf_map_update_elem<K, V>(map: *const htab_def, key: &K, value: &V, flags: u64) -> i64 {
    let f: extern "C" fn(
        *const htab_def,
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

#[link_section = "?fentry/bpf_obj_cancel_fields"]
#[no_mangle]
extern "C" fn bpf_obj_cancel_fields(_ctx: *const u64) -> i32 {
    let key: u32 = 0;
    let value = val {
        t: bpf_timer { __opaque: [0; 2] },
        payload: 1,
    };

    if (bpf_get_current_pid_tgid() >> 32) != unsafe { pid } as u64 {
        return 0;
    }

    let err = bpf_map_update_elem(&htab, &key, &value, 0 /* BPF_ANY */);
    unsafe {
        update_err = err as i32;
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
