#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/htab_update.c.
//
// The map value embeds struct bpf_timer: the kernel recognizes the field
// purely by the member's BTF struct name ("bpf_timer") and size (16), so
// the struct below must reach BTF with exactly that name and layout. The
// timer field is what routes a replace-update of the old element through
// bpf_obj_cancel_fields(), where the fentry program re-enters
// bpf_map_update_elem() and observes -EDEADLK.

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct val {
    t: bpf_timer,
    payload: u64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct htab_def {
    r#type: *const [i32; 1], // BPF_MAP_TYPE_HASH = 1
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

const BPF_ANY: u64 = 0;

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
extern "C" fn bpf_obj_cancel_fields(_ctx: *const core::ffi::c_void) -> i32 {
    let key: u32 = 0;
    let value = val {
        t: bpf_timer { __opaque: [0; 2] },
        payload: 1,
    };

    if (bpf_get_current_pid_tgid() >> 32) != unsafe { pid } as u64 {
        return 0;
    }

    unsafe { update_err = bpf_map_update_elem(&htab, &key, &value, BPF_ANY) as i32 };
    0
}

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
