#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/htab_update.c.
//
// The interesting part here is the map value type: it embeds a
// `struct bpf_timer`, which the kernel discovers purely by BTF *name* when it
// parses the map's special ("BTF-managed") fields. So `bpf_timer` must appear
// in our BTF as a 16-byte struct named exactly "bpf_timer" — same shape as the
// UAPI definition (`__u64 __opaque[2]`, 8-byte aligned).
//
// prog_tests/htab_update.c enables autoload of the (`?`-prefixed, i.e.
// autoload-off) fentry program, sets `pid`, then does two userspace updates of
// key 0. The second one replaces the existing element, so the htab code path
// cancels the BTF fields of the old value via bpf_obj_cancel_fields() — where
// this program runs and re-enters bpf_map_update_elem(), which must report
// -EDEADLK in `update_err`.

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
fn bpf_map_update_elem<K, V>(map: *const htab_def, key: *const K, value: *const V, flags: u64) -> i64 {
    let f: extern "C" fn(
        *const htab_def,
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

#[link_section = "?fentry/bpf_obj_cancel_fields"]
#[no_mangle]
extern "C" fn bpf_obj_cancel_fields(_ctx: *const core::ffi::c_void) -> i32 {
    let key: u32 = 0;
    let value = val {
        t: bpf_timer { __opaque: [0, 0] },
        payload: 1,
    };

    unsafe {
        // C: (bpf_get_current_pid_tgid() >> 32) != pid  — `pid` (int) is
        // converted to __u64 with sign extension before the comparison.
        if (bpf_get_current_pid_tgid() >> 32) != pid as i64 as u64 {
            return 0;
        }

        // C assigns the long helper return to an int; truncate the same way.
        update_err = bpf_map_update_elem(&htab, &key, &value, BPF_ANY) as i32;
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
