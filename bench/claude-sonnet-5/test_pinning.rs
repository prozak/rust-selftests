#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_pinning.c.
//
// No BPF programs, just three map defs exercising libbpf's pinning logic:
// pinmap is LIBBPF_PIN_BY_NAME (1), nopinmap has no pinning attr (defaults
// to LIBBPF_PIN_NONE = 0), nopinmap2 sets LIBBPF_PIN_NONE explicitly.

#[allow(non_camel_case_types)]
#[repr(C)]
struct pinmap_def {
    r#type: *const [i32; 2],   // BPF_MAP_TYPE_ARRAY = 2
    max_entries: *const [i32; 1],
    key: *const u32,
    value: *const u64,
    pinning: *const [i32; 1], // LIBBPF_PIN_BY_NAME = 1
}
unsafe impl Sync for pinmap_def {}

#[link_section = ".maps"]
#[no_mangle]
static pinmap: pinmap_def = pinmap_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    pinning: core::ptr::null(),
};

#[allow(non_camel_case_types)]
#[repr(C)]
struct nopinmap_def {
    r#type: *const [i32; 1], // BPF_MAP_TYPE_HASH = 1
    max_entries: *const [i32; 1],
    key: *const u32,
    value: *const u64,
}
unsafe impl Sync for nopinmap_def {}

#[link_section = ".maps"]
#[no_mangle]
static nopinmap: nopinmap_def = nopinmap_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
};

#[allow(non_camel_case_types)]
#[repr(C)]
struct nopinmap2_def {
    r#type: *const [i32; 1], // BPF_MAP_TYPE_HASH = 1
    max_entries: *const [i32; 1],
    key: *const u32,
    value: *const u64,
    pinning: *const [i32; 0], // LIBBPF_PIN_NONE = 0
}
unsafe impl Sync for nopinmap2_def {}

#[link_section = ".maps"]
#[no_mangle]
static nopinmap2: nopinmap2_def = nopinmap2_def {
    r#type: core::ptr::null(),
    max_entries: core::ptr::null(),
    key: core::ptr::null(),
    value: core::ptr::null(),
    pinning: core::ptr::null(),
};

#[link_section = "license"]
#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
