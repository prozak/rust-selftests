#![no_std]
#![no_main]

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_map_lookup_elem;

// struct { __uint(type, ARRAY); __uint(key_size, sizeof(int));
// __uint(value_size, sizeof(struct ipv_counts)); __uint(max_entries, 4); }
// -- explicit key_size/value_size (not __type), so libbpf can't derive
// BTF key/value type IDs for this map (the "nokv" contract the userspace
// test checks for).
#[allow(non_camel_case_types)]
#[repr(C)]
struct btf_map_def {
    r#type: *const [i32; 2], // BPF_MAP_TYPE_ARRAY
    key_size: *const [i32; 4],
    value_size: *const [i32; 8], // sizeof(struct ipv_counts)
    max_entries: *const [i32; 4],
}
unsafe impl Sync for btf_map_def {}

#[link_section = ".maps"]
#[no_mangle]
static btf_map: btf_map_def = btf_map_def {
    r#type: core::ptr::null(),
    key_size: core::ptr::null(),
    value_size: core::ptr::null(),
    max_entries: core::ptr::null(),
};

#[repr(C)]
struct ipv_counts {
    v4: u32,
    v6: u32,
}

#[no_mangle]
#[inline(never)]
extern "C" fn test_long_fname_2() -> i32 {
    let key: i32 = 0;
    let counts = bpf_map_lookup_elem(&btf_map, &key) as *mut ipv_counts;
    if counts.is_null() {
        return 0;
    }

    unsafe {
        (*counts).v6 += 1;
    }

    0
}

#[no_mangle]
#[inline(never)]
extern "C" fn test_long_fname_1() -> i32 {
    test_long_fname_2()
}

#[link_section = "dummy_tracepoint"]
#[no_mangle]
extern "C" fn _dummy_tracepoint(_arg: *const core::ffi::c_void) -> i32 {
    test_long_fname_1()
}

bpf_object!("GPL");
