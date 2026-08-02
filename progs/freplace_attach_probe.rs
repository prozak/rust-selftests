#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/freplace_attach_probe.c,
// bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_map_lookup_elem, bpf_spin_lock, bpf_spin_unlock};
use bpf_rs_core::maps::{self, BpfMap};

const VAR_NUM: usize = 2;

// struct bpf_spin_lock { __u32 val; };  -- matched by BTF struct name.
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct hmap_elem {
    lock: bpf_spin_lock,
    var: [i32; VAR_NUM],
}

#[link_section = ".maps"]
#[no_mangle]
static hash_map: BpfMap<u32, hmap_elem, { maps::HASH }, 1> = BpfMap::new();

#[link_section = "freplace/handle_kprobe"]
#[no_mangle]
extern "C" fn new_handle_kprobe(_ctx: *const core::ffi::c_void) -> i32 {
    let key: u32 = 0;

    let val = bpf_map_lookup_elem(&hash_map, &key) as *mut hmap_elem;
    if val.is_null() {
        return 1;
    }

    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*val).lock));
        (*val).var[0] = 99;
        bpf_spin_unlock(core::ptr::addr_of_mut!((*val).lock));
    }

    0
}

bpf_object!("GPL");
