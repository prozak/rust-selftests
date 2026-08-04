#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_map_lock.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{
    bpf_get_prandom_u32, bpf_map_lookup_elem, bpf_spin_lock, bpf_spin_unlock,
};
use bpf_rs_core::maps::{self, BpfMap};

const VAR_NUM: usize = 16;

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

#[allow(non_camel_case_types)]
#[repr(C)]
struct array_elem {
    lock: bpf_spin_lock,
    var: [i32; VAR_NUM],
}

#[link_section = ".maps"]
#[no_mangle]
static hash_map: BpfMap<u32, hmap_elem, { maps::HASH }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static array_map: BpfMap<i32, array_elem, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "cgroup/skb"]
#[no_mangle]
extern "C" fn bpf_map_lock_test(_skb: *const __sk_buff) -> i32 {
    let rnd = bpf_get_prandom_u32() as i32;
    let key: u32 = 0;
    let mut err: i32 = 1;

    let val = bpf_map_lookup_elem(&hash_map, &key) as *mut hmap_elem;
    if val.is_null() {
        return err;
    }
    // spin_lock in hash map
    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*val).lock));
        for i in 0..VAR_NUM {
            (*val).var[i] = rnd;
        }
        bpf_spin_unlock(core::ptr::addr_of_mut!((*val).lock));
    }

    // spin_lock in array
    let akey: i32 = 0;
    let q = bpf_map_lookup_elem(&array_map, &akey) as *mut array_elem;
    if q.is_null() {
        return err;
    }
    unsafe {
        bpf_spin_lock(core::ptr::addr_of_mut!((*q).lock));
        for i in 0..VAR_NUM {
            (*q).var[i] = rnd;
        }
        bpf_spin_unlock(core::ptr::addr_of_mut!((*q).lock));
    }
    err = 0;

    err
}

bpf_object!("GPL");
