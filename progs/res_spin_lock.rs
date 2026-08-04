#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/res_spin_lock.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::ctx::__sk_buff;
use bpf_rs_core::helpers::{bpf_ktime_get_ns, bpf_map_lookup_elem};
use bpf_rs_core::maps::{self, BpfMap};

const EDEADLK: i32 = 35;
const ETIMEDOUT: i32 = 110;

// struct bpf_res_spin_lock { u32 val; }; -- matched by BTF struct name
// (kernel/bpf/btf.c: { BPF_RES_SPIN_LOCK, "bpf_res_spin_lock", true }).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_res_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct arr_elem {
    lock: bpf_res_spin_lock,
}

extern "C" {
    fn bpf_res_spin_lock(lock: *mut bpf_res_spin_lock) -> i32;
    fn bpf_res_spin_unlock(lock: *mut bpf_res_spin_lock);
}

#[link_section = ".maps"]
#[no_mangle]
static arrmap: BpfMap<i32, arr_elem, { maps::ARRAY }, 64> = BpfMap::new();

// C: `struct bpf_res_spin_lock lockA __hidden SEC(".data.A");` -- `__hidden`
// downgrades to BTF_VAR_STATIC via libbpf's STV_HIDDEN handling; a plain
// private (non-#[no_mangle]) `static mut` gets the same effective linkage
// without needing a per-item visibility attribute (see test_spin_lock.rs's
// lockA for the full rationale).
#[allow(non_upper_case_globals)]
#[link_section = ".data.A"]
static mut lockA: bpf_res_spin_lock = bpf_res_spin_lock { val: 0 };

#[allow(non_upper_case_globals)]
#[link_section = ".data.B"]
static mut lockB: bpf_res_spin_lock = bpf_res_spin_lock { val: 0 };

#[link_section = "tc"]
#[no_mangle]
extern "C" fn res_spin_lock_test(_ctx: *const __sk_buff) -> i32 {
    let key: i32 = 0;

    let elem1 = bpf_map_lookup_elem(&arrmap, &key) as *mut arr_elem;
    if elem1.is_null() {
        return -1;
    }
    let elem2 = bpf_map_lookup_elem(&arrmap, &key) as *mut arr_elem;
    if elem2.is_null() {
        return -1;
    }

    let r = unsafe { bpf_res_spin_lock(core::ptr::addr_of_mut!((*elem1).lock)) };
    if r != 0 {
        return r;
    }
    let r2 = unsafe { bpf_res_spin_lock(core::ptr::addr_of_mut!((*elem2).lock)) };
    if r2 == 0 {
        unsafe {
            bpf_res_spin_unlock(core::ptr::addr_of_mut!((*elem2).lock));
            bpf_res_spin_unlock(core::ptr::addr_of_mut!((*elem1).lock));
        }
        return -1;
    }
    unsafe {
        bpf_res_spin_unlock(core::ptr::addr_of_mut!((*elem1).lock));
    }
    (r2 != -EDEADLK) as i32
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn res_spin_lock_test_AB(_ctx: *const __sk_buff) -> i32 {
    let r = unsafe { bpf_res_spin_lock(core::ptr::addr_of_mut!(lockA)) };
    if r != 0 {
        return (r == 0) as i32;
    }
    // Only unlock if we took the lock.
    if unsafe { bpf_res_spin_lock(core::ptr::addr_of_mut!(lockB)) } == 0 {
        unsafe {
            bpf_res_spin_unlock(core::ptr::addr_of_mut!(lockB));
        }
    }
    unsafe {
        bpf_res_spin_unlock(core::ptr::addr_of_mut!(lockA));
    }
    0
}

#[no_mangle]
static mut err: i32 = 0;

#[link_section = "tc"]
#[no_mangle]
extern "C" fn res_spin_lock_test_BA(_ctx: *const __sk_buff) -> i32 {
    let r = unsafe { bpf_res_spin_lock(core::ptr::addr_of_mut!(lockB)) };
    if r != 0 {
        return (r == 0) as i32;
    }
    if unsafe { bpf_res_spin_lock(core::ptr::addr_of_mut!(lockA)) } == 0 {
        unsafe {
            bpf_res_spin_unlock(core::ptr::addr_of_mut!(lockA));
        }
    } else {
        unsafe {
            err = -EDEADLK;
        }
    }
    unsafe {
        bpf_res_spin_unlock(core::ptr::addr_of_mut!(lockB));
    }
    unsafe { err }
}

#[link_section = "tc"]
#[no_mangle]
extern "C" fn res_spin_lock_test_held_lock_max(_ctx: *const __sk_buff) -> i32 {
    let mut locks: [*mut bpf_res_spin_lock; 48] = [core::ptr::null_mut(); 48];
    let mut ret: i32 = 0;
    let mut i: i32 = 0;

    // RES_NR_HELD is assumed to be 31 (see the C source's _Static_assert).
    for idx in 0..34usize {
        let key: i32 = idx as i32;
        let e = bpf_map_lookup_elem(&arrmap, &key) as *mut arr_elem;
        if e.is_null() {
            return 1;
        }
        locks[idx] = unsafe { core::ptr::addr_of_mut!((*e).lock) };
    }

    for idx in 34..48usize {
        let key: i32 = idx as i32 - 2;
        let e = bpf_map_lookup_elem(&arrmap, &key) as *mut arr_elem;
        if e.is_null() {
            return 1;
        }
        locks[idx] = unsafe { core::ptr::addr_of_mut!((*e).lock) };
    }

    let time_beg = bpf_ktime_get_ns();

    'end: {
        while i < 34 {
            if unsafe { bpf_res_spin_lock(locks[i as usize]) } != 0 {
                break 'end;
            }
            i += 1;
        }

        // Trigger AA, after exhausting entries in the held lock table. This
        // time, only the timeout can save us, as AA detection won't
        // succeed.
        ret = unsafe { bpf_res_spin_lock(locks[34]) };
        if ret == 0 {
            unsafe {
                bpf_res_spin_unlock(locks[34]);
            }
            ret = 1;
            break 'end;
        }

        ret = if ret != -ETIMEDOUT { 2 } else { 0 };
    }

    i -= 1;
    while i >= 0 {
        unsafe {
            bpf_res_spin_unlock(locks[i as usize]);
        }
        i -= 1;
    }

    let time = bpf_ktime_get_ns().wrapping_sub(time_beg);
    // Time spent should be easily above our limit (1/4 s), since AA
    // detection won't be expedited due to lack of a held lock entry.
    if ret != 0 {
        ret
    } else if time > 1_000_000_000 / 4 {
        0
    } else {
        1
    }
}

bpf_object!("GPL");
