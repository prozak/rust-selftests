#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/timer_crash.c
// (bpf-rs-core idiom).
//
// The map value embeds struct bpf_timer and struct bpf_spin_lock: the
// kernel recognizes both purely by the member's BTF struct name/size, so
// the structs below must reach BTF with exactly that name and layout
// (see timer_start_delete_race.rs / test_spin_lock.rs).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_current_task_btf, bpf_map_lookup_elem, bpf_map_update_elem, bpf_timer_cancel,
};
use bpf_rs_core::maps::{self, BpfMap};
use btf_macros::btf;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

// struct bpf_spin_lock { __u32 val; };
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct map_elem {
    timer: bpf_timer,
    lock: bpf_spin_lock,
    // (the 4 tail padding bytes after the 4-byte lock are zeroed
    // explicitly at each initialization site — see sys_enter; declaring
    // them as a field instead makes rustc lower the whole literal to a
    // memset, which this pipeline has no kfunc for)
}

#[btf]
struct task_struct {
    tgid: i32,
}

#[link_section = ".maps"]
#[no_mangle]
static amap: BpfMap<i32, map_elem, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static hmap: BpfMap<i32, map_elem, { maps::HASH }, 1> = BpfMap::new();

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut crash_map: i32 = 0; // 0 for amap, 1 for hmap

#[link_section = "fentry/do_nanosleep"]
#[no_mangle]
extern "C" fn sys_enter(_ctx: *const core::ffi::c_void) -> i32 {
    // C: `struct map_elem value = {}` — all 24 bytes (timer 16 + lock 4 +
    // 4 tail padding) are zeroed, and the whole value reaches the map.
    // Volatile word stores keep rustc from lowering this to a memset call,
    // which this pipeline has no kfunc for (clang emits plain stores too).
    let mut value: map_elem = unsafe { core::mem::MaybeUninit::uninit().assume_init() };
    unsafe {
        let w = core::ptr::addr_of_mut!(value) as *mut u64;
        core::ptr::write_volatile(w, 0);
        core::ptr::write_volatile(w.add(1), 0);
        core::ptr::write_volatile(w.add(2), 0);
    }

    let task = bpf_get_current_task_btf::<task_struct>();
    let tgid = unsafe { *(&*task).tgid().as_ptr() };
    if tgid != unsafe { pid } {
        return 0;
    }

    unsafe {
        *(core::ptr::addr_of_mut!(value) as *mut usize) = 0xdeadcaf3usize;
    }

    let key: i32 = 0;
    // C selects the map with a TRUTHINESS test — `crash_map ? &hmap : &amap`
    // — but gates the cancel on `crash_map == 1`. The two differ for any
    // other nonzero value, so they must be written separately.
    if unsafe { crash_map } != 0 {
        bpf_map_update_elem(&hmap, &key, &value, 0);
    } else {
        bpf_map_update_elem(&amap, &key, &value, 0);
    }
    if unsafe { crash_map } == 1 {
        let e = bpf_map_lookup_elem(&hmap, &key) as *mut map_elem;
        if e.is_null() {
            return 0;
        }
        unsafe {
            bpf_timer_cancel(core::ptr::addr_of_mut!((*e).timer));
        }
    }
    0
}

bpf_object!("GPL");
