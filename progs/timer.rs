#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/timer.c,
// bpf-rs-core idiom.
//
// struct bpf_timer is recognized by the kernel purely by BTF struct name
// ("bpf_timer") + size (16, aligned 8); several callbacks below take a
// `*mut bpf_timer` third argument directly (rather than the enclosing map
// value struct) because the timer field sits at offset 0 in every value
// struct that uses it here -- same trick the C source itself relies on.
//
// bpf_timer_set_callback is fully generic over the callback's own map/key/
// value parameter types (bpf-rs-core/src/helpers.rs); a single callback fn
// value forces one concrete Rust type for those parameters across every
// call site that passes it, even when (as with timer_cb1 on `array`+`lru`,
// or timer_cb2 on `hmap`+`hmap_malloc`) the C original sets the same
// callback on timers owned by two distinct map objects. This is sound
// because the kernel's timer-callback typecheck cares about the actual
// key/value BTF size at the call site's owning map, not our declared
// static Rust type of the (never-dereferenced) `map` parameter -- and here
// every pair of maps sharing a callback also shares the same key/value
// struct definition.

use bpf_rs_core::bpf_map;
use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_get_smp_processor_id, bpf_ktime_get_boot_ns, bpf_map_delete_elem, bpf_map_lookup_elem,
    bpf_map_update_elem, bpf_timer_cancel, bpf_timer_init, bpf_timer_set_callback,
    bpf_timer_start, bpf_trace_printk, sync_fetch_and_add_u64,
};
use bpf_rs_core::maps::{self, BpfMap};
use core::ffi::c_void;

const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_BOOTTIME: u64 = 7;

const ARRAY: i32 = 1;
const HTAB: i32 = 2;
const HTAB_MALLOC: i32 = 3;
const LRU: i32 = 4;

const BPF_ANY: u64 = 0;
const BPF_F_TIMER_ABS: u64 = 1;
const BPF_F_TIMER_CPU_PIN: u64 = 2;

const EINVAL: i64 = 22;
const EBUSY: i64 = 16;
const EDEADLK: i64 = 35;

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_spin_lock {
    val: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct hmap_elem {
    counter: i32,
    timer: bpf_timer,
    #[allow(dead_code)]
    lock: bpf_spin_lock, // unused
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct elem {
    #[allow(dead_code)]
    t: bpf_timer,
}

extern "C" {
    fn bpf_timer_cancel_async(timer: *mut bpf_timer) -> i32;
}

type HmapMap = BpfMap<i32, hmap_elem, { maps::HASH }, 1000>;
type ArrayMap2 = BpfMap<i32, elem, { maps::ARRAY }, 2>;
type ArrayMap1 = BpfMap<i32, elem, { maps::ARRAY }, 1>;
type LruMap = BpfMap<i32, elem, { maps::LRU_HASH }, 4>;

#[link_section = ".maps"]
#[no_mangle]
static hmap: HmapMap = BpfMap::new();

bpf_map! {
    hmap_malloc {
        r#type: *const [i32; maps::HASH],
        map_flags: *const [i32; 1], // BPF_F_NO_PREALLOC
        max_entries: *const [i32; 1000],
        key: *const i32,
        value: *const hmap_elem,
    }
}

#[link_section = ".maps"]
#[no_mangle]
static array: ArrayMap2 = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static lru: LruMap = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static abs_timer: ArrayMap1 = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static soft_timer_pinned: ArrayMap1 = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static abs_timer_pinned: ArrayMap1 = BpfMap::new();

#[link_section = ".maps"]
#[no_mangle]
static race_array: ArrayMap1 = BpfMap::new();

#[no_mangle]
static mut bss_data: u64 = 0;
#[no_mangle]
static mut abs_data: u64 = 0;
#[no_mangle]
static mut err: u64 = 0;
#[no_mangle]
static mut ok: u64 = 0;
#[no_mangle]
static mut test_hits: u64 = 0;
#[no_mangle]
static mut update_hits: u64 = 0;
#[no_mangle]
static mut cancel_hits: u64 = 0;
#[no_mangle]
static mut callback_check: u64 = 52;
#[no_mangle]
static mut callback2_check: u64 = 52;
#[no_mangle]
static mut pinned_callback_check: u64 = 0;
#[no_mangle]
static mut pinned_cpu: i32 = 0;
#[no_mangle]
static mut async_cancel: bool = false;

fn elem_zero() -> elem {
    elem {
        t: bpf_timer { __opaque: [0, 0] },
    }
}

/// callback for array and lru timers
extern "C" fn timer_cb1(map: *mut ArrayMap2, key: *mut i32, timer: *mut bpf_timer) -> i64 {
    // increment bss variable twice: once via array timer callback, once
    // via lru timer callback.
    unsafe { bss_data += 5 };

    let k = unsafe { *key };
    if k == ARRAY {
        let lru_key: i32 = LRU;

        // rearm array timer to be called again in ~35 seconds
        if bpf_timer_start(timer, 1u64 << 35, 0) != 0 {
            unsafe { err |= 1 };
        }

        let lru_timer = bpf_map_lookup_elem(&lru, &lru_key) as *mut bpf_timer;
        if lru_timer.is_null() {
            return 0;
        }
        bpf_timer_set_callback(lru_timer, timer_cb1);
        if bpf_timer_start(lru_timer, 0, 0) != 0 {
            unsafe { err |= 2 };
        }
    } else if k == LRU {
        let mut i: i32 = LRU + 1;
        // for current LRU eviction algorithm this number should be larger
        // than ~ lru->max_entries * 2
        while i <= 100 {
            let lru_key = i;
            let init = elem_zero();

            // add more elements into lru map to push out current element
            // and force deletion of this timer
            bpf_map_update_elem(map, &lru_key, &init, 0);
            // look it up to bump it into active list
            bpf_map_lookup_elem(map, &lru_key);

            // keep adding until *key changes underneath, which means that
            // key/timer memory was reused
            if unsafe { *key } != LRU {
                break;
            }
            i += 1;
        }

        // check that the timer was removed
        if bpf_timer_cancel(timer) != -EINVAL {
            unsafe { err |= 4 };
        }
        unsafe { ok |= 1 };
    }
    0
}

#[link_section = "fentry/bpf_fentry_test1"]
#[no_mangle]
extern "C" fn test1(_ctx: *const u64) -> i32 {
    let mut array_key: i32 = ARRAY;
    let mut arr_timer = bpf_map_lookup_elem(&array, &array_key) as *mut bpf_timer;
    if arr_timer.is_null() {
        return 0;
    }
    bpf_timer_init(arr_timer, &array, CLOCK_MONOTONIC);

    let lru_key: i32 = LRU;
    let init = elem_zero();
    bpf_map_update_elem(&lru, &lru_key, &init, 0);
    let lru_timer = bpf_map_lookup_elem(&lru, &lru_key) as *mut bpf_timer;
    if lru_timer.is_null() {
        return 0;
    }
    bpf_timer_init(lru_timer, &lru, CLOCK_MONOTONIC);

    bpf_timer_set_callback(arr_timer, timer_cb1);
    bpf_timer_start(arr_timer, 0 /* call timer_cb1 asap */, 0);

    // init more timers to check that array destruction doesn't leak timer
    // memory.
    array_key = 0;
    arr_timer = bpf_map_lookup_elem(&array, &array_key) as *mut bpf_timer;
    if arr_timer.is_null() {
        return 0;
    }
    bpf_timer_init(arr_timer, &array, CLOCK_MONOTONIC);
    0
}

extern "C" fn timer_error(_map: *mut ArrayMap2, _key: *mut i32, _timer: *mut bpf_timer) -> i64 {
    unsafe { err = 42 };
    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_async_cancel_succeed(_ctx: *const c_void) -> i32 {
    let array_key: i32 = ARRAY;
    let arr_timer = bpf_map_lookup_elem(&array, &array_key) as *mut bpf_timer;
    if arr_timer.is_null() {
        return 0;
    }
    bpf_timer_init(arr_timer, &array, CLOCK_MONOTONIC);
    bpf_timer_set_callback(arr_timer, timer_error);
    bpf_timer_start(arr_timer, 100_000 /* 100us */, 0);
    unsafe { bpf_timer_cancel_async(arr_timer) };
    unsafe { ok = 7 };
    0
}

/// callback for prealloc and non-prealloc hashtab timers
extern "C" fn timer_cb2(map: *mut HmapMap, key: *mut i32, val: *mut hmap_elem) -> i64 {
    let k = unsafe { *key };
    if k == HTAB {
        unsafe { callback_check -= 1 };
    } else {
        unsafe { callback2_check -= 1 };
    }

    let mut rearm = false;
    if unsafe { (*val).counter } > 0 {
        unsafe { (*val).counter -= 1 };
        if unsafe { (*val).counter } != 0 {
            rearm = true;
        }
    }

    if rearm {
        // re-arm the timer again to execute after 1 usec
        let timer = unsafe { core::ptr::addr_of_mut!((*val).timer) };
        bpf_timer_start(timer, 1000, 0);
    } else if k == HTAB {
        let array_key: i32 = ARRAY;

        // cancel arr_timer otherwise bpf_fentry_test1 prog will stay alive
        // forever.
        let arr_timer = bpf_map_lookup_elem(&array, &array_key) as *mut bpf_timer;
        if arr_timer.is_null() {
            return 0;
        }
        if bpf_timer_cancel(arr_timer) != 1 {
            // bpf_timer_cancel should return 1 to indicate that arr_timer
            // was active at this time
            unsafe { err |= 8 };
        }

        let val_timer = unsafe { core::ptr::addr_of_mut!((*val).timer) };
        // try to cancel ourself. It shouldn't deadlock.
        if bpf_timer_cancel(val_timer) != -EDEADLK {
            unsafe { err |= 16 };
        }

        // delete this key and this timer anyway. It shouldn't deadlock
        // either.
        bpf_map_delete_elem(map, unsafe { &*key });

        // in preallocated hashmap both 'key' and 'val' could have been
        // reused to store another map element (like in LRU above), but in
        // controlled test environment the below test works. It's not a
        // use-after-free. The memory is owned by the map.
        if bpf_timer_start(val_timer, 1000, 0) != -EINVAL {
            unsafe { err |= 32 };
        }
        unsafe { ok |= 2 };
    } else {
        if k != HTAB_MALLOC {
            unsafe { err |= 64 };
        }

        let val_timer = unsafe { core::ptr::addr_of_mut!((*val).timer) };
        // try to cancel ourself. It shouldn't deadlock.
        if bpf_timer_cancel(val_timer) != -EDEADLK {
            unsafe { err |= 128 };
        }

        // delete this key and this timer anyway. It shouldn't deadlock
        // either.
        bpf_map_delete_elem(map, unsafe { &*key });

        unsafe { ok |= 4 };
    }
    0
}

#[no_mangle]
extern "C" fn bpf_timer_test() -> i32 {
    let key: i32 = HTAB;
    let key_malloc: i32 = HTAB_MALLOC;

    let val = bpf_map_lookup_elem(&hmap, &key) as *mut hmap_elem;
    if !val.is_null() {
        let timer = unsafe { core::ptr::addr_of_mut!((*val).timer) };
        if bpf_timer_init(timer, &hmap, CLOCK_BOOTTIME) != 0 {
            unsafe { err |= 512 };
        }
        bpf_timer_set_callback(timer, timer_cb2);
        bpf_timer_start(timer, 1000, 0);
    }

    let val_m = bpf_map_lookup_elem(&hmap_malloc, &key_malloc) as *mut hmap_elem;
    if !val_m.is_null() {
        let timer = unsafe { core::ptr::addr_of_mut!((*val_m).timer) };
        if bpf_timer_init(timer, &hmap_malloc, CLOCK_BOOTTIME) != 0 {
            unsafe { err |= 1024 };
        }
        bpf_timer_set_callback(timer, timer_cb2);
        bpf_timer_start(timer, 1000, 0);
    }
    0
}

#[link_section = "fentry/bpf_fentry_test2"]
#[no_mangle]
extern "C" fn test2(_ctx: *const u64) -> i32 {
    let init = hmap_elem {
        counter: 10, // number of times to trigger timer_cb2
        timer: bpf_timer { __opaque: [0, 0] },
        lock: bpf_spin_lock { val: 0 },
    };
    let mut key: i32 = HTAB;
    let mut key_malloc: i32 = HTAB_MALLOC;

    bpf_map_update_elem(&hmap, &key, &init, 0);
    let mut val = bpf_map_lookup_elem(&hmap, &key) as *mut hmap_elem;
    if !val.is_null() {
        let timer = unsafe { core::ptr::addr_of_mut!((*val).timer) };
        bpf_timer_init(timer, &hmap, CLOCK_BOOTTIME);
    }
    // update the same key to free the timer
    bpf_map_update_elem(&hmap, &key, &init, 0);

    bpf_map_update_elem(&hmap_malloc, &key_malloc, &init, 0);
    let mut val_m = bpf_map_lookup_elem(&hmap_malloc, &key_malloc) as *mut hmap_elem;
    if !val_m.is_null() {
        let timer = unsafe { core::ptr::addr_of_mut!((*val_m).timer) };
        bpf_timer_init(timer, &hmap_malloc, CLOCK_BOOTTIME);
    }
    // update the same key to free the timer
    bpf_map_update_elem(&hmap_malloc, &key_malloc, &init, 0);

    // init more timers to check that htab operations don't leak timer
    // memory.
    key = 0;
    bpf_map_update_elem(&hmap, &key, &init, 0);
    val = bpf_map_lookup_elem(&hmap, &key) as *mut hmap_elem;
    if !val.is_null() {
        let timer = unsafe { core::ptr::addr_of_mut!((*val).timer) };
        bpf_timer_init(timer, &hmap, CLOCK_BOOTTIME);
    }
    bpf_map_delete_elem(&hmap, &key);
    bpf_map_update_elem(&hmap, &key, &init, 0);
    val = bpf_map_lookup_elem(&hmap, &key) as *mut hmap_elem;
    if !val.is_null() {
        let timer = unsafe { core::ptr::addr_of_mut!((*val).timer) };
        bpf_timer_init(timer, &hmap, CLOCK_BOOTTIME);
    }

    // and with non-prealloc htab
    key_malloc = 0;
    bpf_map_update_elem(&hmap_malloc, &key_malloc, &init, 0);
    val_m = bpf_map_lookup_elem(&hmap_malloc, &key_malloc) as *mut hmap_elem;
    if !val_m.is_null() {
        let timer = unsafe { core::ptr::addr_of_mut!((*val_m).timer) };
        bpf_timer_init(timer, &hmap_malloc, CLOCK_BOOTTIME);
    }
    bpf_map_delete_elem(&hmap_malloc, &key_malloc);
    bpf_map_update_elem(&hmap_malloc, &key_malloc, &init, 0);
    val_m = bpf_map_lookup_elem(&hmap_malloc, &key_malloc) as *mut hmap_elem;
    if !val_m.is_null() {
        let timer = unsafe { core::ptr::addr_of_mut!((*val_m).timer) };
        bpf_timer_init(timer, &hmap_malloc, CLOCK_BOOTTIME);
    }

    bpf_timer_test()
}

/// callback for absolute timer
extern "C" fn timer_cb3(_map: *mut ArrayMap1, _key: *mut i32, timer: *mut bpf_timer) -> i64 {
    unsafe { abs_data += 6 };

    let now = bpf_ktime_get_boot_ns();
    if unsafe { abs_data } < 12 {
        bpf_timer_start(timer, now + 1000, BPF_F_TIMER_ABS);
    } else {
        // Re-arm timer ~35 seconds in future
        bpf_timer_start(timer, now + (1u64 << 35), BPF_F_TIMER_ABS);
    }
    0
}

#[link_section = "fentry/bpf_fentry_test3"]
#[no_mangle]
extern "C" fn test3(_ctx: *const u64) -> i32 {
    // C: bpf_printk("test3") — every C trace-log site must exist here too
    static FMT3: [u8; 6] = *b"test3\0";
    bpf_trace_printk(FMT3.as_ptr() as *const core::ffi::c_void, FMT3.len() as u32, 0, 0, 0);

    let key: i32 = 0;

    let timer = bpf_map_lookup_elem(&abs_timer, &key) as *mut bpf_timer;
    if !timer.is_null() {
        if bpf_timer_init(timer, &abs_timer, CLOCK_BOOTTIME) != 0 {
            unsafe { err |= 2048 };
        }
        bpf_timer_set_callback(timer, timer_cb3);
        bpf_timer_start(timer, bpf_ktime_get_boot_ns() + 1000, BPF_F_TIMER_ABS);
    }
    0
}

/// callback for pinned timer
extern "C" fn timer_cb_pinned(_map: *mut ArrayMap1, _key: *mut i32, _timer: *mut bpf_timer) -> i64 {
    let cpu = bpf_get_smp_processor_id() as i32;
    if cpu != unsafe { pinned_cpu } {
        unsafe { err |= 16384 };
    }
    unsafe { pinned_callback_check += 1 };
    0
}

fn test_pinned_timer(soft: bool) {
    let key: i32 = 0;
    let map: &ArrayMap1 = if soft {
        &soft_timer_pinned
    } else {
        &abs_timer_pinned
    };
    let start_time: u64 = if soft { 0 } else { bpf_ktime_get_boot_ns() };
    let mut flags: u64 = BPF_F_TIMER_CPU_PIN;
    if !soft {
        flags |= BPF_F_TIMER_ABS;
    }

    let timer = bpf_map_lookup_elem(map, &key) as *mut bpf_timer;
    if !timer.is_null() {
        if bpf_timer_init(timer, map, CLOCK_BOOTTIME) != 0 {
            unsafe { err |= 4096 };
        }
        bpf_timer_set_callback(timer, timer_cb_pinned);
        unsafe { pinned_cpu = bpf_get_smp_processor_id() as i32 };
        bpf_timer_start(timer, start_time + 1000, flags);
    } else {
        unsafe { err |= 8192 };
    }
}

#[link_section = "fentry/bpf_fentry_test4"]
#[no_mangle]
extern "C" fn test4(_ctx: *const u64) -> i32 {
    static FMT4: [u8; 6] = *b"test4\0";
    bpf_trace_printk(FMT4.as_ptr() as *const core::ffi::c_void, FMT4.len() as u32, 0, 0, 0);
    test_pinned_timer(true);
    0
}

#[link_section = "fentry/bpf_fentry_test5"]
#[no_mangle]
extern "C" fn test5(_ctx: *const u64) -> i32 {
    static FMT5: [u8; 6] = *b"test5\0";
    bpf_trace_printk(FMT5.as_ptr() as *const core::ffi::c_void, FMT5.len() as u32, 0, 0, 0);
    test_pinned_timer(false);
    0
}

extern "C" fn race_timer_callback(_map: *mut ArrayMap1, _key: *mut i32, timer: *mut bpf_timer) -> i64 {
    bpf_timer_start(timer, 1_000_000, 0);
    0
}

/// Callback that updates its own map element
extern "C" fn update_self_callback(map: *mut ArrayMap1, key: *mut i32, _timer: *mut bpf_timer) -> i64 {
    let init = elem_zero();
    bpf_map_update_elem(map, unsafe { &*key }, &init, BPF_ANY);
    unsafe { sync_fetch_and_add_u64(core::ptr::addr_of_mut!(update_hits), 1) };
    0
}

/// Callback that cancels itself using async cancel
extern "C" fn cancel_self_callback(_map: *mut ArrayMap1, _key: *mut i32, timer: *mut bpf_timer) -> i64 {
    unsafe { bpf_timer_cancel_async(timer) };
    unsafe { sync_fetch_and_add_u64(core::ptr::addr_of_mut!(cancel_hits), 1) };
    0
}

#[derive(Clone, Copy, PartialEq)]
enum TestMode {
    RaceSync,
    RaceAsync,
    Update,
    Cancel,
}

fn test_common(mode: TestMode) -> i32 {
    let key: i32 = 0;
    let init = elem_zero();

    bpf_map_update_elem(&race_array, &key, &init, BPF_ANY);
    let timer = bpf_map_lookup_elem(&race_array, &key) as *mut bpf_timer;
    if timer.is_null() {
        return 0;
    }

    let ret = bpf_timer_init(timer, &race_array, CLOCK_MONOTONIC);
    if ret != 0 && ret != -EBUSY {
        return 0;
    }

    match mode {
        TestMode::RaceSync | TestMode::RaceAsync => {
            bpf_timer_set_callback(timer, race_timer_callback);
        }
        TestMode::Update => {
            bpf_timer_set_callback(timer, update_self_callback);
        }
        TestMode::Cancel => {
            bpf_timer_set_callback(timer, cancel_self_callback);
        }
    }

    bpf_timer_start(timer, 0, 0);

    if mode == TestMode::RaceAsync {
        unsafe { bpf_timer_cancel_async(timer) };
    } else if mode == TestMode::RaceSync {
        bpf_timer_cancel(timer);
    }

    0
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn race(_ctx: *const c_void) -> i32 {
    let mode = if unsafe { async_cancel } {
        TestMode::RaceAsync
    } else {
        TestMode::RaceSync
    };
    test_common(mode)
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn nmi_race(_ctx: *const c_void) -> i32 {
    unsafe { sync_fetch_and_add_u64(core::ptr::addr_of_mut!(test_hits), 1) };
    test_common(TestMode::RaceAsync)
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn nmi_update(_ctx: *const c_void) -> i32 {
    unsafe { sync_fetch_and_add_u64(core::ptr::addr_of_mut!(test_hits), 1) };
    test_common(TestMode::Update)
}

#[link_section = "perf_event"]
#[no_mangle]
extern "C" fn nmi_cancel(_ctx: *const c_void) -> i32 {
    unsafe { sync_fetch_and_add_u64(core::ptr::addr_of_mut!(test_hits), 1) };
    test_common(TestMode::Cancel)
}

bpf_object!("GPL");
