// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/cpumask_success.c
// (bpf-next-x86), bpf-rs-core idiom.
//
// The __kptr fields (the bss globals, their arrays and nested structs, and
// the map value) are declared as plain pointers here and get their
// BTF_KIND_TYPE_TAG from the btf_type_tags! declaration at the bottom, which
// scripts/btf_type_tags.py applies to the built object.
//
// One thing still differs from the C, noted where it occurs:
// bpf_cpumask_equal/bpf_cpumask_intersects are not called directly.
// CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS is the C's weak `__kconfig` bool
// (`// BTF_KCONFIG:` below, scripts/ksym_vars.py mirrors the C object's
// declaration); clang tests it as `w != 0`, so the Rust compares `!= 0`.

use core::ffi::c_void;
use core::ptr::addr_of_mut;

use bpf_rs_core::helpers::{
    bpf_get_current_pid_tgid, bpf_kptr_xchg, bpf_map_lookup_elem, bpf_map_update_elem,
    bpf_trace_printk,
};
use bpf_rs_core::{bpf_object, btf_type_tags};
use bpf_rs_core::maps::{self, BpfMap};

const ENOENT: i32 = 2;
const EACCES: i32 = 13;
const EINVAL: i32 = 22;
const EEXIST: i32 = 17;
const CPUMASK_TEST_MASKLEN: usize = 16; // sizeof(cpumask_t) with the pinned config's NR_CPUS=128
const CPUMASK_KPTR_FIELDS_MAX: usize = 11;

struct bpf_cpumask;
struct cpumask;

extern "C" {
    fn bpf_cpumask_create() -> *mut bpf_cpumask;
    fn bpf_cpumask_release(cpumask: *mut bpf_cpumask);
    fn bpf_cpumask_first(cpumask: *const cpumask) -> u32;
    fn bpf_cpumask_first_zero(cpumask: *const cpumask) -> u32;
    fn bpf_cpumask_first_and(src1: *const cpumask, src2: *const cpumask) -> u32;
    fn bpf_cpumask_set_cpu(cpu: u32, cpumask: *mut bpf_cpumask);
    fn bpf_cpumask_clear_cpu(cpu: u32, cpumask: *mut bpf_cpumask);
    fn bpf_cpumask_test_cpu(cpu: u32, cpumask: *const cpumask) -> bool;
    fn bpf_cpumask_test_and_set_cpu(cpu: u32, cpumask: *mut bpf_cpumask) -> bool;
    fn bpf_cpumask_test_and_clear_cpu(cpu: u32, cpumask: *mut bpf_cpumask) -> bool;
    fn bpf_cpumask_setall(cpumask: *mut bpf_cpumask);
    fn bpf_cpumask_clear(cpumask: *mut bpf_cpumask);
    fn bpf_cpumask_and(dst: *mut bpf_cpumask, src1: *const cpumask, src2: *const cpumask) -> bool;
    fn bpf_cpumask_or(dst: *mut bpf_cpumask, src1: *const cpumask, src2: *const cpumask);
    fn bpf_cpumask_xor(dst: *mut bpf_cpumask, src1: *const cpumask, src2: *const cpumask);
    fn bpf_cpumask_subset(src1: *const cpumask, src2: *const cpumask) -> bool;
    fn bpf_cpumask_empty(cpumask: *const cpumask) -> bool;
    fn bpf_cpumask_full(cpumask: *const cpumask) -> bool;
    fn bpf_cpumask_copy(dst: *mut bpf_cpumask, src: *const cpumask);
    fn bpf_cpumask_any_distribute(src: *const cpumask) -> u32;
    fn bpf_cpumask_any_and_distribute(src1: *const cpumask, src2: *const cpumask) -> u32;
    fn bpf_cpumask_weight(cpumask: *const cpumask) -> u32;
    fn bpf_cpumask_populate(cpumask: *mut bpf_cpumask, src: *mut c_void, src_sz: usize) -> i32;

    fn bpf_rcu_read_lock();
    fn bpf_rcu_read_unlock();

    fn bpf_iter_num_new(it: *mut bpf_iter_num, start: i32, end: i32) -> i32;
    fn bpf_iter_num_next(it: *mut bpf_iter_num) -> *mut i32;
    fn bpf_iter_num_destroy(it: *mut bpf_iter_num);
}

#[repr(C)]
struct bpf_iter_num {
    __opaque: [u64; 1],
}

#[repr(C)]
struct kptr_nested {
    mask: *mut bpf_cpumask,
}

#[repr(C)]
struct kptr_nested_pair {
    mask_1: *mut bpf_cpumask,
    mask_2: *mut bpf_cpumask,
}

#[repr(C)]
struct kptr_nested_mid {
    dummy: i32,
    m: kptr_nested,
}

#[repr(C)]
struct kptr_nested_deep {
    ptrs: [kptr_nested_mid; 2],
    ptr_pairs: [kptr_nested_pair; 3],
}

#[repr(C)]
struct kptr_nested_deep_array_1_2 {
    dummy: i32,
    mask: [*mut bpf_cpumask; CPUMASK_KPTR_FIELDS_MAX],
}

#[repr(C)]
struct kptr_nested_deep_array_1_1 {
    dummy: i32,
    d_2: kptr_nested_deep_array_1_2,
}

#[repr(C)]
struct kptr_nested_deep_array_1 {
    dummy: i64,
    d_1: kptr_nested_deep_array_1_1,
}

#[repr(C)]
struct kptr_nested_deep_array_2_2 {
    dummy: [i64; 2],
    mask: *mut bpf_cpumask,
}

#[repr(C)]
struct kptr_nested_deep_array_2_1 {
    dummy: i32,
    d_2: [kptr_nested_deep_array_2_2; CPUMASK_KPTR_FIELDS_MAX],
}

#[repr(C)]
struct kptr_nested_deep_array_2 {
    dummy: i64,
    d_1: kptr_nested_deep_array_2_1,
}

#[repr(C)]
struct kptr_nested_deep_array_3_2 {
    dummy: [i64; 2],
    mask: *mut bpf_cpumask,
}

#[repr(C)]
struct kptr_nested_deep_array_3_1 {
    dummy: i32,
    d_2: kptr_nested_deep_array_3_2,
}

#[repr(C)]
struct kptr_nested_deep_array_3 {
    dummy: i64,
    d_1: [kptr_nested_deep_array_3_1; CPUMASK_KPTR_FIELDS_MAX],
}

// C: private(MASK) static ... -- file-local variables in their own
// .bss.<name> sections, so each section is a separate map.
#[link_section = ".bss.MASK"]
static mut global_mask: *mut bpf_cpumask = core::ptr::null_mut();
#[link_section = ".bss.MASK"]
static mut global_mask_array: [*mut bpf_cpumask; 2] = [core::ptr::null_mut(); 2];
#[link_section = ".bss.MASK"]
static mut global_mask_array_l2: [[*mut bpf_cpumask; 1]; 2] = [[core::ptr::null_mut(); 1]; 2];
#[link_section = ".bss.MASK"]
static mut global_mask_array_one: [*mut bpf_cpumask; 1] = [core::ptr::null_mut(); 1];
#[link_section = ".bss.MASK"]
static mut global_mask_nested: [kptr_nested; 2] = unsafe { core::mem::zeroed() };
#[link_section = ".bss.MASK_DEEP"]
static mut global_mask_nested_deep: kptr_nested_deep = unsafe { core::mem::zeroed() };
#[link_section = ".bss.MASK_1"]
static mut global_mask_nested_deep_array_1: kptr_nested_deep_array_1 =
    unsafe { core::mem::zeroed() };
#[link_section = ".bss.MASK_2"]
static mut global_mask_nested_deep_array_2: kptr_nested_deep_array_2 =
    unsafe { core::mem::zeroed() };
#[link_section = ".bss.MASK_3"]
static mut global_mask_nested_deep_array_3: kptr_nested_deep_array_3 =
    unsafe { core::mem::zeroed() };

#[repr(C)]
struct __cpumask_map_value {
    cpumask: *mut bpf_cpumask,
}

#[link_section = ".maps"]
#[no_mangle]
static __cpumask_map: BpfMap<i32, __cpumask_map_value, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut nr_cpus: i32 = 0;
#[no_mangle]
static mut err: i32 = 0;
#[no_mangle]
static mut bits: [u64; CPUMASK_TEST_MASKLEN / 8 + 1] = [0; CPUMASK_TEST_MASKLEN / 8 + 1];

#[inline(always)]
fn cast(m: *mut bpf_cpumask) -> *const cpumask {
    m as *const cpumask
}

/// The C calls bpf_cpumask_equal() and bpf_cpumask_intersects(). Both return
/// `bool` and, on x86-64, leave the upper bits of the return register
/// undefined. clang masks the result (`w0 &= 1`); rustc marks a `bool`
/// return `zeroext`, so llc tests the whole register and both calls read as
/// true. Until the pipeline masks kfunc returns, the two are expressed with
/// kfuncs whose results are not affected.
fn cpumask_equal(a: *mut bpf_cpumask, b: *mut bpf_cpumask) -> bool {
    unsafe { bpf_cpumask_subset(cast(a), cast(b)) && bpf_cpumask_subset(cast(b), cast(a)) }
}

fn cpumask_intersects(a: *mut bpf_cpumask, b: *mut bpf_cpumask) -> bool {
    let nc = unsafe { nr_cpus } as u32;
    (unsafe { bpf_cpumask_first_and(cast(a), cast(b)) }) < nc
}

fn is_test_task() -> bool {
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    unsafe { pid == cur_pid }
}

fn create_cpumask() -> *mut bpf_cpumask {
    let mask = unsafe { bpf_cpumask_create() };
    if mask.is_null() {
        unsafe {
            err = 1;
        }
        return core::ptr::null_mut();
    }
    if !unsafe { bpf_cpumask_empty(cast(mask)) } {
        unsafe {
            err = 2;
            bpf_cpumask_release(mask);
        }
        return core::ptr::null_mut();
    }
    mask
}

fn create_cpumask_set() -> Option<[*mut bpf_cpumask; 4]> {
    let mask1 = create_cpumask();
    if mask1.is_null() {
        return None;
    }
    let mask2 = create_cpumask();
    if mask2.is_null() {
        unsafe {
            bpf_cpumask_release(mask1);
            err = 3;
        }
        return None;
    }
    let mask3 = create_cpumask();
    if mask3.is_null() {
        unsafe {
            bpf_cpumask_release(mask1);
            bpf_cpumask_release(mask2);
            err = 4;
        }
        return None;
    }
    let mask4 = create_cpumask();
    if mask4.is_null() {
        unsafe {
            bpf_cpumask_release(mask1);
            bpf_cpumask_release(mask2);
            bpf_cpumask_release(mask3);
            err = 5;
        }
        return None;
    }
    Some([mask1, mask2, mask3, mask4])
}

fn cpumask_map_value_lookup() -> *mut __cpumask_map_value {
    let key: i32 = 0;
    bpf_map_lookup_elem(&__cpumask_map, &key).cast()
}

fn cpumask_map_insert(mask: *mut bpf_cpumask) -> i32 {
    let key: i32 = 0;
    let local = __cpumask_map_value {
        cpumask: core::ptr::null_mut(),
    };
    let status = bpf_map_update_elem(&__cpumask_map, &key, &local, 0);
    if status != 0 {
        unsafe {
            bpf_cpumask_release(mask);
        }
        return status as i32;
    }
    let v = cpumask_map_value_lookup();
    if v.is_null() {
        unsafe {
            bpf_cpumask_release(mask);
        }
        return -ENOENT;
    }
    let old = xchg(unsafe { addr_of_mut!((*v).cpumask) }, mask);
    if !old.is_null() {
        unsafe {
            bpf_cpumask_release(old);
        }
        return -EEXIST;
    }
    0
}

#[inline(always)]
fn xchg(dst: *mut *mut bpf_cpumask, val: *mut bpf_cpumask) -> *mut bpf_cpumask {
    bpf_kptr_xchg(dst.cast(), val.cast()).cast()
}

#[inline(always)]
fn global_mask_array_rcu(mask0: *mut *mut bpf_cpumask, mask1: *mut *mut bpf_cpumask) -> i32 {
    if !is_test_task() {
        return 0;
    }

    // Check if two kptrs in the array work and independently
    let mut local = create_cpumask();
    if local.is_null() {
        return 0;
    }

    unsafe {
        bpf_rcu_read_lock();

        'err_exit: {
            local = xchg(mask0, local);
            if !local.is_null() {
                err = 1;
                break 'err_exit;
            }

            // [<mask 0>, *]
            if (*mask0).is_null() {
                err = 2;
                break 'err_exit;
            }

            if mask1.is_null() {
                break 'err_exit;
            }

            // [*, NULL]
            if !(*mask1).is_null() {
                err = 3;
                break 'err_exit;
            }

            local = create_cpumask();
            if local.is_null() {
                err = 9;
                break 'err_exit;
            }

            local = xchg(mask1, local);
            if !local.is_null() {
                err = 10;
                break 'err_exit;
            }

            // [<mask 0>, <mask 1>]
            if (*mask0).is_null() || (*mask1).is_null() || *mask0 == *mask1 {
                err = 11;
                break 'err_exit;
            }
        }

        if !local.is_null() {
            bpf_cpumask_release(local);
        }
        bpf_rcu_read_unlock();
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_alloc_free_cpumask(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }
    let mask = create_cpumask();
    if mask.is_null() {
        return 0;
    }
    unsafe {
        bpf_cpumask_release(mask);
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_set_clear_cpu(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }
    let mask = create_cpumask();
    if mask.is_null() {
        return 0;
    }
    unsafe {
        bpf_cpumask_set_cpu(0, mask);
    }
    if !unsafe { bpf_cpumask_test_cpu(0, cast(mask)) } {
        unsafe {
            err = 3;
        }
    } else {
        unsafe {
            bpf_cpumask_clear_cpu(0, mask);
        }
        if unsafe { bpf_cpumask_test_cpu(0, cast(mask)) } {
            unsafe {
                err = 4;
            }
        }
    }
    unsafe {
        bpf_cpumask_release(mask);
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_setall_clear_cpu(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }
    let mask = create_cpumask();
    if mask.is_null() {
        return 0;
    }
    unsafe {
        bpf_cpumask_setall(mask);
    }
    if !unsafe { bpf_cpumask_full(cast(mask)) } {
        unsafe {
            err = 3;
        }
    } else {
        unsafe {
            bpf_cpumask_clear(mask);
        }
        if !unsafe { bpf_cpumask_empty(cast(mask)) } {
            unsafe {
                err = 4;
            }
        }
    }
    unsafe {
        bpf_cpumask_release(mask);
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_first_firstzero_cpu(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }
    let mask = create_cpumask();
    if mask.is_null() {
        return 0;
    }
    let nc = unsafe { nr_cpus } as u32;
    if unsafe { bpf_cpumask_first(cast(mask)) } < nc {
        unsafe {
            err = 3;
        }
    } else if unsafe { bpf_cpumask_first_zero(cast(mask)) } != 0 {
        unsafe {
            // C: bpf_printk("first zero: %d", bpf_cpumask_first_zero(...)).
            // The trace log is an observable, so the call belongs here even
            // though only `err` is checked from userspace — and the C calls
            // the kfunc a SECOND time to build the argument.
            static FMT: [u8; 16] = *b"first zero: %d  ";
            bpf_trace_printk(
                FMT.as_ptr() as *const c_void,
                15,
                bpf_cpumask_first_zero(cast(mask)) as u64,
                0,
                0,
            );
            err = 4;
        }
    } else {
        unsafe {
            bpf_cpumask_set_cpu(0, mask);
        }
        if unsafe { bpf_cpumask_first(cast(mask)) } != 0 {
            unsafe {
                err = 5;
            }
        } else if unsafe { bpf_cpumask_first_zero(cast(mask)) } != 1 {
            unsafe {
                err = 6;
            }
        }
    }
    unsafe {
        bpf_cpumask_release(mask);
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_firstand_nocpu(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }
    let mask1 = create_cpumask();
    if mask1.is_null() {
        return 0;
    }
    let mask2 = create_cpumask();
    if !mask2.is_null() {
        unsafe {
            bpf_cpumask_set_cpu(0, mask1);
            bpf_cpumask_set_cpu(1, mask2);
        }
        let first = unsafe { bpf_cpumask_first_and(cast(mask1), cast(mask2)) };
        if first <= 1 {
            unsafe {
                err = 3;
            }
        }
    }
    unsafe {
        if !mask1.is_null() {
            bpf_cpumask_release(mask1);
        }
        if !mask2.is_null() {
            bpf_cpumask_release(mask2);
        }
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_test_and_set_clear(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }
    let mask = create_cpumask();
    if mask.is_null() {
        return 0;
    }
    if unsafe { bpf_cpumask_test_and_set_cpu(0, mask) } {
        unsafe {
            err = 3;
        }
    } else if !unsafe { bpf_cpumask_test_and_set_cpu(0, mask) } {
        unsafe {
            err = 4;
        }
    } else if !unsafe { bpf_cpumask_test_and_clear_cpu(0, mask) } {
        unsafe {
            err = 5;
        }
    }
    unsafe {
        bpf_cpumask_release(mask);
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_and_or_xor(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }
    let [mask1, mask2, dst1, dst2] = match create_cpumask_set() {
        Some(s) => s,
        None => return 0,
    };
    unsafe {
        bpf_cpumask_set_cpu(0, mask1);
        bpf_cpumask_set_cpu(1, mask2);
    }
    if unsafe { bpf_cpumask_and(dst1, cast(mask1), cast(mask2)) } {
        unsafe {
            err = 6;
        }
    } else if !unsafe { bpf_cpumask_empty(cast(dst1)) } {
        unsafe {
            err = 7;
        }
    } else {
        unsafe {
            bpf_cpumask_or(dst1, cast(mask1), cast(mask2));
        }
        if !unsafe { bpf_cpumask_test_cpu(0, cast(dst1)) } {
            unsafe {
                err = 8;
            }
        } else if !unsafe { bpf_cpumask_test_cpu(1, cast(dst1)) } {
            unsafe {
                err = 9;
            }
        } else {
            unsafe {
                bpf_cpumask_xor(dst2, cast(mask1), cast(mask2));
            }
            if !cpumask_equal(dst1, dst2) {
                unsafe {
                    err = 10;
                }
            }
        }
    }
    unsafe {
        bpf_cpumask_release(mask1);
        bpf_cpumask_release(mask2);
        bpf_cpumask_release(dst1);
        bpf_cpumask_release(dst2);
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_intersects_subset(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }
    let [mask1, mask2, dst1, dst2] = match create_cpumask_set() {
        Some(s) => s,
        None => return 0,
    };
    unsafe {
        bpf_cpumask_set_cpu(0, mask1);
        bpf_cpumask_set_cpu(1, mask2);
    }
    if cpumask_intersects(mask1, mask2) {
        unsafe {
            err = 6;
        }
    } else {
        unsafe {
            bpf_cpumask_or(dst1, cast(mask1), cast(mask2));
        }
        if !unsafe { bpf_cpumask_subset(cast(mask1), cast(dst1)) } {
            unsafe {
                err = 7;
            }
        } else if !unsafe { bpf_cpumask_subset(cast(mask2), cast(dst1)) } {
            unsafe {
                err = 8;
            }
        } else if unsafe { bpf_cpumask_subset(cast(dst1), cast(mask1)) } {
            unsafe {
                err = 9;
            }
        }
    }
    unsafe {
        bpf_cpumask_release(mask1);
        bpf_cpumask_release(mask2);
        bpf_cpumask_release(dst1);
        bpf_cpumask_release(dst2);
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_copy_any_anyand(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }
    let [mask1, mask2, dst1, dst2] = match create_cpumask_set() {
        Some(s) => s,
        None => return 0,
    };
    unsafe {
        bpf_cpumask_set_cpu(0, mask1);
        bpf_cpumask_set_cpu(1, mask2);
        bpf_cpumask_or(dst1, cast(mask1), cast(mask2));
    }

    let nc = unsafe { nr_cpus };
    let mut cpu = unsafe { bpf_cpumask_any_distribute(cast(mask1)) } as i32;
    if cpu != 0 {
        unsafe {
            err = 6;
        }
    } else {
        cpu = unsafe { bpf_cpumask_any_distribute(cast(dst2)) } as i32;
        if cpu < nc {
            unsafe {
                err = 7;
            }
        } else {
            unsafe {
                bpf_cpumask_copy(dst2, cast(dst1));
            }
            if !cpumask_equal(dst1, dst2) {
                unsafe {
                    err = 8;
                }
            } else {
                cpu = unsafe { bpf_cpumask_any_distribute(cast(dst2)) } as i32;
                if cpu > 1 {
                    unsafe {
                        err = 9;
                    }
                } else {
                    cpu = unsafe { bpf_cpumask_any_and_distribute(cast(mask1), cast(mask2)) } as i32;
                    if cpu < nc {
                        unsafe {
                            err = 10;
                        }
                    }
                }
            }
        }
    }

    unsafe {
        bpf_cpumask_release(mask1);
        bpf_cpumask_release(mask2);
        bpf_cpumask_release(dst1);
        bpf_cpumask_release(dst2);
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_insert_leave(_ctx: *const u64) -> i32 {
    let mask = create_cpumask();
    if mask.is_null() {
        return 0;
    }
    if cpumask_map_insert(mask) != 0 {
        unsafe {
            err = 3;
        }
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_insert_remove_release(_ctx: *const u64) -> i32 {
    let mut mask = create_cpumask();
    if mask.is_null() {
        return 0;
    }
    if cpumask_map_insert(mask) != 0 {
        unsafe {
            err = 3;
        }
        return 0;
    }
    let v = cpumask_map_value_lookup();
    if v.is_null() {
        unsafe {
            err = 4;
        }
        return 0;
    }
    mask = xchg(unsafe { addr_of_mut!((*v).cpumask) }, core::ptr::null_mut());
    unsafe {
        if !mask.is_null() {
            bpf_cpumask_release(mask);
        } else {
            err = 5;
        }
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_global_mask_rcu(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }
    let mut local = create_cpumask();
    if local.is_null() {
        return 0;
    }
    unsafe {
        let prev = xchg(addr_of_mut!(global_mask), local);
        if !prev.is_null() {
            bpf_cpumask_release(prev);
            err = 3;
            return 0;
        }

        bpf_rcu_read_lock();
        local = global_mask;
        if local.is_null() {
            err = 4;
            bpf_rcu_read_unlock();
            return 0;
        }

        bpf_cpumask_test_cpu(0, cast(local));
        bpf_rcu_read_unlock();
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_global_mask_array_one_rcu(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }

    // Kptr arrays with one element are special cased, being treated
    // just like a single pointer.
    let mut local = create_cpumask();
    if local.is_null() {
        return 0;
    }
    unsafe {
        let prev = xchg(addr_of_mut!(global_mask_array_one[0]), local);
        if !prev.is_null() {
            bpf_cpumask_release(prev);
            err = 3;
            return 0;
        }

        bpf_rcu_read_lock();
        local = global_mask_array_one[0];
        if local.is_null() {
            err = 4;
            bpf_rcu_read_unlock();
            return 0;
        }

        bpf_rcu_read_unlock();
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_global_mask_array_rcu(_ctx: *const u64) -> i32 {
    unsafe {
        global_mask_array_rcu(
            addr_of_mut!(global_mask_array[0]),
            addr_of_mut!(global_mask_array[1]),
        )
    }
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_global_mask_array_l2_rcu(_ctx: *const u64) -> i32 {
    unsafe {
        global_mask_array_rcu(
            addr_of_mut!(global_mask_array_l2[0][0]),
            addr_of_mut!(global_mask_array_l2[1][0]),
        )
    }
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_global_mask_nested_rcu(_ctx: *const u64) -> i32 {
    unsafe {
        global_mask_array_rcu(
            addr_of_mut!(global_mask_nested[0].mask),
            addr_of_mut!(global_mask_nested[1].mask),
        )
    }
}

// Ensure that the field->offset has been correctly advanced from one
// nested struct or array sub-tree to another: bpf_kptr_xchg() is called on
// every kptr in both sub-trees of kptr_nested_deep, so the verifier rejects
// the program if any field->offset is wrong (see the C for the full note).
#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_global_mask_nested_deep_rcu(_ctx: *const u64) -> i32 {
    unsafe {
        let r = global_mask_array_rcu(
            addr_of_mut!(global_mask_nested_deep.ptrs[0].m.mask),
            addr_of_mut!(global_mask_nested_deep.ptrs[1].m.mask),
        );
        if r != 0 {
            return r;
        }

        let pairs = addr_of_mut!(global_mask_nested_deep.ptr_pairs) as *mut kptr_nested_pair;
        for i in 0..3 {
            let r = global_mask_array_rcu(
                addr_of_mut!((*pairs.add(i)).mask_1),
                addr_of_mut!((*pairs.add(i)).mask_2),
            );
            if r != 0 {
                return r;
            }
        }
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_global_mask_nested_deep_array_rcu(_ctx: *const u64) -> i32 {
    unsafe {
        let m1 = addr_of_mut!(global_mask_nested_deep_array_1.d_1.d_2.mask) as *mut *mut bpf_cpumask;
        for i in 0..CPUMASK_KPTR_FIELDS_MAX {
            global_mask_array_rcu(m1.add(i), core::ptr::null_mut());
        }

        let d2 = addr_of_mut!(global_mask_nested_deep_array_2.d_1.d_2)
            as *mut kptr_nested_deep_array_2_2;
        for i in 0..CPUMASK_KPTR_FIELDS_MAX {
            global_mask_array_rcu(addr_of_mut!((*d2.add(i)).mask), core::ptr::null_mut());
        }

        let d1 = addr_of_mut!(global_mask_nested_deep_array_3.d_1)
            as *mut kptr_nested_deep_array_3_1;
        for i in 0..CPUMASK_KPTR_FIELDS_MAX {
            global_mask_array_rcu(addr_of_mut!((*d1.add(i)).d_2.mask), core::ptr::null_mut());
        }
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_cpumask_weight(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }
    let local = create_cpumask();
    if local.is_null() {
        return 0;
    }
    if unsafe { bpf_cpumask_weight(cast(local)) } != 0 {
        unsafe {
            err = 3;
        }
    } else {
        unsafe {
            bpf_cpumask_set_cpu(0, local);
        }
        if unsafe { bpf_cpumask_weight(cast(local)) } != 1 {
            unsafe {
                err = 4;
            }
        } else {
            unsafe {
                bpf_cpumask_set_cpu(1, local);
            }
            if unsafe { bpf_cpumask_test_cpu(1, cast(local)) }
                && unsafe { bpf_cpumask_weight(cast(local)) } != 2
            {
                unsafe {
                    err = 5;
                }
            } else {
                unsafe {
                    bpf_cpumask_clear(local);
                }
                if unsafe { bpf_cpumask_weight(cast(local)) } != 0 {
                    unsafe {
                        err = 6;
                    }
                }
            }
        }
    }
    unsafe {
        bpf_cpumask_release(local);
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_refcount_null_tracking(_ctx: *const u64) -> i32 {
    let mask1 = unsafe { bpf_cpumask_create() };
    let mask2 = unsafe { bpf_cpumask_create() };
    if !mask1.is_null() && !mask2.is_null() {
        unsafe {
            bpf_cpumask_test_cpu(0, cast(mask1));
            bpf_cpumask_test_cpu(0, cast(mask2));
        }
    }
    unsafe {
        if !mask1.is_null() {
            bpf_cpumask_release(mask1);
        }
        if !mask2.is_null() {
            bpf_cpumask_release(mask2);
        }
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_populate_reject_small_mask(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }
    let local = create_cpumask();
    if local.is_null() {
        return 0;
    }
    let toofewbits: u8 = 0;
    let ret = unsafe {
        bpf_cpumask_populate(local, &toofewbits as *const u8 as *mut c_void, 1)
    };
    if ret != -EACCES {
        unsafe {
            err = 2;
        }
    }
    unsafe {
        bpf_cpumask_release(local);
    }
    0
}

// BTF_KCONFIG: CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
extern "C" {
    static CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS: u8;
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_populate_reject_unaligned(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }

    // Skip if unaligned accesses are fine for this arch.
    if unsafe { CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS } != 0 {
        return 0;
    }

    let mask = unsafe { bpf_cpumask_create() };
    if mask.is_null() {
        unsafe {
            err = 1;
        }
        return 0;
    }

    // Misalign the source array by a byte.
    let src = unsafe { (addr_of_mut!(bits) as *mut u8).add(1) };

    let ret = unsafe { bpf_cpumask_populate(mask, src as *mut c_void, CPUMASK_TEST_MASKLEN) };
    if ret != -EINVAL {
        unsafe {
            err = 2;
        }
    }

    unsafe {
        bpf_cpumask_release(mask);
    }
    0
}

#[link_section = "tp_btf/task_newtask"]
#[no_mangle]
extern "C" fn test_populate(_ctx: *const u64) -> i32 {
    if !is_test_task() {
        return 0;
    }

    unsafe {
        let p = addr_of_mut!(bits) as *mut u8;
        for i in 0..CPUMASK_TEST_MASKLEN {
            core::ptr::write_volatile(p.add(i), 0xaa);
        }
    }

    let mask = unsafe { bpf_cpumask_create() };
    if mask.is_null() {
        unsafe {
            err = 1;
        }
        return 0;
    }

    let ret = unsafe {
        bpf_cpumask_populate(
            mask,
            addr_of_mut!(bits) as *mut c_void,
            CPUMASK_TEST_MASKLEN,
        )
    };
    if ret != 0 {
        unsafe {
            err = 2;
        }
    } else {
        let nc = unsafe { nr_cpus };
        if nc < 0 || (nc as usize) > CPUMASK_TEST_MASKLEN * 8 {
            unsafe {
                err = 3;
            }
        } else {
            // C: bpf_for(i, 0, nr_cpus)
            let mut it = bpf_iter_num { __opaque: [0; 1] };
            unsafe {
                bpf_iter_num_new(&mut it, 0, nc);
                loop {
                    let t = bpf_iter_num_next(&mut it);
                    if t.is_null() {
                        break;
                    }
                    let i = *t;
                    if !(i >= 0 && i < nc) {
                        break;
                    }
                    // Odd-numbered bits should be set, even ones unset.
                    let bit = bpf_cpumask_test_cpu(i as u32, cast(mask));
                    if bit == (i % 2 != 0) {
                        continue;
                    }
                    err = 4;
                    break;
                }
                bpf_iter_num_destroy(&mut it);
            }
        }
    }

    unsafe {
        bpf_cpumask_release(mask);
    }
    0
}

btf_type_tags! {
    __cpumask_map_value.cpumask: kptr;
    global_mask: kptr;
    global_mask_array: kptr;
    global_mask_array_l2: kptr;
    global_mask_array_one: kptr;
    kptr_nested.mask: kptr;
    kptr_nested_pair.mask_1: kptr;
    kptr_nested_pair.mask_2: kptr;
    kptr_nested_deep_array_1_2.mask: kptr;
    kptr_nested_deep_array_2_2.mask: kptr;
    kptr_nested_deep_array_3_2.mask: kptr;
}

bpf_object!("GPL");
