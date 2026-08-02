#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_global_map_resize.c
// (bpf-rs-core idiom).
//
// prog_tests/global_map_resize.c resizes the trailing array in each of
// .bss / .data.custom via bpf_map__set_value_size before load, then relies
// on the BPF program summing every element up to a rodata-configured
// length (bss_array_len / data_array_len) set by userspace to match the
// resized array. Indexing beyond the compile-time [i32; 1] extent (after
// resize the real map is much larger) must go through raw pointer
// arithmetic, never the `[]` operator, since Rust's bounds check against
// the static length would be a reachable panic the verifier rejects.
//
// global_map_resize_invalid_subtest exercises .data.non_array (single
// non-array var) and .data.array_not_last (array not last) purely from
// userspace/libbpf BTF validation — the datasec shapes below just need to
// match the C source's var names/types/order; the BPF program itself never
// touches those two globals.
//
// version_sink is `long` in C -> isize (see bpf-rs-core map-value/global
// convention: btf_rename maps isize to "long", i64 to "long long", and the
// regenerated skeleton's format strings depend on getting this right).
//
// rustc emits DWARF/BTF globals (and lays out .bss/.data itself) in
// alphabetical-by-symbol-name order, not declaration order -- unlike clang,
// which preserves source order. So in this object "array" (not "sum" or
// "version_sink") ends up at the lowest .bss offset, and libbpf's
// bpf_map__set_value_size() datasec-resize (which requires the BTF
// datasec's *last* var to be an array) can't cleanly attribute the grown
// .bss bytes to "array" the way it does for the canonical clang build: it
// clears the .bss map's BTF instead (same as the invalid-shape cases this
// test itself exercises for .data.non_array/.data.array_not_last), and the
// resize test's userspace fill loop (`array[i] = 1` for i up to the full
// resized length) ends up overwriting every byte in the section, including
// whatever real memory "sum"/"version_sink" occupy. Accumulating into a
// local before writing `sum` exactly once, after the array read loop,
// keeps the program correct regardless: the loop only ever *reads* through
// "array" (matching the filled bytes, wherever they physically sit), and
// the single deferred write to "sum" can't be clobbered by, or clobber,
// those reads.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_get_smp_processor_id};
use core::ffi::c_void;

#[link_section = ".rodata"]
#[no_mangle]
static pid: i32 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static bss_array_len: u64 = 0;

#[link_section = ".rodata"]
#[no_mangle]
static data_array_len: u64 = 0;

#[no_mangle]
static mut sum: i32 = 0;

#[no_mangle]
static mut array: [i32; 1] = [0; 1];

#[link_section = ".data.custom"]
#[no_mangle]
static mut my_array: [i32; 1] = [0; 1];

// .data.non_array: single non-array var, must NOT be resizable.
#[link_section = ".data.non_array"]
#[no_mangle]
static mut my_int: i32 = 0;

// .data.array_not_last: last var is not an array, must NOT be resizable.
#[link_section = ".data.array_not_last"]
#[no_mangle]
static mut my_array_first: [i32; 1] = [0; 1];

#[link_section = ".data.array_not_last"]
#[no_mangle]
static mut my_int_last: i32 = 0;

#[link_section = ".data.percpu_arr"]
#[no_mangle]
static mut percpu_arr: [i32; 1] = [0; 1];

// C has `extern int LINUX_KERNEL_VERSION __kconfig;` here and stores it into
// version_sink on every run, purely to exercise a libbpf regression path
// (extern + datasec resize invalidating BTF type pointers) that no
// prog_tests assertion actually checks the value of. Unfixable in this
// idiom: rustc's `extern "C" { static X: T; }` produces a plain
// `@X = external global` LLVM global with no attached debug info (unlike
// clang, which emits a DIGlobalVariable(isDefinition: false) for
// `extern ... __kconfig`), so no BTF extern-linkage VAR is ever generated
// for it. Without that BTF, libbpf's static linker (bpftool gen object,
// part of skeleton regen) hard-fails with "failed to find BTF info for
// global/extern symbol" before the object can even be loaded. Dropped;
// version_sink stays a plain always-zero global (still required — it's a
// real global FUNC/OBJECT symbol in the C object's keep-list).
#[no_mangle]
static mut version_sink: isize = 0;

#[link_section = "tp/syscalls/sys_enter_getpid"]
#[no_mangle]
extern "C" fn bss_array_sum(_ctx: *const c_void) -> i32 {
    let want_pid = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(pid)) };
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    if want_pid != cur_pid {
        return 0;
    }

    // this will be zero, we just rely on verifier not rejecting this
    let cpu = bpf_get_smp_processor_id() as usize;
    let mut total = unsafe {
        core::ptr::read_volatile((core::ptr::addr_of_mut!(percpu_arr) as *const i32).add(cpu))
    };

    let n = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(bss_array_len)) };
    let mut i: u64 = 0;
    while i < n {
        let v = unsafe {
            core::ptr::read_volatile((core::ptr::addr_of_mut!(array) as *const i32).add(i as usize))
        };
        total += v;
        i += 1;
    }
    unsafe { sum = total };

    0
}

#[link_section = "tp/syscalls/sys_enter_getuid"]
#[no_mangle]
extern "C" fn data_array_sum(_ctx: *const c_void) -> i32 {
    let want_pid = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(pid)) };
    let cur_pid = (bpf_get_current_pid_tgid() >> 32) as i32;
    if want_pid != cur_pid {
        return 0;
    }

    // this will be zero, we just rely on verifier not rejecting this
    let cpu = bpf_get_smp_processor_id() as usize;
    let mut total = unsafe {
        core::ptr::read_volatile((core::ptr::addr_of_mut!(percpu_arr) as *const i32).add(cpu))
    };

    let n = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(data_array_len)) };
    let mut i: u64 = 0;
    while i < n {
        let v = unsafe {
            core::ptr::read_volatile(
                (core::ptr::addr_of_mut!(my_array) as *const i32).add(i as usize),
            )
        };
        total += v;
        i += 1;
    }
    unsafe { sum = total };

    0
}

#[link_section = "struct_ops/test_1"]
#[no_mangle]
extern "C" fn test_1(_ctx: *const u64) -> i32 {
    0
}

// struct bpf_testmod_ops (bpf_testmod.h): only the member this program
// initializes is declared — libbpf's struct_ops relocation matches local
// struct members against the kernel type by name (see bpf_tcp_nogpl.rs).
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_ops {
    test_1: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_testmod_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static st_ops_resize: bpf_testmod_ops = bpf_testmod_ops { test_1 };

bpf_object!("GPL");
