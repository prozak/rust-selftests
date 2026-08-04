#![no_std]
#![no_main]

// Direct translation of
// tools/testing/selftests/bpf/progs/struct_ops_assoc_in_timer.c,
// bpf-rs-core idiom.
//
// The map value embeds struct bpf_timer: the kernel recognizes the field
// purely by the member's BTF struct name ("bpf_timer") and size (16), so
// the struct below must reach BTF with exactly that name and layout (see
// timer_start_delete_race.rs). struct bpf_testmod_multi_st_ops only needs
// the member this program initializes declared locally (struct_ops
// relocation matches by name, see test_global_map_resize.rs).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_map_lookup_elem, bpf_timer_init, bpf_timer_set_callback, bpf_timer_start,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;
use core::ffi::c_void;

const MAP_MAGIC: i32 = 1234;

#[repr(C)]
struct st_ops_args {
    a: u64,
}

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct elem {
    timer: bpf_timer,
}

#[link_section = ".maps"]
#[no_mangle]
static array_map: BpfMap<i32, elem, { maps::ARRAY }, 1> = BpfMap::new();

#[no_mangle]
static mut recur: i32 = 0;
#[no_mangle]
static mut test_err: i32 = 0;
#[no_mangle]
static mut timer_ns: i32 = 0;
#[no_mangle]
static mut timer_test_1_ret: i32 = 0;
#[no_mangle]
static mut timer_cb_run: i32 = 0;

extern "C" {
    fn bpf_kfunc_multi_st_ops_test_1_assoc(args: *mut st_ops_args) -> i32;
}

#[inline(never)]
extern "C" fn timer_cb(
    _map: *mut BpfMap<i32, elem, { maps::ARRAY }, 1>,
    _key: *mut i32,
    _timer: *mut bpf_timer,
) -> i64 {
    let mut args = st_ops_args { a: 0 };

    unsafe { recur += 1 };
    let ret = unsafe { bpf_kfunc_multi_st_ops_test_1_assoc(&mut args) };
    unsafe { timer_test_1_ret = ret };
    unsafe { recur -= 1 };

    unsafe { timer_cb_run += 1 };

    0
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn test_1(ctx: *const u64) -> i32 {
    let _args = arg(ctx, 0) as *mut st_ops_args;

    if unsafe { recur } == 0 {
        let key: i32 = 0;
        let timer = bpf_map_lookup_elem(&array_map, &key) as *mut bpf_timer;
        if timer.is_null() {
            return 0;
        }

        bpf_timer_init(timer, &array_map, 1);
        bpf_timer_set_callback(timer, timer_cb);
        let ns = unsafe { timer_ns };
        bpf_timer_start(timer, ns as u64, 0);
    }

    MAP_MAGIC
}

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn syscall_prog(_ctx: *mut c_void) -> i32 {
    let mut args = st_ops_args { a: 0 };
    let ret = unsafe { bpf_kfunc_multi_st_ops_test_1_assoc(&mut args) };
    if ret != MAP_MAGIC {
        unsafe { test_err += 1 };
    }
    0
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_testmod_multi_st_ops {
    test_1: extern "C" fn(*const u64) -> i32,
}
unsafe impl Sync for bpf_testmod_multi_st_ops {}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static st_ops_map: bpf_testmod_multi_st_ops = bpf_testmod_multi_st_ops { test_1 };

bpf_object!("GPL");
