#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/struct_ops_nulled_out_cb.c,
// bpf-rs-core idiom.
//
// prog_tests/test_struct_ops_module.c's test_struct_ops_nulled_out_cb() opens
// this object, nulls out skel->struct_ops.ops->test_1 via shadow vars before
// load (so libbpf disables autoload for test_1_turn_off), and asserts the
// load still succeeds with the program left un-autoloaded / no fd.

use bpf_rs_core::bpf_object;

#[link_section = "struct_ops/test_1"]
#[no_mangle]
extern "C" fn test_1_turn_off(_ctx: *const u64) -> i32 {
    // return arr[rand]; /* potentially way out of range access */
    unsafe {
        let idx = rand;
        *(core::ptr::addr_of!(arr) as *const i32).offset(idx as isize)
    }
}

#[no_mangle]
static mut rand: i32 = 0;

#[no_mangle]
static mut arr: [i32; 1] = [0];

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
static ops: bpf_testmod_ops = bpf_testmod_ops {
    test_1: test_1_turn_off,
};

bpf_object!("GPL");
