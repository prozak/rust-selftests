#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/htab_update.c,
// bpf-rs-core idiom.
//
// The map value embeds struct bpf_timer: the kernel recognizes the field
// purely by the member's BTF struct name ("bpf_timer") and size (16), so
// the struct below must reach BTF with exactly that name and layout. The
// timer field is what routes a replace-update of the old element through
// bpf_obj_cancel_fields(), where the fentry program re-enters
// bpf_map_update_elem() and observes -EDEADLK.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{bpf_get_current_pid_tgid, bpf_map_update_elem};
use bpf_rs_core::maps::{self, BpfMap};

// struct bpf_timer { __u64 __opaque[2]; } __attribute__((aligned(8)));
#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_timer {
    __opaque: [u64; 2],
}

#[allow(non_camel_case_types, dead_code)]
#[repr(C)]
struct val {
    t: bpf_timer,
    payload: u64,
}

#[link_section = ".maps"]
#[no_mangle]
static htab: BpfMap<u32, val, { maps::HASH }, 1> = BpfMap::new();

#[no_mangle]
static mut pid: i32 = 0;
#[no_mangle]
static mut update_err: i32 = 0;

const BPF_ANY: u64 = 0;

#[link_section = "?fentry/bpf_obj_cancel_fields"]
#[no_mangle]
extern "C" fn bpf_obj_cancel_fields(_ctx: *const core::ffi::c_void) -> i32 {
    let key: u32 = 0;
    let value = val {
        t: bpf_timer { __opaque: [0; 2] },
        payload: 1,
    };

    if (bpf_get_current_pid_tgid() >> 32) != unsafe { pid } as u64 {
        return 0;
    }

    unsafe { update_err = bpf_map_update_elem(&htab, &key, &value, BPF_ANY) as i32 };
    0
}

bpf_object!("GPL");
