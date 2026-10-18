// SPDX-License-Identifier: GPL-2.0
#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/bpf_tcp_ops.c
// (bpf-rs-core idiom). Six struct_ops instances of the kernel's
// struct bpf_tcp_ops: three record the order their listen/connect callbacks
// run in (prog_tests/bpf_tcp_ops.c attaches them to a cgroup with
// BPF_F_PREORDER / BPF_F_BEFORE / BPF_F_AFTER and reads listen_order and
// connect_order back), three return distinct timeout_init values after
// saving what bpf_get_retval() saw from the previous one.
//
// The C initializes every instance from the full kernel struct and leaves
// the other members zero. Here each instance type carries only the members
// it sets: the order instances use `bpf_tcp_ops` itself, the retval
// instances the CO-RE flavor `bpf_tcp_ops___retval` (libbpf strips the
// `___suffix` to find the kernel type, struct_ops_module.rs does the same).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_retval;

const MAX_CGROUP_OPS: usize = 8;

/* Call order for listen and connect, indexed by call sequence */
#[no_mangle]
static mut listen_order: [u32; MAX_CGROUP_OPS] = [0; MAX_CGROUP_OPS];
#[no_mangle]
static mut listen_cnt: u32 = 0;

#[no_mangle]
static mut connect_order: [u32; MAX_CGROUP_OPS] = [0; MAX_CGROUP_OPS];
#[no_mangle]
static mut connect_cnt: u32 = 0;

#[inline(always)]
fn record_listen(id: i32) {
    unsafe {
        let idx = listen_cnt;

        if (idx as usize) < MAX_CGROUP_OPS {
            *core::ptr::addr_of_mut!(listen_order).cast::<u32>().add(idx as usize) = id as u32;
            listen_cnt = idx + 1;
        }
    }
}

#[inline(always)]
fn record_connect(id: i32) {
    unsafe {
        let idx = connect_cnt;

        if (idx as usize) < MAX_CGROUP_OPS {
            *core::ptr::addr_of_mut!(connect_order).cast::<u32>().add(idx as usize) = id as u32;
            connect_cnt = idx + 1;
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_tcp_ops {
    listen: extern "C" fn(*const u64),
    connect: extern "C" fn(*const u64),
}

unsafe impl Sync for bpf_tcp_ops {}

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_tcp_ops___retval {
    timeout_init: extern "C" fn(*const u64) -> i32,
}

unsafe impl Sync for bpf_tcp_ops___retval {}

/* struct_ops instance 1 */

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn tcp_ops1_listen(_ctx: *const u64) {
    record_listen(1);
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn tcp_ops1_connect(_ctx: *const u64) {
    record_connect(1);
}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static tcp_ops1: bpf_tcp_ops = bpf_tcp_ops {
    listen: tcp_ops1_listen,
    connect: tcp_ops1_connect,
};

/* struct_ops instance 2 */

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn tcp_ops2_listen(_ctx: *const u64) {
    record_listen(2);
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn tcp_ops2_connect(_ctx: *const u64) {
    record_connect(2);
}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static tcp_ops2: bpf_tcp_ops = bpf_tcp_ops {
    listen: tcp_ops2_listen,
    connect: tcp_ops2_connect,
};

/* struct_ops instance 3 */

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn tcp_ops3_listen(_ctx: *const u64) {
    record_listen(3);
}

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn tcp_ops3_connect(_ctx: *const u64) {
    record_connect(3);
}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static tcp_ops3: bpf_tcp_ops = bpf_tcp_ops {
    listen: tcp_ops3_listen,
    connect: tcp_ops3_connect,
};

const OPS_RETVAL1: i32 = 11;
const OPS_RETVAL2: i32 = 22;
const OPS_RETVAL3: i32 = 33;

#[no_mangle]
static mut retval_saw1: i32 = 0;
#[no_mangle]
static mut retval_saw2: i32 = 0;
#[no_mangle]
static mut retval_saw3: i32 = 0;

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn tcp_ops_retval1_timeout_init(_ctx: *const u64) -> i32 {
    unsafe { retval_saw1 = bpf_get_retval() };
    OPS_RETVAL1
}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static tcp_ops_retval1: bpf_tcp_ops___retval = bpf_tcp_ops___retval {
    timeout_init: tcp_ops_retval1_timeout_init,
};

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn tcp_ops_retval2_timeout_init(_ctx: *const u64) -> i32 {
    unsafe { retval_saw2 = bpf_get_retval() };
    OPS_RETVAL2
}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static tcp_ops_retval2: bpf_tcp_ops___retval = bpf_tcp_ops___retval {
    timeout_init: tcp_ops_retval2_timeout_init,
};

#[link_section = "struct_ops"]
#[no_mangle]
extern "C" fn tcp_ops_retval3_timeout_init(_ctx: *const u64) -> i32 {
    unsafe { retval_saw3 = bpf_get_retval() };
    OPS_RETVAL3
}

#[link_section = ".struct_ops.link"]
#[no_mangle]
static tcp_ops_retval3: bpf_tcp_ops___retval = bpf_tcp_ops___retval {
    timeout_init: tcp_ops_retval3_timeout_init,
};

bpf_object!("GPL");
