#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_lookup_key.c
// (bpf-next), bpf-rs-core idiom.

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::bpf_get_current_pid_tgid;

const ENOENT: i32 = 2;

#[allow(non_camel_case_types)]
#[repr(C)]
struct bpf_key {
    _priv: [u8; 0],
}

extern "C" {
    fn bpf_lookup_user_key(serial: i32, flags: u64) -> *mut bpf_key;
    fn bpf_lookup_system_key(id: u64) -> *mut bpf_key;
    fn bpf_key_put(key: *mut bpf_key);
}

#[no_mangle]
static mut monitored_pid: u32 = 0;
#[no_mangle]
static mut key_serial: i32 = 0;
#[no_mangle]
static mut key_id: u32 = 0;
#[no_mangle]
static mut flags: u64 = 0;

#[link_section = "lsm.s/bpf"]
#[no_mangle]
extern "C" fn bpf(_ctx: *const u64) -> i32 {
    // int cmd, union bpf_attr *attr, unsigned int size, bool kernel
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { monitored_pid } {
        return 0;
    }

    let (serial, id, fl) = unsafe { (key_serial, key_id, flags) };
    let bkey = if serial != 0 {
        unsafe { bpf_lookup_user_key(serial, fl) }
    } else {
        unsafe { bpf_lookup_system_key(id as u64) }
    };

    if bkey.is_null() {
        return -ENOENT;
    }

    unsafe { bpf_key_put(bkey) };

    0
}

bpf_object!("GPL");
