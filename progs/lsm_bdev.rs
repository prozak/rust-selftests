#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/lsm_bdev.c

use core::ffi::c_void;

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_copy_from_user, bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_update_elem,
    sync_fetch_and_add_u32,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;
use btf_macros::btf;

const BPF_NOEXIST: u64 = 1;

// enum lsm_integrity_type (include/linux/blk_types.h)
const LSM_INT_DMVERITY_SIG_VALID: i32 = 0;
const LSM_INT_DMVERITY_ROOTHASH: i32 = 1;

#[btf]
struct block_device {
    bd_dev: u32,
}

#[repr(C)]
struct verity_info {
    has_roothash: u8,
    sig_valid: u8,
    setintegrity_cnt: u32,
}

#[link_section = ".maps"]
#[no_mangle]
static verity_devices: BpfMap<u32, verity_info, { maps::HASH }, 64> = BpfMap::new();

#[no_mangle]
static mut alloc_count: i32 = 0;

#[link_section = "lsm.s/bdev_setintegrity"]
#[no_mangle]
extern "C" fn bdev_setintegrity(ctx: *const u64) -> i32 {
    let bdev = arg(ctx, 0) as *const block_device;
    let ty = arg(ctx, 1) as i32;
    let value = arg(ctx, 2) as *const c_void;

    let mut buf: u8 = 0;
    bpf_copy_from_user(
        &mut buf as *mut u8 as *mut c_void,
        1,
        core::ptr::null(),
    );

    let dev = unsafe { *(&*bdev).bd_dev().as_ptr() };

    let zero = verity_info {
        has_roothash: 0,
        sig_valid: 0,
        setintegrity_cnt: 0,
    };
    let mut info = bpf_map_lookup_elem(&verity_devices, &dev) as *mut verity_info;
    if info.is_null() {
        bpf_map_update_elem(&verity_devices, &dev, &zero, BPF_NOEXIST);
        info = bpf_map_lookup_elem(&verity_devices, &dev) as *mut verity_info;
        if info.is_null() {
            return 0;
        }
    }

    if ty == LSM_INT_DMVERITY_ROOTHASH {
        unsafe { (*info).has_roothash = 1 };
    } else if ty == LSM_INT_DMVERITY_SIG_VALID {
        unsafe { (*info).sig_valid = (!value.is_null()) as u8 };
    }

    sync_fetch_and_add_u32(
        unsafe { core::ptr::addr_of_mut!((*info).setintegrity_cnt) },
        1,
    );

    0
}

#[link_section = "lsm/bdev_free_security"]
#[no_mangle]
extern "C" fn bdev_free_security(ctx: *const u64) -> i32 {
    let bdev = arg(ctx, 0) as *const block_device;
    let dev = unsafe { *(&*bdev).bd_dev().as_ptr() };

    bpf_map_delete_elem(&verity_devices, &dev);
    0
}

#[link_section = "lsm.s/bdev_alloc_security"]
#[no_mangle]
extern "C" fn bdev_alloc_security(ctx: *const u64) -> i32 {
    let _bdev = arg(ctx, 0);

    let mut buf: u8 = 0;
    bpf_copy_from_user(
        &mut buf as *mut u8 as *mut c_void,
        1,
        core::ptr::null(),
    );

    sync_fetch_and_add_u32(core::ptr::addr_of_mut!(alloc_count) as *mut u32, 1);

    0
}

bpf_object!("GPL");
