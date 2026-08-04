#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/test_verify_pkcs7_sig.c
// (bpf-rs-core idiom).

use bpf_rs_core::bpf_object;
use bpf_rs_core::helpers::{
    bpf_copy_from_user, bpf_dynptr_from_mem, bpf_get_current_pid_tgid, bpf_map_lookup_elem,
};
use bpf_rs_core::maps::{self, BpfMap};
use bpf_rs_core::progs::fentry_arg as arg;
use core::ffi::c_void;

const MAX_DATA_SIZE: u32 = 1024 * 1024;
const MAX_SIG_SIZE: u32 = 1024;

const EINVAL: i32 = -22;
const ENOENT: i32 = -2;
const EFAULT: i32 = -14;
// err.h's IS_ERR_VALUE floor: valid errno returns must be >= -MAX_ERRNO.
const MAX_ERRNO_NEG: i32 = -4095;

#[repr(C)]
struct Data {
    data: [u8; MAX_DATA_SIZE as usize],
    data_len: u32,
    sig: [u8; MAX_SIG_SIZE as usize],
    sig_len: u32,
}

#[repr(C, align(8))]
struct bpf_dynptr {
    opaque: [u64; 2],
}

// `value` sits at a fixed byte offset in the kernel's `union bpf_attr`
// (BPF_MAP_*_ELEM command member: map_fd u32 + pad + key u64, then value).
// #[btf] only emits STRUCT carriers, and CO-RE root-type matching requires
// the same kind (struct vs. union) as the target, so a #[btf]-declared
// `bpf_attr` can never match the real UNION type; hardcode the offset and
// read it off the raw trusted ctx-arg pointer instead (loading ctx[i] for a
// BTF-typed LSM/tracing argument makes the register PTR_TO_BTF_ID regardless
// of how the loaded value is subsequently cast, so this offset is validated
// against the real kernel BTF the same way a CO-RE-resolved load would be).
const BPF_ATTR_VALUE_OFFSET: usize = 16;

// Two call sites clamp a raw kfunc/helper return into the [-4095, 0] range
// the LSM hook's return value must satisfy. Sharing this via a genuine
// #[inline(never)] subprogram (rather than duplicating the same `if` in two
// places) keeps the verifier from tail-merging the two occurrences into one
// block reached from different call sites with different known bounds,
// which otherwise widens the merged range past what the exit check accepts.
#[inline(never)]
fn normalize_lsm_ret(mut ret: i32) -> i32 {
    if ret < MAX_ERRNO_NEG || ret > 0 {
        ret = EFAULT;
    }
    ret
}

extern "C" {
    fn bpf_lookup_user_key(serial: i32, flags: u64) -> *mut c_void;
    fn bpf_lookup_system_key(id: u64) -> *mut c_void;
    fn bpf_key_put(key: *mut c_void);
    fn bpf_verify_pkcs7_signature(
        data_ptr: *const c_void,
        sig_ptr: *const c_void,
        trusted_keyring: *mut c_void,
    ) -> i32;
}

#[no_mangle]
static mut monitored_pid: u32 = 0;
#[no_mangle]
static mut user_keyring_serial: i32 = 0;
#[no_mangle]
static mut system_keyring_id: u64 = 0;

#[link_section = ".maps"]
#[no_mangle]
static data_input: BpfMap<u32, Data, { maps::ARRAY }, 1> = BpfMap::new();

#[link_section = "lsm.s/bpf"]
#[no_mangle]
extern "C" fn bpf(ctx: *const u64) -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if pid != unsafe { monitored_pid } {
        return 0;
    }

    let data_val = bpf_map_lookup_elem(&data_input, &0u32) as *mut Data;
    if data_val.is_null() {
        return 0;
    }

    let attr_addr = arg(ctx, 1);
    let value: u64 =
        unsafe { *((attr_addr as *const u8).add(BPF_ATTR_VALUE_OFFSET) as *const u64) };

    let cfu_ret = bpf_copy_from_user(
        data_val as *mut c_void,
        core::mem::size_of::<Data>() as u32,
        value as *const c_void,
    );
    let ret: i32 = cfu_ret as i32;
    if ret != 0 {
        return normalize_lsm_ret(ret);
    }

    let data_len = unsafe { (*data_val).data_len };
    if data_len > MAX_DATA_SIZE {
        return EINVAL;
    }

    let mut data_ptr = bpf_dynptr { opaque: [0; 2] };
    unsafe {
        bpf_dynptr_from_mem(
            core::ptr::addr_of_mut!((*data_val).data) as *mut c_void,
            data_len as u64,
            0,
            &mut data_ptr as *mut bpf_dynptr as *mut c_void,
        );
    }

    let sig_len = unsafe { (*data_val).sig_len };
    if sig_len > MAX_SIG_SIZE {
        return EINVAL;
    }

    let mut sig_ptr = bpf_dynptr { opaque: [0; 2] };
    unsafe {
        bpf_dynptr_from_mem(
            core::ptr::addr_of_mut!((*data_val).sig) as *mut c_void,
            sig_len as u64,
            0,
            &mut sig_ptr as *mut bpf_dynptr as *mut c_void,
        );
    }

    let serial = unsafe { user_keyring_serial };
    let trusted_keyring = if serial != 0 {
        unsafe { bpf_lookup_user_key(serial, 0) }
    } else {
        unsafe { bpf_lookup_system_key(system_keyring_id) }
    };

    if trusted_keyring.is_null() {
        return ENOENT;
    }

    let vret = unsafe {
        bpf_verify_pkcs7_signature(
            &data_ptr as *const bpf_dynptr as *const c_void,
            &sig_ptr as *const bpf_dynptr as *const c_void,
            trusted_keyring,
        )
    };

    unsafe { bpf_key_put(trusted_keyring) };

    normalize_lsm_ret(vret)
}

bpf_object!("GPL");
