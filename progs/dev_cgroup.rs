#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/dev_cgroup.c
// (bpf-rs-core idiom). DEBUG tracing is not defined in the C build config,
// so that branch is omitted (matches the default #ifdef DEBUG being unset).

use bpf_rs_core::bpf_object;

// UAPI struct name is load-bearing: the kernel matches BTF struct types by
// name for the cgroup/dev ctx argument.
#[repr(C)]
pub struct bpf_cgroup_dev_ctx {
    pub access_type: u32,
    pub major: u32,
    pub minor: u32,
}

const BPF_DEVCG_DEV_CHAR: u32 = 2;

#[link_section = "cgroup/dev"]
#[no_mangle]
extern "C" fn bpf_prog1(ctx: *const bpf_cgroup_dev_ctx) -> i32 {
    let access_type = unsafe { (*ctx).access_type };
    let major = unsafe { (*ctx).major };
    let minor = unsafe { (*ctx).minor };
    let dev_type = access_type & 0xFFFF;

    // Allow access to /dev/null and /dev/urandom.
    // Forbid everything else.
    if major != 1 || dev_type != BPF_DEVCG_DEV_CHAR {
        return 0;
    }

    match minor {
        3 | 9 => 1,
        _ => 0,
    }
}

bpf_object!("GPL");
