#![no_std]
#![no_main]

// Direct translation of tools/testing/selftests/bpf/progs/btf_type_tag_user.c
// bpf-rs-core idiom.
//
// prog_tests/btf_tag.c loads this skeleton expecting the load to FAIL
// (ASSERT_ERR): the traced functions' real kernel/module BTF tags the
// dereferenced pointer argument as __user, and the verifier rejects any
// direct (non bpf_probe_read_user) access to it. That tag lives on the
// kernel/module side (bpf_testmod_test_btf_type_tag_user_1/2, and
// __sys_getsockname's sockaddr __user * arg in vmlinux BTF) -- entirely
// outside this translation unit -- so replicating the same direct-deref
// shape as the C original reproduces the same verifier rejection.

use bpf_rs_core::bpf_object;
use bpf_rs_core::progs::fentry_arg as arg;

#[repr(C)]
struct bpf_testmod_btf_type_tag_1 {
    a: i32,
}

#[repr(C)]
struct bpf_testmod_btf_type_tag_2 {
    p: *const bpf_testmod_btf_type_tag_1,
}

#[repr(C)]
struct sockaddr {
    sa_family: u16,
    sa_data: [u8; 14],
}

#[no_mangle]
static mut g: i32 = 0;

#[link_section = "fentry/bpf_testmod_test_btf_type_tag_user_1"]
#[no_mangle]
extern "C" fn test_user1(ctx: *const u64) -> i32 {
    let p = arg(ctx, 0) as *const bpf_testmod_btf_type_tag_1;
    let a = unsafe { (*p).a };
    unsafe { g = a };
    0
}

#[link_section = "fentry/bpf_testmod_test_btf_type_tag_user_2"]
#[no_mangle]
extern "C" fn test_user2(ctx: *const u64) -> i32 {
    let p = arg(ctx, 0) as *const bpf_testmod_btf_type_tag_2;
    let a = unsafe { (*(*p).p).a };
    unsafe { g = a };
    0
}

#[link_section = "fentry/__sys_getsockname"]
#[no_mangle]
extern "C" fn test_sys_getsockname(ctx: *const u64) -> i32 {
    let usockaddr = arg(ctx, 1) as *const sockaddr;
    let fam = unsafe { (*usockaddr).sa_family };
    unsafe { g = fam as i32 };
    0
}

bpf_object!("GPL");
